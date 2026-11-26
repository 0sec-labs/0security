import type { Finding, ScanReport } from "@0/engine/shared";
import { describe, expect, it } from "vitest";
import { exportReport } from "@0/engine";
import { locationKey, mergePasses, repoRelativePath, scanExitCode, scanJson, toScanReport, type MergedFinding, type ScanOutcome } from "./scan-report.js";

const stored = (overrides: Partial<Finding> = {}): Finding => ({
  id: "f1", templateId: "manual", title: "SQL injection in /users", description: "", severity: "high", category: "sql-injection", status: "discovered", timestamp: 1,
  fingerprint: "abc123", confidence: 0.9, cvssScore: 8.1, cvssVector: "CVSS:3.1/AV:N",
  evidence: { request: "GET /users?id=1'", response: "500", analysis: "id reaches the query" },
  reviewAnnotation: { path: "src/users.ts", startLine: 12, endLine: 14, suggestion: "db.query('select 1 where id = ?', [id])" },
  ...overrides,
}) as Finding;

const outcome: ScanOutcome = { target: "repo", threadId: "t1", startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:01:00.000Z", budgetUsd: 5, costUsd: 0.4, budgetExhausted: false, failed: false, summary: "covered src/" };
const base = (findings: Finding[]): ScanReport => ({ target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings, warnings: [{ stage: "report", message: "Export reconstructed from retained scan rows." }] });

describe("scanJson", () => {
  it("is versioned and carries counts, location, evidence, fingerprint and the fix", () => {
    const report = scanJson(outcome, [stored()]) as Record<string, any>;
    expect(report.schemaVersion).toBe(1);
    expect(report.status).toBe("complete");
    expect(report.counts).toEqual({ total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 });
    expect(report.findings[0]).toMatchObject({ id: "f1", fingerprint: locationKey("src/users.ts", 12), title: "SQL injection in /users", severity: "high", category: "sql-injection", location: { path: "src/users.ts", startLine: 12, endLine: 14 }, cvssScore: 8.1, suggestedFix: { replacement: "db.query('select 1 where id = ?', [id])" } });
  });
  it("carries the fix explanation next to, or without, the replacement", () => {
    const withBoth = scanJson(outcome, [stored({ reviewAnnotation: { path: "src/users.ts", startLine: 12, suggestion: "x()", fixExplanation: "Bind the id as a parameter." } })]) as Record<string, any>;
    expect(withBoth.findings[0].suggestedFix).toEqual({ replacement: "x()", explanation: "Bind the id as a parameter." });
    const only = scanJson(outcome, [stored({ reviewAnnotation: { path: "src/users.ts", startLine: 12, fixExplanation: "Bind the id as a parameter." } })]) as Record<string, any>;
    expect(only.findings[0].suggestedFix).toEqual({ explanation: "Bind the id as a parameter." });
    const none = scanJson(outcome, [stored({ reviewAnnotation: { path: "src/users.ts", startLine: 12 } })]) as Record<string, any>;
    expect(none.findings[0].suggestedFix).toBeUndefined();
  });
  it("falls back to the analysis when a finding has no description", () => {
    expect((scanJson(outcome, [stored()]) as Record<string, any>).findings[0].description).toBe("id reaches the query");
  });
  it("lists the worst findings first", () => {
    const report = scanJson(outcome, [stored({ id: "low", title: "a", severity: "low" }), stored({ id: "crit", title: "b", severity: "critical" })]) as Record<string, any>;
    expect(report.findings.map((finding: { id: string }) => finding.id)).toEqual(["crit", "low"]);
  });
  it("marks a partial scan and a failed scan", () => {
    expect((scanJson({ ...outcome, budgetExhausted: true }, []) as Record<string, any>).status).toBe("budget_exhausted");
    expect((scanJson({ ...outcome, failed: true, error: "boom" }, []) as Record<string, any>)).toMatchObject({ status: "failed", error: "boom" });
  });
  it("has no findings and a complete status for a clean scan", () => {
    expect(scanJson(outcome, [])).toMatchObject({ status: "complete", counts: { total: 0 }, findings: [] });
  });
});

describe("toScanReport", () => {
  it("puts this scan's target, times and counts over the stored rows and drops the legacy note", () => {
    const report = toScanReport(outcome, base([stored(), stored({ id: "f2", severity: "critical" })]));
    expect(report).toMatchObject({ target: "source:repo", durationMs: 60_000, summary: { totalFindings: 2, critical: 1, high: 1 }, warnings: [] });
    expect(report.findings[0]!.severity).toBe("critical");
  });
  it("warns that a budget stop is partial", () => {
    const report = toScanReport({ ...outcome, budgetExhausted: true }, base([]));
    expect(report.warnings[0]!.message).toMatch(/partial/);
    expect(report.costCeilingExceeded).toBe(true);
  });
});

describe("scanExitCode", () => {
  const findings = [stored()];
  it("is 0 without a threshold", () => expect(scanExitCode(outcome, findings, undefined)).toBe(0));
  it("is 1 when a finding reaches the threshold", () => expect(scanExitCode(outcome, findings, "high")).toBe(1));
  it("is 0 when findings are below the threshold", () => expect(scanExitCode(outcome, findings, "critical")).toBe(0));
  it("is 1 for a failed scan", () => expect(scanExitCode({ ...outcome, failed: true }, [], undefined)).toBe(1));
  it("is 3 when the budget ran out and nothing else fired", () => expect(scanExitCode({ ...outcome, budgetExhausted: true }, [], "high")).toBe(3));
  it("is 3 for a time stop and for units not reached", () => {
    expect(scanExitCode({ ...outcome, timedOut: true }, [], undefined)).toBe(3);
    const coverage = { complete: false } as ScanOutcome["coverage"];
    expect(scanExitCode({ ...outcome, coverage }, [], undefined)).toBe(3);
  });
  it("with allowPartial follows the findings alone", () => {
    const partial = { ...outcome, budgetExhausted: true, allowPartial: true };
    expect(scanExitCode(partial, [], undefined)).toBe(0);
    expect(scanExitCode({ ...partial, budgetExhausted: false, timedOut: true }, [], "high")).toBe(0);
    expect(scanExitCode({ ...partial, budgetExhausted: false, coverage: { complete: false } as ScanOutcome["coverage"] }, [], undefined)).toBe(0);
    expect(scanExitCode(partial, findings, "high")).toBe(1);
    expect(scanExitCode({ ...partial, failed: true }, [], undefined)).toBe(1);
  });
  it("marks the JSON status partial under allowPartial, whatever stopped the scan", () => {
    expect(scanJson({ ...outcome, budgetExhausted: true }, []).status).toBe("budget_exhausted");
    expect(scanJson({ ...outcome, budgetExhausted: true, allowPartial: true }, []).status).toBe("partial");
    expect(scanJson({ ...outcome, timedOut: true, allowPartial: true }, []).status).toBe("partial");
    expect(scanJson({ ...outcome, allowPartial: true }, []).status).toBe("complete");
    expect(scanJson({ ...outcome, failed: true, allowPartial: true }, []).status).toBe("failed");
  });
});

describe("a report that reads the same in CI", () => {
  const ci = { ...outcome, target: "repo", roots: ["/home/runner/work/repo/repo", "/private/home/runner/work/repo/repo"] };
  const at = (path: string, overrides: Partial<Finding> = {}) => stored({ templateId: "manual", fingerprint: "text-hash-that-changes", reviewAnnotation: { path, startLine: 12, endLine: 14 }, ...overrides });

  it("repoRelativePath strips the checkout root and rejects anything outside it", () => {
    expect(repoRelativePath("/home/runner/work/repo/repo/src/a.ts", ci.roots)).toBe("src/a.ts");
    expect(repoRelativePath("/private/home/runner/work/repo/repo/src/a.ts", ci.roots)).toBe("src/a.ts");
    expect(repoRelativePath("./src/a.ts", ci.roots)).toBe("src/a.ts");
    expect(repoRelativePath("src\\a.ts", ci.roots)).toBe("src/a.ts");
    for (const bad of ["/etc/passwd", "../x.ts", "src/../../x.ts", "C:/x.ts", "https://x/y", ""]) expect(repoRelativePath(bad, ci.roots), bad).toBeUndefined();
  });

  it("locationKey depends on the place and not on anything else", () => {
    expect(locationKey("src/a.ts", 12)).toBe(locationKey("src/a.ts", 12));
    expect(locationKey("src/a.ts", 12)).not.toBe(locationKey("src/a.ts", 13));
    expect(locationKey("src/a.ts", 12)).not.toBe(locationKey("src/b.ts", 12));
  });

  it("gives the same JSON fingerprint and a relative path on two machines and two runs, whatever the model wrote", () => {
    const one = scanJson({ ...ci, roots: ["/home/runner/work/repo/repo"] }, [at("/home/runner/work/repo/repo/src/a.ts", { title: "SQL injection in the user lookup" })]) as Record<string, any>;
    const two = scanJson({ ...ci, roots: ["/Users/dev/code/repo"] }, [at("/Users/dev/code/repo/src/a.ts", { title: "User id reaches a query unescaped", evidence: { request: "other words", response: "x" } })]) as Record<string, any>;
    expect(one.findings[0].location.path).toBe("src/a.ts");
    expect(one.findings[0].fingerprint).toBe(two.findings[0].fingerprint);
    expect(one.target).toBe("repo");
  });

  it("omits the fingerprint when a finding cites no usable location", () => {
    const report = scanJson(ci, [at("/etc/passwd")]) as Record<string, any>;
    expect(report.findings[0].fingerprint).toBeUndefined();
    expect(report.findings[0].location).toBeUndefined();
  });

  it("SARIF has repo-relative paths, the category as rule id and a key that does not move", async () => {
    const sarifFor = async (root: string, title: string) => {
      const report = toScanReport({ ...ci, roots: [root] }, base([at(`${root}/src/a.ts`, { title, category: "sql-injection" as Finding["category"] })]));
      const artifact = await exportReport(report, "sarif", "x");
      return JSON.parse(new TextDecoder().decode(artifact.body)).runs[0];
    };
    const a = await sarifFor("/home/runner/work/repo/repo", "First wording");
    const b = await sarifFor("/Users/dev/other-checkout/repo", "A completely different wording");
    const result = a.results[0];
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe("src/a.ts");
    expect(result.locations[0].physicalLocation.region).toMatchObject({ startLine: 12, endLine: 14 });
    expect(result.ruleId).toBe("sql-injection");
    expect(result.partialFingerprints.primary).toMatch(/^loc:[0-9a-f]{24}$/);
    expect(result.partialFingerprints.primary).toBe(b.results[0].partialFingerprints.primary);
    expect(JSON.stringify(a)).not.toMatch(/\/home\/runner|\/Users\/dev/);
  });
});


describe("mergePasses", () => {
  const f = (id: string, path: string, line: number, over: Partial<Finding> = {}) => stored({ id, title: `title ${id}`, reviewAnnotation: { path, startLine: line }, ...over });

  it("merges findings that cite the same place in different passes, and counts the passes", () => {
    const merged = mergePasses([[f("a", "src/x.ts", 10)], [f("b", "src/x.ts", 12)], [f("c", "src/x.ts", 40)]]);
    expect(merged).toHaveLength(2);
    expect(merged.find(m => m.reviewAnnotation?.startLine === 40)!.foundInPasses).toBe(1);
    expect(merged.find(m => m.reviewAnnotation?.startLine !== 40)!.foundInPasses).toBe(2);
  });
  it("keeps the most severe version, then the most detailed", () => {
    const merged = mergePasses([[f("a", "src/x.ts", 10, { severity: "medium", description: "short" })], [f("b", "src/x.ts", 10, { severity: "critical", description: "x" })], [f("c", "src/x.ts", 10, { severity: "critical", description: "a much longer description" })]]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.id).toBe("c");
  });
  it("never merges a pass with itself, so two flaws close together in one pass stay two", () => {
    expect(mergePasses([[f("a", "src/x.ts", 10), f("b", "src/x.ts", 11)]])).toHaveLength(2);
    expect(mergePasses([[f("a", "src/x.ts", 10), f("b", "src/x.ts", 11)], [f("c", "src/x.ts", 10)]])).toHaveLength(2);
  });
  it("does not merge different files, and compares paths after making them relative", () => {
    expect(mergePasses([[f("a", "src/x.ts", 10)], [f("b", "src/y.ts", 10)]])).toHaveLength(2);
    expect(mergePasses([[f("a", "/work/repo/src/x.ts", 10)], [f("b", "src/x.ts", 10)]], ["/work/repo"])).toHaveLength(1);
  });
  it("merges findings with no location only when the title matches", () => {
    const bare = (id: string, title: string) => stored({ id, title, reviewAnnotation: undefined });
    expect(mergePasses([[bare("a", "Weak crypto")], [bare("b", "weak crypto")]])).toHaveLength(1);
    expect(mergePasses([[bare("a", "Weak crypto")], [bare("b", "Other")]])).toHaveLength(2);
  });
  it("merges one flaw that two batches of a pass filed under different labels, keeping the highest severity", () => {
    // From a real batched scan of a vulnerable API: one missing ownership check, three titles and two labels.
    const one = f("a", "api_views/books.py", 50, { title: "Book lookup omits ownership authorization", category: "information-disclosure", severity: "medium", reviewAnnotation: { path: "api_views/books.py", startLine: 50, endLine: 51 } });
    const two = f("b", "api_views/books.py", 50, { title: "Authenticated users can read other users' book secrets", category: "missing-validation", severity: "high", reviewAnnotation: { path: "api_views/books.py", startLine: 50, endLine: 56 } });
    const merged = mergePasses([[one, two]]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ id: "b", severity: "high", category: "broken-access-control", mergedFindingIds: ["a"] });
  });
  it("keeps two different flaws on nearby lines of one file apart, and never merges two categories", () => {
    const sql = f("a", "models/user_model.py", 72, { title: "SQL injection in username lookup", reviewAnnotation: { path: "models/user_model.py", startLine: 72, endLine: 73 } });
    const plain = f("b", "models/user_model.py", 72, { title: "User passwords are stored and compared in plaintext", category: "other", reviewAnnotation: { path: "models/user_model.py", startLine: 72, endLine: 73 } });
    expect(mergePasses([[sql, plain]])).toHaveLength(2);
    expect(mergePasses([[sql], [plain]])).toHaveLength(2);
  });
  it("keeps findings for different advisories on one manifest line as separate records", () => {
    const dep = (id: string, advisory: string) => f(id, "pom.xml", 6, { title: `[not-reached] snakeyaml 1.30: ${advisory}`, category: "supply-chain", severity: "info", reviewAnnotation: { path: "pom.xml", startLine: 6 } });
    expect(mergePasses([[dep("a", "GHSA-3mc7-4q67-w48m"), dep("b", "GHSA-98wm-3w3q-mw94")]])).toHaveLength(2);
    expect(mergePasses([[dep("a", "GHSA-3mc7-4q67-w48m")], [dep("b", "GHSA-98wm-3w3q-mw94")]])).toHaveLength(2);
    expect(mergePasses([[dep("a", "GHSA-3mc7-4q67-w48m")], [dep("b", "GHSA-3mc7-4q67-w48m")]])).toHaveLength(1);
  });
  it("files an old finding under the same category rules as a new one", () => {
    const [only] = mergePasses([[f("a", "api_views/users.py", 60, { title: "Public registration accepts an admin flag and grants administrator privileges", category: "missing-validation" })]]);
    expect(only).toMatchObject({ category: "mass-assignment", categoryLabel: "missing-validation", templateId: "mass-assignment" });
  });
  it("says nothing about passes for a single pass", () => {
    const [only] = mergePasses([[f("a", "src/x.ts", 10)]]) as MergedFinding[];
    expect(only!.foundInPasses).toBeUndefined();
  });
  it("tells the reader, in every format, how many passes found a finding", () => {
    const merged = mergePasses([[f("a", "src/x.ts", 10)], [f("b", "src/x.ts", 10)], []]);
    const report = toScanReport({ ...outcome, passes: { requested: 3, completed: 3, failed: 0 } }, base(merged));
    expect(report.findings[0]!.description).toMatch(/Found in 2 of 3 scan passes\./);
  });
  it("warns when some passes could not finish", () => {
    const report = toScanReport({ ...outcome, passes: { requested: 3, completed: 2, failed: 1 } }, base([]));
    expect(report.warnings.map(w => w.message).join(" ")).toMatch(/1 of 3 scan passes could not finish/);
  });
});
