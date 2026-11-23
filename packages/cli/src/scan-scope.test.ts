import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, ScanReport } from "@0/engine/shared";
import { exportReport } from "@0/engine";
import { afterEach, describe, expect, it } from "vitest";
import { applyScope, scanExitCode, scanJson, toScanReport, type ScanOutcome } from "./scan-report.js";
import { loadScope } from "./scan-steering.js";
import { withoutOutOfScope } from "./commands/findings-upload.js";

const text = (body: string | Uint8Array): string => (typeof body === "string" ? body : new TextDecoder().decode(body));
const dirs: string[] = [];
const folder = () => { const dir = mkdtempSync(join(tmpdir(), "scope-test-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const SCOPE = "# Security\n\n## Scope\n\n### In scope\n\n- broken-access-control: tenants must not see each other's data\n\n### Out of scope\n\n- denial of service: behind a gateway\n- missing rate limit: gateway does it\n";

const finding = (id: string, category: string, severity: string, path = "src/app.js"): Finding => ({
  id, templateId: "manual", title: `${category} in ${path}`, description: "d", severity, category, status: "discovered", timestamp: 1, fingerprint: id,
  evidence: { request: "", response: "", analysis: "a" }, reviewAnnotation: { path, startLine: 3 },
}) as unknown as Finding;

const stored = [finding("dos", "denial-of-service", "high"), finding("rate", "missing-rate-limit", "medium"), finding("eval", "code-injection", "critical"), finding("own", "broken-access-control", "high")];
const err: string[] = [];
const quiet = (text: string) => { err.push(text); };

function outcomeWith(scope: string | undefined): ScanOutcome {
  const dir = folder();
  writeFileSync(join(dir, "SECURITY.md"), scope ?? "");
  const declared = scope === undefined ? undefined : loadScope(dir, { scope: join(dir, "SECURITY.md") }, quiet);
  return { target: "repo", threadId: "t", startedAt: "2026-11-23T00:00:00.000Z", completedAt: "2026-11-23T00:01:00.000Z", budgetUsd: 1, budgetExhausted: false, failed: false, ...(declared ? { scope: declared } : {}) };
}

describe("loadScope trust", () => {
  it("reads nothing by default, even when the folder has a SECURITY.md that declares everything out of scope", () => {
    const dir = folder();
    writeFileSync(join(dir, "SECURITY.md"), "## Scope\n### Out of scope\n- everything: yes\n- denial of service: yes\n- code injection: yes\n");
    err.length = 0;
    expect(loadScope(dir, {}, quiet)).toBeUndefined();
    expect(err).toEqual([]);
  });

  it("--scope reads the named file, wherever it is", () => {
    const dir = folder(); const other = folder();
    writeFileSync(join(other, "base-security.md"), SCOPE);
    const declared = loadScope(dir, { scope: join(other, "base-security.md") }, quiet)!;
    expect(declared.source).toBe("base-security.md");
    expect(declared.outOfScopeVectors).toEqual(["denial-of-service", "missing-rate-limit"]);
    expect(declared.inScopeVectors).toEqual(["broken-access-control"]);
  });

  it("--repo-scope reads SECURITY.md of the folder and prints the pull request warning", () => {
    const dir = folder();
    writeFileSync(join(dir, "SECURITY.md"), SCOPE);
    err.length = 0;
    const declared = loadScope(dir, { repoScope: true }, quiet)!;
    expect(declared.entries).toHaveLength(3);
    expect(err[0]).toMatch(/--repo-scope reads SECURITY.md from the folder being scanned/);
    expect(err[0]).toMatch(/pull request/);
    expect(err[0]).toMatch(/--scope/);
  });

  it("--repo-scope ignores a SECURITY.md that is a link out of the folder", () => {
    const dir = folder(); const outside = folder();
    writeFileSync(join(outside, "x.md"), SCOPE);
    symlinkSync(join(outside, "x.md"), join(dir, "SECURITY.md"));
    err.length = 0;
    expect(loadScope(dir, { repoScope: true }, quiet)).toBeUndefined();
    expect(err.join(" ")).toMatch(/not found/);
  });

  it("refuses both flags, a missing file, a bad --scope-sarif and suppress without a scope", () => {
    const dir = folder();
    expect(() => loadScope(dir, { scope: "a.md", repoScope: true }, quiet)).toThrow(/not both/);
    expect(() => loadScope(dir, { scope: join(dir, "missing.md") }, quiet)).toThrow(/not a file/);
    expect(() => loadScope(dir, { scopeSarif: "banana" }, quiet)).toThrow(/label or suppress/);
    expect(() => loadScope(dir, { scopeSarif: "suppress" }, quiet)).toThrow(/needs --scope/);
  });

  it("warns about a file with no Scope section and about unmatched entries", () => {
    const dir = folder();
    writeFileSync(join(dir, "a.md"), "# Nothing\n");
    err.length = 0;
    expect(loadScope(dir, { scope: join(dir, "a.md") }, quiet)).toBeUndefined();
    expect(err.join(" ")).toMatch(/no '## Scope' section/);
    writeFileSync(join(dir, "b.md"), "## Scope\n### Out of scope\n- the moon: far away\n");
    err.length = 0;
    const declared = loadScope(dir, { scope: join(dir, "b.md") }, quiet)!;
    expect(declared.unmatched).toBe(1);
    expect(err.join(" ")).toMatch(/unmatched scope entry/);
  });
});

describe("a declared scope in the scan report", () => {
  it("labels, lists apart, and leaves the headline counts and the exit code to the in-scope findings", () => {
    const outcome = outcomeWith(SCOPE);
    const json = scanJson(outcome, stored) as Record<string, any>;
    expect(json.counts).toEqual({ total: 2, critical: 1, high: 1, medium: 0, low: 0, info: 0 });
    expect(json.outOfScopeCounts).toMatchObject({ total: 2, high: 1, medium: 1 });
    expect(json.findings).toHaveLength(4);
    const byId = Object.fromEntries(json.findings.map((f: { id: string }) => [f.id, f]));
    expect(byId.dos).toMatchObject({ scope: "out-of-scope", scopeReason: "behind a gateway", scopeSource: "SECURITY.md" });
    expect(byId.rate.scope).toBe("out-of-scope");
    expect(byId.eval.scope).toBeUndefined();
    expect(byId.own.scope).toBe("in-scope");
    // The in-scope findings come first, the declared vector before the rest; the labelled ones last.
    expect(json.findings.map((f: { id: string }) => f.id)).toEqual(["own", "eval", "dos", "rate"]);
    expect(json.scope).toMatchObject({ source: "SECURITY.md", outOfScope: ["denial-of-service", "missing-rate-limit"] });
    expect(scanExitCode(outcome, stored, "high")).toBe(1);
  });

  it("does not fail the run when only out-of-scope findings reach the threshold", () => {
    const outcome = outcomeWith(SCOPE);
    expect(scanExitCode(outcome, [stored[0]!, stored[1]!], "low")).toBe(0);
    expect(scanExitCode(outcome, [stored[0]!, stored[1]!, stored[3]!], "high")).toBe(1);
  });

  it("without a scope nothing is labelled and every finding counts", () => {
    const outcome = outcomeWith(undefined);
    const json = scanJson(outcome, stored) as Record<string, any>;
    expect(json.counts.total).toBe(4);
    expect(json.scope).toBeUndefined();
    expect(json.findings.some((f: { scope?: string }) => f.scope)).toBe(false);
    expect(scanExitCode(outcome, [stored[0]!], "high")).toBe(1);
  });

  it("honours a path glob and an expiry", () => {
    const dir = folder();
    writeFileSync(join(dir, "s.md"), "## Scope\n### Out of scope\n- dos: gateway [paths: src/admin/**]\n- missing rate limit: old (until 2026-01-01)\n");
    const declared = loadScope(dir, { scope: join(dir, "s.md") }, quiet)!;
    const outcome: ScanOutcome = { ...outcomeWith(undefined), scope: declared };
    const labelled = applyScope(outcome, [finding("a", "denial-of-service", "high", "src/admin/x.js"), finding("b", "denial-of-service", "high", "src/web/x.js"), finding("c", "missing-rate-limit", "low")]);
    expect(labelled.map(f => f.scope)).toEqual(["out-of-scope", undefined, undefined]);
  });

  it("the markdown, SARIF and JSON reports carry the label and the reason; the summary counts exclude the labelled findings", async () => {
    const outcome = outcomeWith(SCOPE);
    const base: ScanReport = { target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: stored, warnings: [] } as unknown as ScanReport;
    const report = toScanReport(outcome, base);
    expect(report.summary).toMatchObject({ totalFindings: 2, critical: 1, high: 1, medium: 0 });
    const md = text((await exportReport(report, "markdown", "t")).body);
    expect(md).toContain("- **Findings:** 2");
    expect(md).toContain("- **Outside declared scope:** 2");
    expect(md).toContain("## Outside declared scope (2)");
    expect(md.indexOf("## Findings")).toBeLessThan(md.indexOf("## Outside declared scope"));
    expect(md).toContain("out of scope (SECURITY.md): behind a gateway");
    expect(md).toContain("Declared scope");
    const sarif = JSON.parse(text((await exportReport(report, "sarif", "t")).body));
    const results = sarif.runs[0].results as Array<{ properties: Record<string, unknown>; suppressions?: unknown }>;
    const dos = results.find(r => r.properties.findingId === "dos")!;
    expect(dos.properties).toMatchObject({ scope: "out-of-scope", scopeReason: "behind a gateway", scopeSource: "SECURITY.md" });
    expect(dos.suppressions).toBeUndefined();
    const suppressed = JSON.parse(text((await exportReport(toScanReport({ ...outcome, scopeSarifSuppress: true }, base), "sarif", "t")).body)).runs[0].results as Array<{ properties: Record<string, unknown>; suppressions?: Array<{ justification?: string }> }>;
    expect(suppressed.find(r => r.properties.findingId === "dos")!.suppressions?.[0]?.justification).toContain("behind a gateway");
    expect(suppressed.find(r => r.properties.findingId === "eval")!.suppressions).toBeUndefined();
    const html = text((await exportReport(report, "html", "t")).body);
    expect(html).toContain("Outside declared scope");
  });

  it("a hostile reason cannot inject Markdown or HTML into the report", async () => {
    const dir = folder();
    writeFileSync(join(dir, "s.md"), "## Scope\n### Out of scope\n- dos: <img src=x onerror=alert(1)> [click](http://evil.example) | @everyone #1\n");
    const declared = loadScope(dir, { scope: join(dir, "s.md") }, quiet)!;
    const base: ScanReport = { target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [finding("dos", "denial-of-service", "high")], warnings: [] } as unknown as ScanReport;
    const md = text((await exportReport(toScanReport({ ...outcomeWith(undefined), scope: declared }, base), "markdown", "t")).body);
    expect(md).not.toMatch(/<img|evil\.example\)/);
  });
});

describe("withoutOutOfScope (findings upload)", () => {
  it("drops labelled results from SARIF and scan JSON, and returns other text unchanged", () => {
    const sarif = JSON.stringify({ version: "2.1.0", runs: [{ results: [{ properties: { scope: "out-of-scope" } }, { properties: { scope: "in-scope" } }, { properties: {} }] }] });
    const out = withoutOutOfScope(sarif);
    expect(out.dropped).toBe(1);
    expect(JSON.parse(out.text).runs[0].results).toHaveLength(2);
    const scan = JSON.stringify({ findings: [{ scope: "out-of-scope" }, { id: "x" }] });
    expect(withoutOutOfScope(scan).dropped).toBe(1);
    expect(withoutOutOfScope("not json")).toEqual({ text: "not json", dropped: 0 });
    expect(withoutOutOfScope(JSON.stringify({ runs: [{ results: [{}] }] }))).toMatchObject({ dropped: 0 });
  });
});

