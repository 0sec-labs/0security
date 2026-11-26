import { describe, expect, it } from "vitest";
import type { Finding, ScanReport } from "../shared/index.js";
import { formatSarif } from "./sarif.js";

function physicalLocation(reviewAnnotation?: Finding["reviewAnnotation"], target = "/home/runner/work/app/app"): unknown {
  const report: ScanReport = {
    target,
    scanDepth: "quick",
    startedAt: "2026-11-08T04:00:00.000Z",
    completedAt: "2026-11-08T04:01:00.000Z",
    durationMs: 60_000,
    warnings: [],
    summary: { totalAttacks: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    findings: [{
      id: "finding-1", templateId: "0:path-traversal", title: "Download route reads any file",
      description: "The download handler joins the user path to the storage root without containment.",
      severity: "high", category: "path-traversal", status: "confirmed",
      evidence: { request: "", response: "", analysis: "" },
      reviewAnnotation, timestamp: 1_794_110_400_000,
    }],
  };
  return JSON.parse(formatSarif(report)).runs[0].results[0].locations[0].physicalLocation;
}

describe("formatSarif", () => {
  it("locates a source-review finding at its cited file and lines", () => {
    expect(physicalLocation({ path: "src/routes/download.ts", startLine: 42, endLine: 44 })).toEqual({
      artifactLocation: { uri: "file:///home/runner/work/app/app/src/routes/download.ts" },
      region: { startLine: 42, endLine: 44 },
    });
  });

  it("keeps the cited file but drops an invalid cited line range", () => {
    expect(physicalLocation({ path: "src/routes/download.ts", startLine: 0 })).toEqual({
      artifactLocation: { uri: "file:///home/runner/work/app/app/src/routes/download.ts" },
    });
    expect(physicalLocation({ path: "src/routes/download.ts", startLine: 42, endLine: 40 })).toEqual({
      artifactLocation: { uri: "file:///home/runner/work/app/app/src/routes/download.ts" },
      region: { startLine: 42 },
    });
  });

  it("locates a finding without a source annotation at the scan target", () => {
    expect(physicalLocation()).toEqual({ artifactLocation: { uri: "/home/runner/work/app/app" } });
  });
  it.each([
    ["repo:/checkout/packages/api", "src/auth #1%?.ts", "file:///checkout/packages/api/src/auth%20%231%25%3F.ts"],
    ["packages/app@old", "src/auth.ts", "packages/app%40old/src/auth.ts"],
    ["@apps/api", "src/auth.ts", "%40apps/api/src/auth.ts"],
    ["\\\\server\\share\\api", "src/auth.ts", "file://server/share/api/src/auth.ts"],
    ["repo:packages/api", "src/auth.ts", "packages/api/src/auth.ts"],
    ["repo:.", "src/auth.ts", "src/auth.ts"],
    ["./packages/api", "src/ü.ts", "packages/api/src/%C3%BC.ts"],
    ["file:///checkout/packages/api", "src/auth.ts", "file:///checkout/packages/api/src/auth.ts"],
    ["C:\\checkout\\packages\\api", "src/auth.ts", "file:///C:/checkout/packages/api/src/auth.ts"],
    ["https://example.test/repository.git", "src/auth.ts", "src/auth.ts"],
  ])("anchors %s without using the renderer working directory", (target, path, uri) => {
    expect(physicalLocation({ path, startLine: 42 }, target)).toEqual({ artifactLocation: { uri }, region: { startLine: 42 } });
  });

  it.each(["../secret.ts", "/outside.ts", "C:\\outside.ts", "https://outside.test/a.ts"])("rejects invalid persisted annotation path %s", path => {
    expect(physicalLocation({ path, startLine: 42 }, "repo:packages/api")).toEqual({ artifactLocation: { uri: "repo:packages/api" } });
  });

});

describe("formatSarif finding keys", () => {
  const report = (fingerprint: string | undefined, title: string, target: string): ScanReport => ({
    target, scanDepth: "default", startedAt: "2026-11-08T04:00:00.000Z", completedAt: "2026-11-08T04:01:00.000Z", durationMs: 60_000, warnings: [],
    summary: { totalAttacks: 0, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    findings: [{ id: "f", templateId: "sql-injection", title, description: "d", severity: "high", category: "sql-injection", status: "discovered", evidence: { request: "", response: "" }, timestamp: 1, ...(fingerprint ? { fingerprint } : {}) }],
  });
  const key = (r: ScanReport) => JSON.parse(formatSarif(r)).runs[0].results[0].partialFingerprints.primary as string;

  it("uses a location key alone, so the title and the target do not change it", () => {
    expect(key(report("loc:abc123", "One wording", "source:repo"))).toBe("loc:abc123");
    expect(key(report("loc:abc123", "Other wording", "https://github.com/acme/app"))).toBe("loc:abc123");
  });
  it("keeps the older text-based key for any other fingerprint", () => {
    const text = key(report("text-hash", "One wording", "repo"));
    expect(text).toContain("text-hash");
    expect(text).toContain("One wording");
  });
});

describe("formatSarif custom rules", () => {
  it("marks a finding that a user-supplied rule flagged, and only that one", () => {
    const base = { title: "t", description: "d", severity: "high", category: "other", status: "confirmed", evidence: { request: "", response: "", analysis: "" }, timestamp: 1 } as const;
    const report = { target: "t", scanDepth: "quick", startedAt: "", completedAt: "", durationMs: 0, warnings: [], summary: { totalAttacks: 0, totalFindings: 2, critical: 0, high: 2, medium: 0, low: 0, info: 0 },
      findings: [{ ...base, id: "a", templateId: "acme.no-backdoor", ruleSource: "custom" }, { ...base, id: "b", templateId: "other" }] } as unknown as ScanReport;
    const results = JSON.parse(formatSarif(report)).runs[0].results;
    expect(results[0].properties.ruleSource).toBe("custom");
    expect(results[1].properties.ruleSource).toBeUndefined();
  });

  it("records how the scan ended in the run properties", () => {
    const report = { target: "t", scanDepth: "quick", startedAt: "", completedAt: "", durationMs: 0, warnings: [], summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], scanStatus: "budget_exhausted" } as unknown as ScanReport;
    expect(JSON.parse(formatSarif(report)).runs[0].properties).toEqual({ status: "budget_exhausted" });
    expect(JSON.parse(formatSarif({ ...report, scanStatus: undefined } as ScanReport)).runs[0].properties).toBeUndefined();
  });

  it("records why the scan did not finish in the run properties", () => {
    const report = { target: "t", scanDepth: "quick", startedAt: "", completedAt: "", durationMs: 0, warnings: [], summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], scanStatus: "partial", scanFailure: { cause: "provider_connection", message: "The model provider dropped the connection" } } as unknown as ScanReport;
    expect(JSON.parse(formatSarif(report)).runs[0].properties).toEqual({ status: "partial", failure: { cause: "provider_connection", message: "The model provider dropped the connection" } });
  });

  it("records an accepted risk as an external suppression with its reason, expiry and approver", () => {
    const base = { target: "/repo", scanDepth: "quick" as const, startedAt: "", completedAt: "", durationMs: 0, warnings: [], summary: { totalAttacks: 0, totalFindings: 2, critical: 0, high: 2, medium: 0, low: 0, info: 0 } };
    const finding = (id: string, extra: Partial<Finding>): Finding => ({ id, templateId: "t", title: id, description: "d", severity: "high", category: "path-traversal", status: "confirmed", evidence: { request: "", response: "" }, timestamp: 1, ...extra });
    const sarif = JSON.parse(formatSarif({ ...base, findings: [
      finding("accepted", { triageStatus: "accepted", triageNote: "vendor patch due", triageExpiresAt: "2026-12-31T23:59:59.999Z", triageApprover: "security lead" }),
      finding("open", {}),
    ] }));
    const byId = Object.fromEntries(sarif.runs[0].results.map((r: { properties: { findingId: string } }) => [r.properties.findingId, r]));
    expect(byId["accepted"].suppressions).toEqual([{ kind: "external", status: "accepted", justification: "vendor patch due", properties: { triage: "accepted", expiresAt: "2026-12-31T23:59:59.999Z", approver: "security lead" } }]);
    expect(byId["open"].suppressions).toBeUndefined();
  });

  it("carries the fix explanation as a SARIF fix and a result property", () => {
    const report: ScanReport = {
      target: "/w/app", scanDepth: "quick", startedAt: "", completedAt: "", durationMs: 0, warnings: [],
      summary: { totalAttacks: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      findings: [{
        id: "f1", templateId: "0:sqli", title: "SQL built from input", description: "d", severity: "high", category: "sql-injection", status: "confirmed",
        evidence: { request: "", response: "", analysis: "" }, timestamp: 1,
        reviewAnnotation: { path: "db.py", startLine: 2, endLine: 3, suggestion: "run(query, [name])", fixExplanation: "Pass name as a bound parameter so it is never read as SQL." },
      }],
    };
    const result = JSON.parse(formatSarif(report)).runs[0].results[0];
    expect(result.properties.fixExplanation).toBe("Pass name as a bound parameter so it is never read as SQL.");
    expect(result.fixes).toEqual([{
      description: { text: "Pass name as a bound parameter so it is never read as SQL." },
      artifactChanges: [{ artifactLocation: { uri: "file:///w/app/db.py" }, replacements: [{ deletedRegion: { startLine: 2, endLine: 3 }, insertedContent: { text: "run(query, [name])\n" } }] }],
    }]);
    delete report.findings[0]!.reviewAnnotation!.fixExplanation;
    expect(JSON.parse(formatSarif(report)).runs[0].results[0].fixes).toBeUndefined();
  });
});
