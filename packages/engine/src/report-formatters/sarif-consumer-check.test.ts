import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Finding, ScanReport } from "../shared/index.js";
import { checkSarifForConsumers } from "./sarif-consumer-check.js";
import { formatSarif } from "./sarif.js";

const here = dirname(fileURLToPath(import.meta.url));
const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({ id, templateId: `0:${id}`, title: id, description: `${id} description`, severity: "high", category: "path-traversal", status: "confirmed", evidence: { request: "", response: "", analysis: "" }, timestamp: 1, ...extra });
const report = (target: string, findings: Finding[], extra: Partial<ScanReport> = {}): ScanReport => ({
  target, scanDepth: "quick", startedAt: "2026-11-08T04:00:00.000Z", completedAt: "2026-11-08T04:01:00.000Z", durationMs: 60_000, warnings: [],
  summary: { totalAttacks: 0, totalFindings: findings.length, critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, findings, ...extra,
});
const check = (r: ScanReport) => checkSarifForConsumers(JSON.parse(formatSarif(r)));

describe("checkSarifForConsumers on 0's own output", () => {
  const located = [
    finding("a", { reviewAnnotation: { path: "src/a.ts", startLine: 3, endLine: 5, suggestion: "safe()", fixExplanation: "Use safe()." } }),
    finding("b", { reviewAnnotation: { path: "src/b.ts", startLine: 9 }, triageStatus: "accepted", triageNote: "vendor patch due" }),
  ];

  it("has no errors and no warnings for findings located below a relative scan root", () => {
    const result = check(report(".", located));
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.results).toBe(2);
    expect(result.rules).toBe(2);
  });

  it("warns that an absolute scan root gives file URIs that code scanning cannot map to the repository", () => {
    const result = check(report("/home/runner/work/app/app", located));
    expect(result.errors).toEqual([]);
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings[0]).toContain("not relative to the repository");
  });

  it("warns about a finding with no cited file: it has no line for a viewer", () => {
    const result = check(report(".", [finding("c")]));
    expect(result.errors).toEqual([]);
    expect(result.warnings.join("\n")).toContain("no region");
  });

  it("warns that review-check results carry no location", () => {
    const result = check(report(".", located, { reviewChecks: [{ id: "c1", name: "Check", status: "issue", reason: "r", fix: "f" }] as unknown as ScanReport["reviewChecks"] }));
    expect(result.errors).toEqual([]);
    expect(result.warnings.filter((w) => w.includes("no location"))).toHaveLength(1);
  });

  it("accepts a report with no findings", () => {
    expect(check(report(".", []))).toMatchObject({ errors: [], warnings: [], results: 0 });
  });
});

describe("checkSarifForConsumers on SARIF from other tools", () => {
  const files = [
    join(here, "../shared/__fixtures__"),
    join(here, "../../../../scripts/bench/fix-cases/sqli"),
    join(here, "../../../../scripts/bench/fix-cases/java-xxe"),
  ].flatMap((dir) => readdirSync(dir).filter((f) => f.endsWith(".sarif")).map((f) => join(dir, f)));

  it("finds sample files to check", () => { expect(files.length).toBeGreaterThanOrEqual(5); });
  it.each(files.map((f) => [f.split("/").slice(-2).join("/"), f]))("reports no spec errors for %s", (_name, file) => {
    expect(checkSarifForConsumers(JSON.parse(readFileSync(file!, "utf8"))).errors).toEqual([]);
  });
});

describe("checkSarifForConsumers rejects", () => {
  const valid = () => ({ version: "2.1.0", runs: [{ tool: { driver: { name: "t", rules: [{ id: "r1" }] } }, results: [{ ruleId: "r1", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.ts" }, region: { startLine: 3 } } }] }] }] });
  const errorsOf = (mutate: (log: ReturnType<typeof valid>) => void) => { const log = valid(); mutate(log); return checkSarifForConsumers(log).errors.join("\n"); };

  it("accepts the baseline", () => { expect(checkSarifForConsumers(valid())).toMatchObject({ errors: [], warnings: [] }); });
  it("a wrong version", () => { expect(errorsOf((l) => { l.version = "2.0.0"; })).toContain("version"); });
  it("no runs", () => { expect(checkSarifForConsumers({ version: "2.1.0", runs: [] }).errors[0]).toContain("runs"); });
  it("no tool name", () => { expect(errorsOf((l) => { delete (l.runs[0]!.tool.driver as { name?: string }).name; })).toContain("driver.name"); });
  it("a result with no message", () => { expect(errorsOf((l) => { (l.runs[0]!.results[0] as { message: unknown }).message = {}; })).toContain("message.text"); });
  it("a rule id that is not declared", () => { expect(errorsOf((l) => { l.runs[0]!.results[0]!.ruleId = "ghost"; })).toContain("ghost"); });
  it("a ruleIndex that points at another rule", () => {
    expect(errorsOf((l) => { l.runs[0]!.tool.driver.rules.push({ id: "r2" }); (l.runs[0]!.results[0] as Record<string, unknown>)["ruleIndex"] = 1; })).toContain("ruleIndex points at r2");
  });
  it("a level outside the spec", () => { expect(errorsOf((l) => { (l.runs[0]!.results[0] as Record<string, unknown>)["level"] = "critical"; })).toContain("level"); });
  it("a line of zero", () => { expect(errorsOf((l) => { (l.runs[0]!.results[0]!.locations[0]!.physicalLocation.region as { startLine: number }).startLine = 0; })).toContain("startLine"); });
  it("an end line before the start", () => { expect(errorsOf((l) => { Object.assign(l.runs[0]!.results[0]!.locations[0]!.physicalLocation.region, { endLine: 1 }); })).toContain("endLine 1 is before startLine 3"); });
  it("a uri with a space or a backslash", () => {
    expect(errorsOf((l) => { l.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri = "src/my file.ts"; })).toContain("valid URI");
    expect(errorsOf((l) => { l.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri = "src\\a.ts"; })).toContain("valid URI");
  });
  it("a uri with a control character", () => { expect(errorsOf((l) => { l.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri = "a\u001b[2Jb"; })).toContain("valid URI"); });
  it("a fingerprint that is not a string", () => { expect(errorsOf((l) => { (l.runs[0]!.results[0] as Record<string, unknown>)["partialFingerprints"] = { primary: 1 }; })).toContain("partialFingerprints"); });
  it("a fix with no replacement region", () => {
    expect(errorsOf((l) => { (l.runs[0]!.results[0] as Record<string, unknown>)["fixes"] = [{ artifactChanges: [{ artifactLocation: { uri: "a" }, replacements: [{}] }] }]; })).toContain("deletedRegion");
  });
  it("a suppression of an unknown kind", () => { expect(errorsOf((l) => { (l.runs[0]!.results[0] as Record<string, unknown>)["suppressions"] = [{ kind: "maybe" }]; })).toContain("suppressions"); });
  it("a non-boolean executionSuccessful", () => { expect(errorsOf((l) => { (l.runs[0] as Record<string, unknown>)["invocations"] = [{ executionSuccessful: "yes" }]; })).toContain("executionSuccessful"); });
});

describe("checkSarifForConsumers warns", () => {
  it("about more results than code scanning accepts per run", () => {
    const results = Array.from({ length: 25_001 }, () => ({ ruleId: "r1", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.ts" }, region: { startLine: 1 } } }] }));
    const out = checkSarifForConsumers({ version: "2.1.0", runs: [{ tool: { driver: { name: "t", rules: [{ id: "r1" }] } }, results }] });
    expect(out.errors).toEqual([]);
    expect(out.warnings.join("\n")).toContain("25001 results");
  });
  it("about a path that climbs out of the repository", () => {
    const out = checkSarifForConsumers({ version: "2.1.0", runs: [{ tool: { driver: { name: "t" } }, results: [{ message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "../x.ts" }, region: { startLine: 1 } } }] }] }] });
    expect(out.warnings.join("\n")).toContain("not relative");
  });
});
