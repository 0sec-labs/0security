import { describe, expect, it } from "vitest";
import { REPRODUCTION_HARNESS, type Finding, type ScanReport } from "../shared/index.js";
import { formatSarif } from "./sarif.js";
import { formatMarkdown } from "./markdown.js";

const result = {
  schemaVersion: 1 as const, harness: REPRODUCTION_HARNESS, status: "not-reproduced" as const, reason: "canary-absent",
  commit: "0123456789abcdef0123456789abcdef01234567", imageDigest: `sha256:${"a".repeat(64)}`, isolation: "container" as const, network: "loopback" as const,
  canary: { token: "canary-abcdef12", observed: false }, recipeSha256: "b".repeat(64), appSha256: "d".repeat(64),
  startedAt: "2026-11-24T10:00:00.000Z", finishedAt: "2026-11-24T10:00:03.000Z", logTail: "",
};

function report(extra: Partial<Finding>): ScanReport {
  return {
    target: "/work/app", scanDepth: "quick", startedAt: "2026-11-08T04:00:00.000Z", completedAt: "2026-11-08T04:01:00.000Z", durationMs: 60_000, warnings: [],
    summary: { totalAttacks: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    findings: [{
      id: "finding-1", templateId: "0:path-traversal", title: "Download route reads any file", description: "No containment.", severity: "high", category: "path-traversal", status: "confirmed",
      evidence: { request: "GET /files?name=../x", response: "root", analysis: "" }, timestamp: 1_794_110_400_000, ...extra,
    }],
  } as ScanReport;
}

describe("reproduction in exports", () => {
  const steps = [{ id: "e", kind: "exploit" as const, summary: "hit", action: { type: "http" as const, method: "GET", url: "/files?name=../x" } }];

  it("labels a proposed recipe as not run in SARIF and the report", () => {
    const r = report({ pocSteps: steps });
    const props = JSON.parse(formatSarif(r)).runs[0].results[0].properties.reproduction;
    expect(props.proof.label).toBe("proposed");
    expect(props.proofLabel).toMatch(/^Proposed steps, not run/);
    expect(props.result).toBeUndefined();
    expect(formatMarkdown(r)).toMatch(/\*\*Proof:\*\* Proposed steps, not run/);
    expect(formatMarkdown(r)).not.toMatch(/Reproduced on commit/);
  });

  it("carries a harness result and says not-reproduced is not safety", () => {
    const r = report({ pocSteps: steps, reproduction: { result } });
    const props = JSON.parse(formatSarif(r)).runs[0].results[0].properties.reproduction;
    expect(props.result.status).toBe("not-reproduced");
    expect(props.resultLabel).toMatch(/does not mean the issue is absent/);
    expect(formatMarkdown(r)).toMatch(/\*\*Proof:\*\* Not reproduced: the app as run did not return the canary for this request, on commit 0123456789ab/);
  });

  it("adds nothing to a finding without steps or a record", () => {
    expect(JSON.parse(formatSarif(report({}))).runs[0].results[0].properties.reproduction).toBeUndefined();
    expect(formatMarkdown(report({}))).not.toMatch(/\*\*Proof:\*\*/);
  });
});
