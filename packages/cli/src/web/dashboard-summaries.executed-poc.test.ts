import { describe, expect, it } from "vitest";
import { normalizeFinding, type DBFindingRow } from "./dashboard-summaries.js";

const row = (extra: Record<string, unknown>): DBFindingRow => ({
  id: "f1", scanId: "s1", title: "t", description: "d", severity: "high", category: "xss", status: "discovered", timestamp: 1, evidenceRequest: "r", evidenceResponse: "p", ...extra,
} as unknown as DBFindingRow);

const stored = {
  schemaVersion: 1, harness: "0security-executed-poc/1", outcome: "script-matched", reason: "expectation-met", stepIds: ["p1"],
  run: { status: "pass", reason: "ok", command: "sh app.sh", isolation: "container", durationMs: 10, logTail: "x", imageDigest: `sha256:${"a".repeat(64)}` },
  startedAt: "2026-01-01T00:00:00.000Z", finishedAt: "2026-01-01T00:00:01.000Z",
};

describe("dashboard findings carry the executed PoC record", () => {
  it("parses the stored text into the record", () => {
    expect(normalizeFinding(row({ executedPoc: JSON.stringify(stored) })).executedPoc).toMatchObject({ outcome: "script-matched", run: { isolation: "container" } });
  });
  it("shows a high or critical finding with no record as static-only, never proven", () => {
    for (const severity of ["high", "critical"]) expect(normalizeFinding(row({ severity })).executedPoc).toMatchObject({ outcome: "static-only", reason: "not-attempted" });
  });
  it("has no record for lower severities", () => {
    for (const severity of ["medium", "low", "info"]) expect(normalizeFinding(row({ severity })).executedPoc).toBeNull();
  });
  it("refuses an incomplete stored record: a proven record without a container run is not served as proven", () => {
    const tampered = JSON.stringify({ ...stored, run: { ...stored.run, isolation: "host" } });
    expect(normalizeFinding(row({ executedPoc: tampered })).executedPoc).toMatchObject({ outcome: "static-only", reason: "not-attempted" });
    expect(normalizeFinding(row({ severity: "low", executedPoc: tampered })).executedPoc).toBeNull();
  });
});
