import { describe, expect, it } from "vitest";
import { REPRODUCTION_HARNESS } from "@0/engine/shared";
import { reproductionDetail, reproductionPhrase, rowReproduction } from "./finding-reproduction.js";
import { normalizeFinding } from "./web/dashboard-summaries.js";

const steps = JSON.stringify([{ id: "e", kind: "exploit", summary: "hit", action: { type: "http", method: "GET", url: "/files?name=../x" } }]);
const result = {
  schemaVersion: 1, harness: REPRODUCTION_HARNESS, status: "reproduced", reason: "canary-observed",
  commit: "0123456789abcdef0123456789abcdef01234567", imageDigest: `sha256:${"a".repeat(64)}`, isolation: "container", network: "loopback",
  canary: { token: "canary-abcdef12", observed: true }, recipeSha256: "b".repeat(64), appSha256: "d".repeat(64),
  startedAt: "2026-11-24T10:00:00.000Z", finishedAt: "2026-11-24T10:00:03.000Z", logTail: "ok",
};

describe("finding proof in the CLI", () => {
  it("old rows without the column or steps show nothing", () => {
    expect(rowReproduction({})).toBeUndefined();
    expect(reproductionPhrase({ reproduction: null, pocSteps: null })).toBeUndefined();
  });
  it("shows proposed steps as not run", () => {
    expect(reproductionPhrase({ pocSteps: steps })).toBe("proposed steps, not run");
    expect(reproductionDetail({ pocSteps: steps })?.line).toMatch(/^Proposed steps, not run/);
  });
  it("shows Reproduced only from a stored harness record", () => {
    expect(reproductionDetail({ pocSteps: steps, reproduction: JSON.stringify({ result }) })?.line).toMatch(/^Reproduced: the app as run returned the canary for this request, on commit 0123456789ab in an isolated container/);
    const forged = JSON.stringify({ result: { ...result, harness: "model" } });
    expect(reproductionDetail({ pocSteps: steps, reproduction: forged })?.line).toMatch(/^Proposed steps, not run/);
  });
  it("reaches the web payload as a parsed record", () => {
    const base = { id: "f", scanId: "s", title: "t", description: "d", severity: "high", category: "c", status: "discovered", timestamp: 1, evidenceRequest: "", evidenceResponse: "" };
    expect(normalizeFinding({ ...base, reproduction: JSON.stringify({ result }) }).reproduction?.result?.status).toBe("reproduced");
    expect(normalizeFinding(base).reproduction).toBeNull();
  });
});
