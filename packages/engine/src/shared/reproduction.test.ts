import { describe, expect, it } from "vitest";
import {
  REPRODUCTION_HARNESS, claimsReproduced, gateReproductionClaim, isReproduced, parseFindingReproduction, parseReproductionResult,
  proofLine, proposeProof, reproductionFor, reproductionLabel, reproductionLine, type ReproductionResult,
} from "./reproduction.js";
import type { PocStep } from "./types.js";

const harnessRecord = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  schemaVersion: 1, harness: REPRODUCTION_HARNESS, status: "reproduced", reason: "canary-observed",
  commit: "0123456789abcdef0123456789abcdef01234567", imageDigest: `sha256:${"a".repeat(64)}`, isolation: "container", network: "loopback",
  canary: { token: "canary-abcdef12", observed: true }, recipeSha256: "b".repeat(64), appSha256: "d".repeat(64),
  startedAt: "2026-11-24T10:00:00.000Z", finishedAt: "2026-11-24T10:00:03.000Z", logTail: "ok", ...over,
});

describe("reproduction result: only a complete harness record counts", () => {
  it("accepts a complete record", () => {
    expect(parseReproductionResult(harnessRecord())?.status).toBe("reproduced");
    expect(isReproduced(harnessRecord())).toBe(true);
  });

  it.each([
    ["no harness id", { harness: undefined }],
    ["another harness id", { harness: "model" }],
    ["no commit", { commit: undefined }],
    ["no image digest", { imageDigest: undefined }],
    ["image by tag, not digest", { imageDigest: "node:20" }],
    ["host isolation", { isolation: "host" }],
    ["no network note", { network: undefined }],
    ["no canary", { canary: undefined }],
    ["canary not observed but status reproduced", { canary: { token: "canary-abcdef12", observed: false } }],
    ["no recipe hash", { recipeSha256: undefined }],
    ["no app file hash", { appSha256: undefined }],
    ["an unisolated run", { isolation: "unisolated" }],
    ["no timestamps", { startedAt: undefined }],
    ["finished before started", { finishedAt: "2026-11-24T09:00:00.000Z" }],
    ["no log tail", { logTail: undefined }],
  ])("refuses 'reproduced' with %s", (_name, over) => {
    const record = harnessRecord(over);
    expect(parseReproductionResult(record)).toBeUndefined();
    expect(isReproduced(record)).toBe(false);
    expect(reproductionLine(record as unknown as ReproductionResult)).not.toMatch(/^Reproduced/);
  });

  it("refuses 'not-reproduced' with the canary observed, and without a full record", () => {
    expect(parseReproductionResult(harnessRecord({ status: "not-reproduced" }))).toBeUndefined();
    expect(parseReproductionResult(harnessRecord({ status: "not-reproduced", canary: { token: "canary-abcdef12", observed: false }, commit: undefined }))).toBeUndefined();
    expect(parseReproductionResult(harnessRecord({ status: "not-reproduced", canary: { token: "canary-abcdef12", observed: false } }))?.status).toBe("not-reproduced");
  });

  it("keeps an unisolated run to inconclusive, with the reason in the wording", () => {
    const unisolated = parseReproductionResult({ ...harnessRecord({ status: "inconclusive", reason: "unisolated-run-canary-observed", isolation: "unisolated" }) });
    expect(unisolated?.isolation).toBe("unisolated");
    expect(reproductionLine(unisolated)).toMatch(/not isolated, so it cannot count as reproduced/);
    expect(isReproduced(unisolated)).toBe(false);
  });

  it("lets inconclusive and error carry a reason without a commit or image", () => {
    const bare = { schemaVersion: 1, harness: REPRODUCTION_HARNESS, reason: "app-did-not-start", startedAt: "2026-11-24T10:00:00.000Z", finishedAt: "2026-11-24T10:00:01.000Z", logTail: "" };
    expect(parseReproductionResult({ ...bare, status: "error" })?.status).toBe("error");
    expect(parseReproductionResult({ ...bare, status: "inconclusive" })?.status).toBe("inconclusive");
    expect(parseReproductionResult({ ...bare, status: "safe" })).toBeUndefined();
  });

  it("caps the log tail", () => {
    expect(parseReproductionResult(harnessRecord({ logTail: "x".repeat(5000) }))?.logTail.length).toBe(2048);
  });
});

describe("wording", () => {
  it("says Reproduced only for a complete harness record, naming commit and image", () => {
    const line = reproductionLine(parseReproductionResult(harnessRecord()));
    expect(line).toMatch(/^Reproduced: the app as run returned the canary for this request, on commit 0123456789ab in an isolated container \(image a{12}\)/);
    expect(line).toMatch(/not a statement about the code/);
  });
  it("never lets 'not reproduced' read as safe", () => {
    const line = reproductionLine(parseReproductionResult(harnessRecord({ status: "not-reproduced", canary: { token: "canary-abcdef12", observed: false } })));
    expect(line).toMatch(/^Not reproduced: the app as run did not return the canary for this request/);
    expect(line).toMatch(/does not mean the issue is absent or the code is safe/);
    expect(line).not.toMatch(/\bfixed\b/i);
    expect(reproductionLine(parseReproductionResult({ ...harnessRecord(), status: "inconclusive", canary: undefined, commit: undefined, imageDigest: undefined }))).toMatch(/does not mean the issue is absent/);
  });
  it("labels a proposed proof as not run", () => {
    const proof = proposeProof({ pocSteps: [{ id: "s", kind: "exploit", summary: "x", action: { type: "shell", cmd: "echo hi" } }] });
    expect(proofLine(proof)).toBe("Proposed steps, not run (1 step). Nothing has checked them");
    expect(reproductionLabel({ proof })).toBe("proposed steps, not run");
  });
  it("gates a reproduced claim on a harness record", () => {
    expect(claimsReproduced("The issue was reproduced locally")).toBe(true);
    expect(claimsReproduced("This could not be reproduced")).toBe(false);
    const denied = gateReproductionClaim("Confirmed: reproduced the traversal.", undefined);
    expect(denied.allowed).toBe(false);
    expect(denied.message).toMatch(/not backed by a harness result/);
    expect(gateReproductionClaim("Confirmed: reproduced the traversal.", harnessRecord() as unknown as ReproductionResult).allowed).toBe(true);
    expect(gateReproductionClaim("Looks like path traversal.", undefined).allowed).toBe(true);
  });
});

describe("proposed proof", () => {
  const steps: PocStep[] = [
    { id: "exploit-1", kind: "exploit", summary: "hit", action: { type: "http", method: "get", url: "http://victim.example/files?name=../../etc/passwd" } },
    { id: "verify-1", kind: "verify", summary: "see", action: { type: "note", text: "root:x" }, expect: { type: "body-contains", text: "root:x" } },
  ];
  it("keeps only the path from a URL and takes the later expectation", () => {
    const proof = proposeProof({ pocSteps: steps })!;
    expect(proof).toMatchObject({ label: "proposed", ran: false, steps: [{ kind: "http", method: "GET", path: "/files?name=../../etc/passwd", expect: { bodyContains: "root:x" } }] });
  });
  it("is absent when nothing is replayable", () => {
    expect(proposeProof({})).toBeUndefined();
    expect(proposeProof({ pocSteps: [{ id: "n", kind: "prerequisite", summary: "n", action: { type: "note", text: "n" } }] })).toBeUndefined();
  });
  it("is read back as proposed even if stored text says otherwise", () => {
    const proof = proposeProof({ pocSteps: steps })!;
    const stored = JSON.stringify({ proof: { ...proof, label: "reproduced", ran: true } });
    expect(parseFindingReproduction(stored)?.proof).toMatchObject({ label: "proposed", ran: false });
  });
  it("a stored result that is not a harness record is dropped", () => {
    expect(parseFindingReproduction({ result: { status: "reproduced", reason: "the model said so" } })).toBeUndefined();
    expect(reproductionFor({}, undefined)).toBeUndefined();
  });
});
