import type { CoverageSummary } from "@0/engine/storage";
import { describe, expect, it } from "vitest";
import { leftText, resumeCommand, resumeHint, shellQuote } from "./scan-resume.js";

const tally = (total: number, reviewed: number, pending: number) => ({ total, reviewed, pending, skipped: 0 });
const summary = (over: Partial<CoverageSummary> = {}): CoverageSummary => ({ scanId: "scan-abc123", entryPoints: tally(57, 41, 16), otherGroups: tally(0, 0, 0), byKind: {}, notReached: { budget: 16 }, complete: false, ...over });
const stop = { budgetHit: false, budgetUsd: 5, timedOut: false, timeoutSeconds: 3600, failures: [] as string[] };

describe("shellQuote and resumeCommand", () => {
  it("leaves a plain path alone and quotes the rest", () => {
    expect(shellQuote("/home/me/app")).toBe("/home/me/app");
    expect(shellQuote("/home/me/my app")).toBe("'/home/me/my app'");
    expect(shellQuote("/tmp/it's")).toBe("'/tmp/it'\\''s'");
    expect(resumeCommand("/home/me/my app", "scan-1")).toBe("0security scan '/home/me/my app' --resume scan-1");
  });
});

describe("resumeHint", () => {
  it("is undefined for a complete review", () => expect(resumeHint("/a", summary({ complete: true }), stop)).toBeUndefined());

  it("says what stopped it, how much is left and the exact command, for a budget stop", () => {
    const hint = resumeHint("/code/app", summary(), { ...stop, budgetHit: true, budgetUsd: 0.1 })!;
    expect(hint.left).toBe("16 of 57 entry points not reached");
    expect(hint.stoppedBy).toBe("the $0.1 budget");
    expect(hint.command).toBe("0security scan /code/app --resume scan-abc123");
    expect(hint.text).toBe("Stopped by the $0.1 budget; 16 of 57 entry points not reached.\nContinue with: 0security scan /code/app --resume scan-abc123\nAdd --budget <usd> to allow more spend.");
  });

  it("names the time limit", () => expect(resumeHint("/a", summary(), { ...stop, timedOut: true, timeoutSeconds: 600 })!.stoppedBy).toBe("the 600s time limit"));

  it("names a failed batch with its reason, and counts several", () => {
    expect(resumeHint("/a", summary(), { ...stop, failures: ["UND_ERR_SOCKET"] })!.stoppedBy).toBe("a failed batch: UND_ERR_SOCKET");
    expect(resumeHint("/a", summary(), { ...stop, failures: ["x", "x", "y"] })!.stoppedBy).toBe("3 failed batches: x");
  });

  it("falls back to the ledger's reasons when this run stopped for none", () => {
    expect(resumeHint("/a", summary({ notReached: { "thread failed": 2 } }), stop)!.stoppedBy).toBe("thread failed");
  });

  it("counts groups of other files when no entry point is left", () => {
    expect(leftText(summary({ entryPoints: tally(5, 5, 0), otherGroups: tally(3, 1, 2) }))).toBe("2 of 3 groups of other files not reached");
    expect(leftText(summary({ entryPoints: tally(1, 0, 1) }))).toBe("1 of 1 entry point not reached");
  });
});
