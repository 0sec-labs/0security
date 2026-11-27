import { describe, expect, it } from "vitest";
import { applyRefusal, firstSentence, groupFindings, runVerify, verifyMetric, type VerifyCandidate, type VerifyDeps, type VerifyOptions } from "../verify.js";
import type { FindingModelVerification } from "@0/engine/storage";

const cand = (id: string, extra: Partial<VerifyCandidate> = {}): VerifyCandidate => ({
  id, dbPath: "/db", fingerprint: `fp-${id}`, title: `Title ${id}`, severity: "high", category: "injection", tool: null, description: "d",
  scanId: "s1", status: "discovered", triage: "new", timestamp: 1, path: "src/a.ts", startLine: 3, ...extra,
});

const block = (o: unknown) => `\`\`\`json\n${JSON.stringify(o)}\n\`\`\``;
const options = (extra: Partial<VerifyOptions> = {}): VerifyOptions => ({ folder: "/work", budget: "2", perFinding: "0.3", concurrency: "1", batch: "1", maxConsecutiveFailures: "3", timeout: "60", ...extra });

function harness(candidates: VerifyCandidate[], answer: (message: string, thread: number) => string | undefined, overrides: Partial<{ missing: string[]; costs: Array<number | undefined> }> = {}) {
  const saved = new Map<string, FindingModelVerification>();
  const suppressed: Array<[string, string]> = [];
  const messages: string[] = [];
  const caps: number[] = [];
  let threads = 0;
  const sessions = new Map<string, string | undefined>();
  const client = { request: async (method: string, path: string, body?: { text?: string; costCeilingUsd?: number }) => {
    if (method === "POST" && path.endsWith("/sessions")) { threads++; caps.push(body!.costCeilingUsd!); return { session: { id: `t${threads}` } }; }
    if (method === "POST" && path.endsWith("/messages")) { messages.push(body!.text!); sessions.set(path.split("/")[4]!, answer(body!.text!, threads)); return {}; }
    if (method === "GET") {
      const reply = sessions.get(path.split("/")[4]!);
      return { snapshot: { session: { status: "ready" }, messages: reply ? [{ role: "assistant", content: [{ type: "text", text: reply }] }] : [], lastOutcome: {}, usage: { inputTokens: 10, outputTokens: 5, costUsd: overrides.costs ? overrides.costs[threads - 1] : 0.1 } } };
    }
    return {};
  } };
  const deps: VerifyDeps = {
    open: async () => client as never, err: () => {}, sleep: async () => {}, startConsole: async () => () => {}, out: () => {},
    loadCandidates: () => candidates,
    save: (c, record) => { saved.set(c.id, record); },
    suppress: (c, note) => { suppressed.push([c.id, note]); },
    exists: (_folder, relative) => !(overrides.missing ?? []).includes(relative),
    now: () => new Date("2026-11-22T00:00:00Z"),
  };
  return { deps, saved, suppressed, messages, caps };
}

const idIn = (message: string) => /"id": "([^"]+)"/.exec(message)![1]!;

describe("runVerify", () => {
  it("stops new verification and variant threads when the base receipt is unavailable", async () => {
    const h = harness([cand("a"), cand("b")], m => block({ finding: idIn(m), verdict: "true-positive", reasoning: "src/a.ts:3" }), { costs: [undefined] });
    h.deps.variants = { variantsOf: () => [], saveRootCause: () => {}, saveVariant: () => "new", markFixedPendingMerge: () => {} };
    const report = await runVerify([], options({ budget: "0.5" }), h.deps);
    expect(h.caps).toHaveLength(1);
    expect(report.costUsd).toBeNull();
    expect(report.stoppedReason).toMatch(/receipt unavailable/);
    expect(report.items[1]!.result).toBe("skipped");
  });

  it.each([false, true])("bounds variant hunts by the global remaining receipt budget (unknown=%s)", async unknown => {
    const h = harness([cand("a"), cand("b")], m => m.includes("<seed>") ? block({ variants: [] }) : block({ finding: idIn(m), verdict: "true-positive", reasoning: "Unsafe sink src/a.ts:3.", root_cause: { bug_class: "x", unsafe_pattern: { sink: "db.query", source: "id" }, missing_guard: "binding", design_origin: "helper" } }), { costs: [0.1, 0.1, unknown ? undefined : 0.3] });
    h.deps.variants = { variantsOf: () => [], saveRootCause: () => {}, saveVariant: () => "new", markFixedPendingMerge: () => {} };
    const report = await runVerify([], options({ budget: "0.5" }), h.deps);
    expect(h.caps).toHaveLength(3);
    expect(h.caps[2]).toBeCloseTo(0.3);
    expect(report.costUsd).toBe(unknown ? null : 0.5);
    expect(report.tokens).toBe(45);
    expect(report.items[1]!.variants!.error).toMatch(unknown ? /receipt unavailable/ : /budget exhausted/);
  });

  it("stores a verdict per finding by id and leaves severity and status alone", async () => {
    const h = harness([cand("a"), cand("b", { path: "src/b.ts" })], m => block({ finding: idIn(m), verdict: "true-positive", severity: "low", reasoning: "Attack built through a.ts:3." }));
    const report = await runVerify([], options(), h.deps);
    expect(report.counts["true-positive"]).toBe(2);
    expect(h.saved.get("a")).toMatchObject({ verdict: "true-positive", advisorySeverity: "low", threadId: "t1" });
    expect(h.suppressed).toEqual([]);
    expect(report.items[0]!.severity).toBe("high");
  });

  it("does not put earlier reasoning or severity in the prompt", async () => {
    const h = harness([cand("a", { description: "claim text" })], m => block({ finding: idIn(m), verdict: "uncertain", reasoning: "r" }));
    await runVerify([], options(), h.deps);
    expect(h.messages[0]).toContain("claim text");
    expect(h.messages[0]).not.toMatch(/"severity"/);
  });

  it("records uncertain with a reason when no verdict comes back, and never matches by title", async () => {
    const h = harness([cand("a")], () => `Title a is fine.\n${block({ finding: "other", verdict: "false-positive", reasoning: "r" })}`);
    const report = await runVerify([], options(), h.deps);
    expect(h.saved.get("a")).toMatchObject({ verdict: "uncertain", reasoning: "no verdict returned" });
    expect(report.items[0]!.verdict).toBe("uncertain");
  });

  it("stores nothing when the thread gives no answer, so a rerun tries again", async () => {
    const h = harness([cand("a")], () => undefined);
    const report = await runVerify([], options(), h.deps);
    expect(h.saved.size).toBe(0);
    expect(report.failed).toBe(1);
  });

  it("skips verified, suppressed, fixed and false-positive findings unless forced", async () => {
    const verified: FindingModelVerification = { verdict: "fixed", reasoning: "r", verifiedAt: "x" };
    const rows = [cand("a", { verification: verified }), cand("b", { triage: "suppressed" }), cand("c", { status: "fixed" }), cand("d", { status: "false-positive" }), cand("e")];
    const h = harness(rows, m => block({ finding: idIn(m), verdict: "true-positive", reasoning: "r" }));
    const report = await runVerify([], options(), h.deps);
    expect(h.saved.size).toBe(1);
    expect(report.items.find(i => i.finding === "a")).toMatchObject({ result: "skipped" });
    const forced = harness(rows, m => block({ finding: idIn(m), verdict: "true-positive", reasoning: "r" }));
    await runVerify(["a"], options({ force: true }), forced.deps);
    expect(forced.saved.has("a")).toBe(true);
  });

  it("selects by id prefix and by filters", async () => {
    const rows = [cand("abc123", { severity: "low" }), cand("abd456", { severity: "high" })];
    const h = harness(rows, m => block({ finding: idIn(m), verdict: "uncertain", reasoning: "r" }));
    await runVerify([], options({ severity: "high" }), h.deps);
    expect([...h.saved.keys()]).toEqual(["abd456"]);
    await expect(runVerify(["ab"], options(), h.deps)).rejects.toThrow(/ambiguous/);
    await expect(runVerify(["zzz"], options(), h.deps)).rejects.toThrow(/not found/);
  });

  it("skips findings whose file is not in the folder", async () => {
    const h = harness([cand("a")], m => block({ finding: idIn(m), verdict: "uncertain", reasoning: "r" }), { missing: ["src/a.ts"] });
    const report = await runVerify([], options(), h.deps);
    expect(h.saved.size).toBe(0);
    expect(report.items[0]!.reason).toMatch(/--folder/);
  });

  it("does not change status without --apply", async () => {
    const h = harness([cand("a")], m => block({ finding: idIn(m), verdict: "false-positive", control: "src/guard.ts:9", reasoning: "Blocked by the guard at src/guard.ts:9." }));
    const report = await runVerify([], options(), h.deps);
    expect(h.suppressed).toEqual([]);
    expect(report.applied).toBe(0);
  });

  it("with --apply suppresses only a false-positive that cites a control", async () => {
    const h = harness([cand("a", { severity: "medium" }), cand("b", { path: "src/b.ts", severity: "medium" }), cand("c", { path: "src/c.ts", severity: "medium" })], m => {
      const id = idIn(m);
      if (id === "a") return block({ finding: id, verdict: "false-positive", control: "src/guard.ts:9", reasoning: "Blocked by the guard at src/guard.ts:9. More text." });
      if (id === "b") return block({ finding: id, verdict: "false-positive", reasoning: "Looks safe." });
      return block({ finding: id, verdict: "true-positive", reasoning: "Real at c.ts:1." });
    });
    const report = await runVerify([], options({ apply: true }), h.deps);
    expect(h.suppressed).toEqual([["a", "False positive (model-verified): Blocked by the guard at src/guard.ts:9."]]);
    expect(h.saved.get("a")!.applied).toBe(true);
    expect(report.items.find(i => i.finding === "b")!.applyRefused).toMatch(/no control/);
    expect(report.applied).toBe(1);
  });

  it("with --apply never suppresses a critical or high finding, whatever the verdict says", async () => {
    const h = harness([cand("a", { severity: "high" }), cand("b", { path: "src/b.ts", severity: "critical" })], m => block({ finding: idIn(m), verdict: "false-positive", control: "src/guard.ts:9", reasoning: "Blocked by the guard at src/guard.ts:9." }));
    const report = await runVerify([], options({ apply: true }), h.deps);
    expect(h.suppressed).toEqual([]);
    expect(report.applied).toBe(0);
    expect(report.items.every(i => /a person decides/.test(i.applyRefused ?? ""))).toBe(true);
  });

  it("stops after consecutive threads without a verdict", async () => {
    const rows = ["a", "b", "c", "d", "e"].map(id => cand(id, { path: `src/${id}.ts` }));
    const h = harness(rows, () => "no block here");
    const report = await runVerify([], options({ maxConsecutiveFailures: "2" }), h.deps);
    expect(report.stoppedReason).toMatch(/2 checks in a row/);
    expect(report.items.filter(i => i.result === "skipped")).toHaveLength(3);
  });

  it("stops when the total budget is spent", async () => {
    const rows = ["a", "b", "c"].map(id => cand(id, { path: `src/${id}.ts` }));
    const h = harness(rows, m => block({ finding: idIn(m), verdict: "uncertain", reasoning: "r" }));
    const report = await runVerify([], options({ budget: "0.15", perFinding: "0.1" }), h.deps);
    expect(report.stoppedReason).toMatch(/budget/);
    expect(report.verified).toBeLessThan(3);
  });

  it("batches findings of one file and resolves duplicate-of inside the batch", async () => {
    const h = harness([cand("a"), cand("b")], m => {
      return [block({ finding: "a", verdict: "true-positive", reasoning: "r a.ts:3" }), block({ finding: "b", verdict: "duplicate-of a", reasoning: "same" })].join("\n");
    });
    const report = await runVerify([], options({ batch: "2" }), h.deps);
    expect(h.messages).toHaveLength(1);
    expect(h.saved.get("b")).toMatchObject({ verdict: "duplicate", duplicateOf: "a" });
    expect(report.counts.duplicate).toBe(1);
  });

  it("changes nothing on a dry run", async () => {
    const h = harness([cand("a")], () => undefined);
    const report = await runVerify([], options({ dryRun: true }), h.deps);
    expect(report.items[0]!.result).toBe("planned");
    expect(h.messages).toHaveLength(0);
  });

  it("rejects bad numbers", async () => {
    const h = harness([], () => undefined);
    await expect(runVerify([], options({ concurrency: "4" }), h.deps)).rejects.toThrow(/--concurrency/);
    await expect(runVerify([], options({ budget: "0" }), h.deps)).rejects.toThrow(/--budget/);
  });
});

describe("finding verification display", () => {
  it("reads the stored column and words the verdict", async () => {
    const { rowVerification, verificationPhrase } = await import("../../finding-verification.js");
    const stored = JSON.stringify({ verdict: "false-positive", reasoning: "r", verifiedAt: "x" });
    expect(verificationPhrase(rowVerification({ modelVerification: stored }))).toBe("verified: likely false positive");
    expect(rowVerification({ modelVerification: "garbage" })).toBeUndefined();
    expect(rowVerification({ modelVerification: null })).toBeUndefined();
    expect(verificationPhrase(undefined)).toBeUndefined();
  });
});

describe("helpers", () => {
  it("groups by file only when asked", () => {
    expect(groupFindings([cand("a"), cand("b"), cand("c")], 1)).toHaveLength(3);
    expect(groupFindings([cand("a"), cand("b"), cand("c")], 2).map(g => g.length)).toEqual([2, 1]);
  });
  it("takes the first sentence", () => {
    expect(firstSentence("One thing. Two things.")).toBe("One thing.");
    expect(firstSentence("no stop")).toBe("no stop");
  });
  it("refuses to apply on a missing control file", () => {
    const record = { verdict: "false-positive" as const, reasoning: "see x.ts:1", control: "x.ts:1" };
    expect(applyRefusal({ severity: "low" }, record, "/w", () => false)).toMatch(/not in the folder/);
    expect(applyRefusal({ severity: "low" }, record, "/w", () => true)).toBeUndefined();
    expect(applyRefusal({ severity: "medium", variantOf: "parent" }, record, "/w", () => true)).toMatch(/variant found by a hunt/);
  });
});

describe("verify run metrics", () => {
  it("records counts and finding ids once per run, and nothing for a dry run", async () => {
    const h = harness([cand("a"), cand("b", { path: "src/b.ts" })], m => block({ finding: idIn(m), verdict: "true-positive", reasoning: "Attack built through a.ts:3." }));
    const rows: unknown[] = [];
    const deps = { ...h.deps, metrics: (row: unknown) => { rows.push(row); } };
    await runVerify([], options({ model: "m1" }), deps);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ command: "verify", model: "m1", budgetUsd: 2, findingsAttempted: 2, findingsProposed: 2, checksPassed: null, status: "ok", findingIds: ["a", "b"] });
    expect(JSON.stringify(rows[0])).not.toContain("Title a");
    await runVerify([], options({ dryRun: true, force: true }), deps);
    expect(rows).toHaveLength(1);
  });

  it("is absent when no thread ran", () => {
    const report = { folder: "/w", dryRun: false, selected: 0, verified: 0, failed: 0, skipped: 0, counts: {}, applied: 0, costUsd: 0, items: [] } as never;
    expect(verifyMetric(report, { budget: "2" }, 0, 0)).toBeUndefined();
  });
});
