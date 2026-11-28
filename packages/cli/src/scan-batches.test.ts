import { describe, expect, it } from "vitest";
import { batchBudget, BATCH_CONCURRENCY_CEILING, DEFAULT_MAX_BATCH_CONCURRENCY, isRetryable, maxBatchConcurrency, MIN_BATCH_BUDGET_USD, retryDelayMs, runBatches, type BatchOutcome, type LedgerPort } from "./scan-batches.js";

const batches = (count: number) => Array.from({ length: count }, (_, index) => ({ index, units: [{ id: `u${index}`, kind: "http-route" as const, path: `f${index}.js`, startLine: 1 }] }));
const ok = (cost = 0.1): BatchOutcome => ({ threadId: "t", reviewed: true, costUsd: cost, budgetExhausted: false, timedOut: false, failed: false });

function ledger() {
  const marks: Array<[string[], string, string | undefined]> = [];
  const threads: string[] = [];
  const port: LedgerPort = {
    mark: (_scan, ids, update) => { marks.push([[...ids], update.status, update.reason]); },
    addSpend: () => {}, addThread: (_scan, id) => { threads.push(id); }, setPendingReason: (_scan, reason) => { marks.push([["*"], "pending", reason]); },
  };
  return { port, marks, threads };
}

describe("batchBudget", () => {
  it("shares what is left between the batches not yet started, with a floor, never above what is left", () => {
    expect(batchBudget(5, 4)).toBe(1.25);
    expect(batchBudget(0.1, 10)).toBe(MIN_BATCH_BUDGET_USD);
    expect(batchBudget(0.03, 2)).toBe(0.03);
    expect(batchBudget(5, 0)).toBe(5);
  });
});

describe("runBatches", () => {
  it("marks a batch reviewed only when its thread finished normally", async () => {
    const { port, marks } = ledger();
    const outcomes: BatchOutcome[] = [ok(), { ...ok(), reviewed: false, budgetExhausted: true }, { ...ok(), reviewed: false, failed: true, error: "boom" }, ok()];
    const result = await runBatches({ batches: batches(4), ledger: port, scanId: "s", budgetUsd: 10, deadline: Infinity, concurrency: 1, run: async batch => outcomes[batch.index]! });
    expect(marks.map(([, status, reason]) => `${status}${reason ? `:${reason}` : ""}`)).toEqual(["reviewed", "pending:budget", "pending:thread failed", "reviewed"]);
    expect(result.budgetHit).toBe(true);
    expect(result.stopped).toBeUndefined();
  });

  it("gives each batch a share of the remaining budget, not the whole of it", async () => {
    const { port } = ledger();
    const given: number[] = [];
    await runBatches({ batches: batches(4), ledger: port, scanId: "s", budgetUsd: 2, deadline: Infinity, concurrency: 1, run: async (_batch, budget) => { given.push(budget); return ok(0.1); } });
    // 2/4, then 1.9/3, 1.8/2, 1.7/1: unused budget rolls on to later batches.
    expect(given.map(value => Number(value.toFixed(3)))).toEqual([0.5, 0.633, 0.9, 1.7]);
  });

  it("stops at the budget and leaves the rest pending with that reason", async () => {
    const { port, marks } = ledger();
    const result = await runBatches({ batches: batches(5), ledger: port, scanId: "s", budgetUsd: 0.3, deadline: Infinity, concurrency: 1, run: async () => ok(0.1) });
    expect(result.outcomes).toHaveLength(3);
    expect(result.stopped).toBe("budget");
    expect(marks.at(-1)).toEqual([["*"], "pending", "budget"]);
  });

  it("stops at the time limit", async () => {
    const { port, marks } = ledger();
    let clock = 0;
    const result = await runBatches({ batches: batches(4), ledger: port, scanId: "s", budgetUsd: 10, deadline: 1500, concurrency: 1, now: () => clock, run: async () => { clock += 1000; return ok(); } });
    expect(result.outcomes).toHaveLength(2);
    expect(result.stopped).toBe("time limit");
    expect(result.timedOut).toBe(true);
    expect(marks.at(-1)).toEqual([["*"], "pending", "time limit"]);
  });

  it("stops after repeated failures instead of burning the budget", async () => {
    const { port, marks } = ledger();
    const result = await runBatches({ batches: batches(6), ledger: port, scanId: "s", budgetUsd: 10, deadline: Infinity, concurrency: 1, run: async () => { throw new Error("model rejected"); } });
    expect(result.outcomes).toHaveLength(3);
    expect(result.stopped).toBe("thread failed");
    expect(result.spentUsd).toBe(0);
    expect(marks.at(-1)).toEqual([["*"], "pending", "thread failed"]);
  });

  it("runs batches at the same time up to the concurrency, reserving budget for those in flight", async () => {
    const { port } = ledger();
    let running = 0;
    let peak = 0;
    const given: number[] = [];
    await runBatches({ batches: batches(6), ledger: port, scanId: "s", budgetUsd: 3, deadline: Infinity, concurrency: 3, run: async (_batch, budget) => { given.push(budget); peak = Math.max(peak, ++running); await new Promise(resolve => setTimeout(resolve, 5)); running--; return ok(0.05); } });
    expect(peak).toBe(3);
    // Three start together: 3/6, then (3-0.5)/5, then (3-0.5-0.5)/4; their sum stays within the total.
    expect(given.slice(0, 3).reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(3);
  });

  it("records every thread it starts", async () => {
    const { port, threads } = ledger();
    await runBatches({ batches: batches(2), ledger: port, scanId: "s", budgetUsd: 1, deadline: Infinity, concurrency: 1, run: async batch => ({ ...ok(), threadId: `thread-${batch.index}` }) });
    expect(threads).toEqual(["thread-0", "thread-1"]);
  });
});

describe("retrying a failed batch", () => {
  const transient = (cost = 0.1): BatchOutcome => ({ threadId: "t", reviewed: false, costUsd: cost, budgetExhausted: false, timedOut: false, failed: true, error: "reset", failure: { cause: "provider_connection", transient: true, message: "The model provider dropped the connection" } });
  const permanent = (): BatchOutcome => ({ ...transient(), failure: { cause: "provider_auth", transient: false, message: "The model provider refused the credentials" } });
  const common = { scanId: "s", deadline: Infinity, concurrency: 1, sleep: async () => {}, random: () => 0.5 };

  it("backs off with jitter, doubling up to a limit", () => {
    expect(retryDelayMs(1, () => 0)).toBe(1000);
    expect(retryDelayMs(1, () => 1)).toBe(2000);
    expect(retryDelayMs(2, () => 1)).toBe(4000);
    expect(retryDelayMs(10, () => 1)).toBe(30_000);
  });

  it("never retries a provider refusal and lists its units as refused, not as a stop reason", async () => {
    const { port, marks } = ledger();
    const refusal: BatchOutcome = { ...permanent(), failure: { cause: "provider_refusal", transient: false, message: "The model provider refused the request" } };
    let calls = 0;
    const result = await runBatches({ ...common, batches: batches(1), ledger: port, budgetUsd: 10, retries: 3, run: async () => { calls++; return refusal; } });
    expect(isRetryable(refusal)).toBe(false);
    expect(calls).toBe(1);
    expect(marks).toEqual([[expect.any(Array), "pending", "refused by the model provider"]]);
    expect(result.failures).toEqual([{ batch: 1, cause: "provider_refusal", message: "The model provider refused the request" }]);
  });

  it("only retries a failure that is transient", () => {
    expect(isRetryable(transient())).toBe(true);
    expect(isRetryable(permanent())).toBe(false);
    expect(isRetryable({ ...transient(), budgetExhausted: true })).toBe(false);
    expect(isRetryable({ ...transient(), timedOut: true })).toBe(false);
    expect(isRetryable({ ...transient(), batchTimedOut: true })).toBe(false);
    expect(isRetryable({ ...ok(), reviewed: false, failed: true })).toBe(false);
  });

  it("keeps the unit pending until an attempt finishes normally, then marks it reviewed", async () => {
    const { port, marks, threads } = ledger();
    const calls: number[] = [];
    const result = await runBatches({ ...common, batches: batches(2), ledger: port, budgetUsd: 10, run: async batch => { calls.push(batch.index); return batch.index === 0 && calls.length === 1 ? transient() : ok(); } });
    expect(calls).toEqual([0, 0, 1]);
    expect(marks.map(([, status]) => status)).toEqual(["reviewed", "reviewed"]);
    expect(result.retried).toEqual([{ batch: 1, attempts: 2, causes: ["provider_connection"], recovered: true }]);
    expect(threads).toEqual(["t", "t", "t"]);
  });

  it("counts the cost of failed attempts against the total budget", async () => {
    const { port } = ledger();
    const result = await runBatches({ ...common, batches: batches(1), ledger: port, budgetUsd: 10, retries: 2, run: async () => transient(0.25) });
    expect(result.spentUsd).toBeCloseTo(0.75, 5);
    expect(result.retried[0]).toMatchObject({ attempts: 3, recovered: false });
    expect(result.failures).toEqual([{ batch: 1, cause: "provider_connection", message: "The model provider dropped the connection" }]);
  });

  it("stops retrying when the budget cannot pay for another attempt", async () => {
    const { port } = ledger();
    let calls = 0;
    await runBatches({ ...common, batches: batches(1), ledger: port, budgetUsd: 0.12, run: async () => { calls++; return transient(0.1); } });
    expect(calls).toBe(1);
  });

  it("stops retrying when the time limit would pass during the wait", async () => {
    const { port } = ledger();
    let calls = 0;
    await runBatches({ ...common, batches: batches(1), ledger: port, budgetUsd: 10, deadline: 500, now: () => 0, run: async () => { calls++; return transient(); } });
    expect(calls).toBe(1);
  });

  it("never retries a permanent failure, and not with retries 0", async () => {
    for (const [outcome, retries] of [[permanent(), 2], [transient(), 0]] as const) {
      const { port } = ledger();
      let calls = 0;
      const result = await runBatches({ ...common, batches: batches(1), ledger: port, budgetUsd: 10, retries, run: async () => { calls++; return outcome; } });
      expect(calls).toBe(1);
      expect(result.retried).toEqual([]);
    }
  });

  it("logs each retry", async () => {
    const { port } = ledger();
    const lines: string[] = [];
    await runBatches({ ...common, batches: batches(1), ledger: port, budgetUsd: 10, log: line => lines.push(line), run: async () => transient() });
    expect(lines.filter(line => line.includes("trying again"))).toHaveLength(2);
    expect(lines.at(-1)).toMatch(/not reviewed \(failed: The model provider dropped the connection; 2 retries used\)/);
  });

  it("leaves a batch that timed out pending with reason timeout and goes on to the next", async () => {
    const { port, marks } = ledger();
    const result = await runBatches({ ...common, batches: batches(3), ledger: port, budgetUsd: 10, run: async batch => (batch.index === 0 ? { ...ok(), reviewed: false, batchTimedOut: true } : ok()) });
    expect(marks.map(([, status, reason]) => `${status}${reason ? `:${reason}` : ""}`)).toEqual(["pending:timeout", "reviewed", "reviewed"]);
    expect(result.stopped).toBeUndefined();
    expect(result.timedOut).toBe(false);
    expect(result.failures[0]).toMatchObject({ batch: 1, cause: "batch_timeout" });
  });
});

describe("maxBatchConcurrency", () => {
  it("defaults, accepts a whole number up to the ceiling, and ignores anything else", () => {
    expect(maxBatchConcurrency({})).toBe(DEFAULT_MAX_BATCH_CONCURRENCY);
    expect(maxBatchConcurrency({ ZERO_SCAN_MAX_CONCURRENCY: "16" })).toBe(16);
    expect(maxBatchConcurrency({ ZERO_SCAN_MAX_CONCURRENCY: " 2 " })).toBe(2);
    for (const bad of ["0", "17", "-1", "3.5", "many", "", "1e1", String(BATCH_CONCURRENCY_CEILING + 1)]) expect(maxBatchConcurrency({ ZERO_SCAN_MAX_CONCURRENCY: bad })).toBe(DEFAULT_MAX_BATCH_CONCURRENCY);
  });
});

describe("a rate limit slows every batch, not only the one that hit it", () => {
  const limited = (): BatchOutcome => ({ threadId: "t", reviewed: false, costUsd: 0.01, budgetExhausted: false, timedOut: false, failed: true, error: "429", failure: { cause: "provider_rate_limit", transient: true, message: "The model provider rate limit was hit" } });

  it("holds the other workers' next batch until the pause is over", async () => {
    const { port } = ledger();
    let clock = 0;
    const sleeps: number[] = [];
    const startedAt: Array<[number, number]> = [];
    let first = true;
    const log: string[] = [];
    await runBatches({
      batches: batches(6), ledger: port, scanId: "s", budgetUsd: 10, deadline: Infinity, concurrency: 3, retries: 1, now: () => clock, random: () => 1, log: text => log.push(text),
      sleep: async ms => { sleeps.push(ms); clock += ms; },
      run: async batch => { startedAt.push([batch.index, clock]); if (batch.index === 0 && first) { first = false; return limited(); } await Promise.resolve(); return ok(0.01); },
    });
    // The first attempt of batch 0 is rate limited: retry delay 2000 ms. Every worker waits that long before it starts another batch.
    expect(sleeps).toContain(2000);
    const afterLimit = startedAt.filter(([index]) => index >= 3);
    expect(afterLimit.length).toBeGreaterThan(0);
    for (const [, at] of afterLimit) expect(at).toBeGreaterThanOrEqual(2000);
    expect(log.some(line => /rate limit was hit; no batch starts for 2s/.test(line))).toBe(true);
  });

  it("does not pause for other transient failures", async () => {
    const { port } = ledger();
    const sleeps: number[] = [];
    const reset: BatchOutcome = { ...limited(), failure: { cause: "provider_connection", transient: true, message: "dropped" } };
    let first = true;
    await runBatches({ batches: batches(4), ledger: port, scanId: "s", budgetUsd: 10, deadline: Infinity, concurrency: 3, retries: 1, now: () => 0, random: () => 1, sleep: async ms => { sleeps.push(ms); }, run: async batch => { if (batch.index === 0 && first) { first = false; return reset; } return ok(0.01); } });
    // Only the retrying batch sleeps (its own backoff); nobody else is held.
    expect(sleeps).toEqual([2000]);
  });
});
