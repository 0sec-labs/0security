import { describe, expect, it } from "vitest";
import { batchBudget, MIN_BATCH_BUDGET_USD, runBatches, type BatchOutcome, type LedgerPort } from "./scan-batches.js";

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
