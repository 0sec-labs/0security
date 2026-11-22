import type { Inventory, InventoryUnit } from "@0/engine";
import { describe, expect, it } from "vitest";
import { estimateCost, HIGH_FACTOR, LOW_FACTOR, MEASURED_USD_PER_BATCH, MEASURED_USD_PER_THREAD, planScan, planText } from "./scan-plan.js";

const route = (i: number): InventoryUnit => ({ id: `r${i}`, kind: "http-route", path: `routes/r${i}.js`, startLine: 1, name: `GET /r${i}` });
function inventory(routes: number, others = 0, sourceFiles = routes + others): Inventory {
  const units: InventoryUnit[] = [...Array.from({ length: routes }, (_, i) => route(i)), ...Array.from({ length: others }, (_, i): InventoryUnit => ({ id: `o${i}`, kind: "other", path: "lib", name: "1 file", files: [`lib/f${i}.js`] }))];
  return { units, summary: { sourceFiles, entryPoints: routes, otherUnits: others, byKind: { ...(routes ? { "http-route": routes } : {}), ...(others ? { other: others } : {}) }, directories: [], skipped: { tooLarge: [], unreadable: 0, walkLimit: false, unitLimit: false } } };
}

describe("estimateCost", () => {
  it("scales the measured per-batch cost into a half-to-three-times range", () => {
    const estimate = estimateCost(10, true, 5);
    expect(estimate.lowUsd).toBeCloseTo(10 * MEASURED_USD_PER_BATCH * LOW_FACTOR);
    expect(estimate.highUsd).toBeCloseTo(10 * MEASURED_USD_PER_BATCH * HIGH_FACTOR);
    expect(estimate.basis).toContain("about $0.035 per batch");
    expect(estimate.basis).toContain("not a quote");
  });
  it("uses the one-thread measurement when not batched", () => {
    expect(estimateCost(1, false, 5).highUsd).toBeCloseTo(MEASURED_USD_PER_THREAD * HIGH_FACTOR);
  });
  it("judges the budget: complete, partial or either way", () => {
    expect(estimateCost(9, true, 5).verdict).toBe("likely complete");
    expect(estimateCost(300, true, 5).verdict).toBe("likely partial");
    expect(estimateCost(100, true, 5).verdict).toBe("could go either way");
  });
  it("costs nothing for no threads", () => expect(estimateCost(0, true, 5)).toMatchObject({ lowUsd: 0, highUsd: 0, verdict: "likely complete" }));
});

describe("planScan", () => {
  const at = { folder: "/code/app", batchSize: 8, batchesMode: "auto", budgetUsd: 5 };
  it("counts batches and batches a folder with more entry points than a batch", () => {
    const plan = planScan(inventory(20, 1), at);
    expect(plan).toMatchObject({ entryPoints: 20, otherUnits: 1, batchCount: 4, wouldBatch: true, autoWouldBatch: true, byKind: { "http-route": 20 } });
    expect(plan.estimate.threads).toBe(4);
  });
  it("keeps a small folder as one thread under auto but batches under --batches on", () => {
    expect(planScan(inventory(3), at)).toMatchObject({ wouldBatch: false, autoWouldBatch: false, estimate: { threads: 1 } });
    expect(planScan(inventory(3), { ...at, batchesMode: "on" })).toMatchObject({ wouldBatch: true, autoWouldBatch: false });
    expect(planScan(inventory(30), { ...at, batchesMode: "off" })).toMatchObject({ wouldBatch: false, autoWouldBatch: true, estimate: { threads: 1 } });
  });
  it("batches a large tree of few entry points", () => expect(planScan(inventory(2, 10, 400), at).autoWouldBatch).toBe(true));
  it("honours --batch-size", () => expect(planScan(inventory(20), { ...at, batchSize: 2 }).batchCount).toBe(10));
  it("says so for an empty folder and gives no estimate line", () => {
    const plan = planScan(inventory(0), at);
    expect(plan.notes.join(" ")).toMatch(/nothing to scan/);
    expect(planText(plan)).not.toContain("Estimated cost");
  });
  it("is likely partial at the default budget for a very large folder", () => expect(planScan(inventory(4000), at).estimate.verdict).toBe("likely partial"));
});

describe("planText", () => {
  it("prints counts, batches, the estimate, its basis and the budget verdict", () => {
    const text = planText(planScan(inventory(20, 1), { folder: "/code/app", batchSize: 8, batchesMode: "auto", budgetUsd: 5 }));
    expect(text).toContain("Plan for /code/app");
    expect(text).toContain("Entry points: 20 (http-route 20)");
    expect(text).toContain("Other units: 1 group");
    expect(text).toContain("Batches: 4 at --batch-size 8");
    expect(text).toContain("--batches auto would batch this folder");
    expect(text).toMatch(/Estimated cost: \$0\.070 to \$0\.42 for 4 threads/);
    expect(text).toContain("At the $5 budget: likely complete");
    expect(text).toContain("not a quote");
  });
});
