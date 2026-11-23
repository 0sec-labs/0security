import { describe, expect, it } from "vitest";
import { mapWithConcurrency } from "./concurrency.js";

describe("mapWithConcurrency", () => {
  it("preserves input order", async () => {
    await expect(mapWithConcurrency([3, 1, 2], 2, async (n) => n * 2)).resolves.toEqual([6, 2, 4]);
  });

  it("still runs every item when the limit is NaN, zero or negative", async () => {
    for (const limit of [Number.NaN, 0, -3]) {
      await expect(mapWithConcurrency([1, 2, 3], limit, async (n) => n + 1)).resolves.toEqual([2, 3, 4]);
    }
  });
});
