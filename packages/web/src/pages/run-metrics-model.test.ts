import { describe, expect, it } from "vitest";
import { metricTotal } from "./run-metrics-model";
describe("receipt totals", () => {
  it("shows missing receipts as unknown, preserving actually measured zero", () => {
    expect(metricTotal(0, 1, 1, true)).toBe("Unknown"); expect(metricTotal(0, 1, 1)).toBe("Unknown");
    expect(metricTotal(0, 0, 1, true)).toBe("$0.0000"); expect(metricTotal(0, 0, 1)).toBe("0");
  });
  it("identifies partial totals without charging missing runs as free", () => {
    expect(metricTotal(.25, 2, 3, true)).toBe("$0.2500 (+2 unknown)");
    expect(metricTotal(120, 1, 2)).toBe("120 (+1 unknown)");
  });
});
