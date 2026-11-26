import { describe, expect, it } from "vitest";
import { handleMetricsRequest, handleMetricHostRefreshRequest } from "./metrics-routes.js";
import { sanitizeMetric } from "../run-metrics.js";
describe("run metrics endpoint", () => {
  it("does not read workspace metrics for a non-owner", () => {
    expect(handleMetricsRequest("run-metrics", "GET", new URLSearchParams(), false, () => { throw new Error("must not read"); })?.status).toBe(403);
  });
  it("exports only stored sanitized records and validates grouping", () => {
    const row = sanitizeMetric({ at: new Date().toISOString(), command: "sentinel", model: "m", sentinelId: "s-1", costUsd: .1, tokens: 12 })!;
    const response = handleMetricsRequest("run-metrics", "GET", new URLSearchParams("by=sentinel"), true, () => [row]);
    expect(response?.data).toMatchObject({ rows: [{ key: "s-1", runs: 1, tokens: 12 }], summary: { runs: 1 } });
    expect(handleMetricsRequest("run-metrics", "GET", new URLSearchParams("by=bad"), true)?.status).toBe(400);
    expect(handleMetricsRequest("run-metrics", "POST", new URLSearchParams(), true)?.status).toBe(405);
  });
});

describe("explicit owner host refresh", () => {
  it("refuses non-owner or missing checkout before reading or refreshing anything", async () => {
    const deps = { read: () => { throw new Error("must not read"); }, refresh: async () => { throw new Error("must not refresh"); } };
    expect((await handleMetricHostRefreshRequest("run-metrics/refresh-host", "POST", { checkout: "/checkout" }, false, deps))?.status).toBe(403);
    expect((await handleMetricHostRefreshRequest("run-metrics/refresh-host", "POST", {}, true, deps))?.status).toBe(400);
  });
});
