import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { METRICS_MAX_BYTES, appendRunMetric, metricsPath, parseSince, readRunMetrics, sanitizeMetric, groupMetrics, renderGroups, renderGroupsCsv, metricIdentityFromEnv, metricIdentityEnv, usageTokens, summarizeMetrics, renderMetrics, type RunMetric } from "./run-metrics.js";

const record = (extra: Partial<RunMetric> = {}): Omit<RunMetric, "version" | "ci"> => ({
  at: "2026-11-20T10:00:00.000Z", command: "fix", model: "gpt-6-luna", budgetUsd: 0.5, costUsd: 0.02, durationSeconds: 30, findingsAttempted: 1, findingsProposed: 1, checksPassed: 1, tokens: 1200, status: "ok", findingIds: ["f-1"], ...extra,
});
const home = () => mkdtempSync(join(tmpdir(), "0-metrics-"));

describe("run metrics file", () => {
  it("appends one JSON line per run, readable by the owner only", () => {
    const h = home();
    appendRunMetric(record(), h);
    appendRunMetric(record({ at: "2026-11-21T10:00:00.000Z", command: "scan" }), h);
    const lines = readFileSync(metricsPath(h), "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!)).toMatchObject({ version: 1, ci: "unknown", command: "fix" });
    expect(statSync(metricsPath(h)).mode & 0o777).toBe(0o600);
    expect(readRunMetrics(h).map(r => r.command)).toEqual(["fix", "scan"]);
  });

  it("keeps no free text: unknown fields, odd model names and odd ids are dropped", () => {
    const clean = sanitizeMetric({ ...record(), title: "SQL injection in src/db.ts", path: "/home/me/app", prompt: "secret", model: "bad model name with spaces", findingIds: ["f-1", "has spaces and /slashes", 7] });
    expect(clean).toBeDefined();
    expect(Object.keys(clean!).sort()).toEqual(["at", "budgetUsd", "checksPassed", "ci", "command", "costUsd", "durationSeconds", "findingIds", "findingsAttempted", "findingsProposed", "model", "status", "tokens", "version"]);
    expect(clean!.model).toBe("unknown");
    expect(clean!.findingIds).toEqual(["f-1"]);
    expect(sanitizeMetric({ ...record(), command: "burndown" })).toBeUndefined();
    expect(sanitizeMetric({ ...record(), at: "yesterday" })).toBeUndefined();
    expect(sanitizeMetric({ ...record(), costUsd: -1, tokens: Number.NaN })).toMatchObject({ costUsd: null, tokens: null });
  });

  it("caps the ids per record", () => {
    const ids = Array.from({ length: 80 }, (_, i) => `f-${i}`);
    expect(sanitizeMetric(record({ findingIds: ids }))!.findingIds).toHaveLength(50);
  });

  it("rotates to a second file at the size cap and reads both", () => {
    const h = home();
    appendRunMetric(record({ at: "2026-11-01T00:00:00.000Z" }), h);
    writeFileSync(metricsPath(h), `${readFileSync(metricsPath(h), "utf8")}${" ".repeat(METRICS_MAX_BYTES)}\n`);
    appendRunMetric(record({ at: "2026-11-02T00:00:00.000Z" }), h);
    expect(statSync(`${metricsPath(h)}.1`).size).toBeGreaterThan(METRICS_MAX_BYTES);
    expect(statSync(metricsPath(h)).size).toBeLessThan(2000);
    expect(readRunMetrics(h).map(r => r.at.slice(0, 10))).toEqual(["2026-11-01", "2026-11-02"]);
  });

  it("skips torn lines and never throws on an unwritable home", () => {
    const h = home();
    appendRunMetric(record(), h);
    writeFileSync(metricsPath(h), `${readFileSync(metricsPath(h), "utf8")}{"command":"fix","at":\nnot json\n`);
    expect(readRunMetrics(h)).toHaveLength(1);
    expect(() => appendRunMetric(record(), "/dev/null/nope")).not.toThrow();
  });
});

describe("metrics summary", () => {
  const rows = [
    sanitizeMetric(record({ costUsd: 0.02, findingsProposed: 1, checksPassed: 1 }))!,
    sanitizeMetric(record({ at: "2026-11-21T10:00:00.000Z", costUsd: 0.04, findingsProposed: 1, checksPassed: 0 }))!,
    sanitizeMetric(record({ at: "2026-11-21T11:00:00.000Z", costUsd: 0.06, findingsProposed: 0, checksPassed: 0, status: "failed" }))!,
    sanitizeMetric(record({ command: "scan", costUsd: 0.1, findingsAttempted: null, findingsProposed: 7, checksPassed: null }))!,
    sanitizeMetric(record({ command: "verify", costUsd: 0.2, findingsAttempted: 10, findingsProposed: 9, checksPassed: null }))!,
  ];

  it("reports cost per proposed fix and the share that passed their checks", () => {
    const s = summarizeMetrics(rows);
    expect(s.runs).toBe(5);
    expect(s.byCommand.fix).toMatchObject({ runs: 3, proposed: 2, checksPassed: 1, failed: 1 });
    expect(s.costPerProposedFix).toBeCloseTo(0.06, 6);
    expect(s.shareVerified).toBe(0.5);
    expect(s.verdicts).toBe(9);
    expect(s.costUsd).toBeCloseTo(0.42, 6);
  });

  it("filters by command and by time", () => {
    expect(summarizeMetrics(rows, { command: "scan" }).runs).toBe(1);
    expect(summarizeMetrics(rows, { since: Date.parse("2026-11-21T00:00:00Z") }).runs).toBe(2);
    expect(summarizeMetrics(rows, { command: "scan" }).costPerProposedFix).toBeNull();
  });

  it("renders a table, or a plain sentence when there are no runs", () => {
    expect(renderMetrics(summarizeMetrics(rows))).toMatch(/Cost per proposed fix \$0\.0600\. Share .* 50%/);
    expect(renderMetrics(summarizeMetrics([]))).toMatch(/No runs recorded yet/);
  });

  it("parses --since as hours, days, weeks or a date", () => {
    const now = Date.parse("2026-11-22T00:00:00Z");
    expect(parseSince("36h", now)).toBe(now - 36 * 3_600_000);
    expect(parseSince("7d", now)).toBe(now - 7 * 86_400_000);
    expect(parseSince("2w", now)).toBe(now - 14 * 86_400_000);
    expect(parseSince("2026-11-01", now)).toBe(Date.parse("2026-11-01"));
    expect(parseSince("soon", now)).toBeUndefined();
  });
});

describe("workflow metric identity", () => {
  it("keeps safe opaque IDs and drops names, paths and injected values", () => {
    expect(sanitizeMetric(record({ sentinelId: "sentinel-1", triggerId: "trigger_2", activationId: "activation-3" }))).toMatchObject({ sentinelId: "sentinel-1", triggerId: "trigger_2", activationId: "activation-3" });
    expect(metricIdentityFromEnv({ ZERO_METRIC_SENTINEL_ID: "/home/private/repo", ZERO_METRIC_TRIGGER_ID: "token with spaces", ZERO_METRIC_ACTIVATION_ID: "__proto__" })).toEqual({});
    expect(metricIdentityEnv({ sentinelId: "s-1", triggerId: "t-1" })).toMatchObject({ ZERO_METRIC_SENTINEL_ID: "s-1", ZERO_METRIC_TRIGGER_ID: "t-1" });
  });
  it("does not invent missing token receipts", () => {
    expect(usageTokens(undefined)).toBeNull(); expect(usageTokens({ inputTokens: 4 })).toBeNull();
    expect(usageTokens({ inputTokens: 4, outputTokens: 2 })).toBe(6);
  });
});

describe("unknown usage receipts in grouped metrics", () => {
  it("counts missing receipts in JSON and additive CSV columns instead of presenting free runs", () => {
    const rows = groupMetrics([sanitizeMetric(record({ command: "scan", costUsd: null, tokens: null }))!], "command");
    expect(rows[0]).toMatchObject({ unknownCostRuns: 1, unknownTokenRuns: 1 });
    expect(renderGroupsCsv("command", rows).split("\n")[1]!.split(",")[2]).toBe("");
    expect(renderGroupsCsv("command", rows).split("\n")[1]!.split(",")[7]).toBe("");
    expect(renderGroupsCsv("command", rows)).toMatch(/unknown_cost_runs,unknown_token_runs/);
  });
  it("keeps partial known totals and withholds cost per fix when a fix cost is missing", () => {
    const rows = groupMetrics([sanitizeMetric(record({ costUsd: .2, tokens: 120 }))!, sanitizeMetric(record({ costUsd: null, tokens: null }))!], "command");
    expect(rows[0]).toMatchObject({ costUsd: .2, tokens: 120, unknownCostRuns: 1, unknownTokenRuns: 1, costPerProposedFix: null });
    expect(summarizeMetrics([sanitizeMetric(record({ costUsd: null }))!]).costPerProposedFix).toBeNull();
  });
});

describe("human-readable missing receipts", () => {
  it("never presents unpriced runs as free in default or grouped CLI reports", () => {
    const records = [sanitizeMetric(record({ command: "scan", costUsd: null, tokens: null }))!];
    expect(renderMetrics(summarizeMetrics(records))).toContain("Known cost subtotal unknown");
    expect(renderMetrics(summarizeMetrics(records))).toContain("1 cost runs; 1 token runs");
    expect(renderGroups("command", groupMetrics(records, "command"))).not.toContain("$0.0000");
  });
});
