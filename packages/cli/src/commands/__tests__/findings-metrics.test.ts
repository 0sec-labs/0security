import { describe, expect, it } from "vitest";
import { runFindingsMetrics } from "../findings-metrics.js";
import { sanitizeMetric, type RunMetric } from "../../run-metrics.js";

const row = (extra: Record<string, unknown>): RunMetric => sanitizeMetric({ at: "2026-11-20T10:00:00.000Z", command: "fix", model: "m", budgetUsd: 1, costUsd: 0.1, durationSeconds: 10, findingsAttempted: 1, findingsProposed: 1, checksPassed: 1, tokens: null, status: "ok", findingIds: ["f-1"], ...extra })!;
const run = (options: Parameters<typeof runFindingsMetrics>[0], rows: RunMetric[]) => {
  const out: string[] = [];
  runFindingsMetrics(options, { read: () => rows, out: text => out.push(text), now: () => Date.parse("2026-11-22T00:00:00Z") });
  return out.join("\n");
};

describe("0 findings metrics", () => {
  const rows = [row({}), row({ at: "2026-11-10T10:00:00.000Z", costUsd: 0.3, findingsProposed: 0, checksPassed: 0, status: "failed" }), row({ command: "scan", findingsAttempted: null })];

  it("prints a text summary by default", () => {
    expect(run({}, rows)).toMatch(/fix\s+2\s+\$0\.4000/);
  });

  it("prints JSON with the filters applied", () => {
    const json = JSON.parse(run({ format: "json", since: "7d", command: "fix" }, rows));
    expect(json.runs).toBe(1);
    expect(json.byCommand.fix.runs).toBe(1);
    expect(json.shareVerified).toBe(1);
    expect(json.since).toBe("2026-11-15T00:00:00.000Z");
  });

  it("groups by week with fix-only cost per fix", () => {
    const out = run({ by: "week" }, rows);
    expect(out).toMatch(/^week\s+runs/);
    expect(out).toMatch(/2026-11-09\s+1\s+\$0\.3000/);
    expect(out).toMatch(/2026-11-16\s+2\s+\$0\.2000\s+2\s+\$0\.1000\s+100%/);
  });

  it("groups by model as JSON", () => {
    const json = JSON.parse(run({ by: "model", format: "json" }, [...rows, row({ model: "other", costUsd: 0.5 })]));
    expect(json.by).toBe("model");
    expect(json.rows.map((r: { key: string }) => r.key)).toEqual(["m", "other"]);
  });

  it("exports CSV with a header and empty cells for n/a", () => {
    const lines = run({ by: "command", format: "csv" }, rows).split("\n");
    expect(lines[0]).toBe("command,runs,cost_usd,duration_seconds,attempted,proposed,checks_passed,tokens,failed,cost_per_proposed_fix,share_verified");
    expect(lines[1]).toBe("fix,2,0.4,20,2,1,1,0,1,0.4,1");
    expect(lines[2]).toBe("scan,1,0.1,10,0,1,1,0,0,,");
  });

  it("refuses a bad --by and CSV without --by", () => {
    expect(() => run({ by: "sentinel" }, rows)).toThrow(/--by/);
    expect(() => run({ format: "csv" }, rows)).toThrow(/--by/);
  });

  it("refuses a bad --since or --command", () => {
    expect(() => run({ since: "soon" }, rows)).toThrow(/--since/);
    expect(() => run({ command: "burndown" }, rows)).toThrow(/--command/);
  });
});
