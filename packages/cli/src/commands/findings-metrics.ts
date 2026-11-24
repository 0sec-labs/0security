import { Option, type Command } from "commander";
import { METRIC_COMMANDS, METRIC_GROUPS, groupMetrics, parseSince, readRunMetrics, renderGroups, renderGroupsCsv, renderMetrics, summarizeMetrics, type MetricCommand, type MetricGroup, type RunMetric } from "../run-metrics.js";
import { finishWithError, UsageError } from "./output.js";

export interface FindingsMetricsOptions { since?: string; command?: string; format?: string; by?: string }
export interface FindingsMetricsDeps { read(): RunMetric[]; out(text: string): void; now(): number }

const defaults: FindingsMetricsDeps = { read: () => readRunMetrics(), out: text => process.stdout.write(`${text}\n`), now: Date.now };

/** `0 findings metrics`: what the scan, fix and verify runs cost and produced, from the local metrics file. */
export function runFindingsMetrics(options: FindingsMetricsOptions, deps: FindingsMetricsDeps = defaults): void {
  let since: number | undefined;
  if (options.since !== undefined) {
    since = parseSince(options.since, deps.now());
    if (since === undefined) throw new UsageError("--since must be a number of hours, days or weeks such as 36h, 7d or 2w, or a date such as 2026-11-01.");
  }
  if (options.command !== undefined && !(METRIC_COMMANDS as readonly string[]).includes(options.command)) throw new UsageError(`--command must be one of ${METRIC_COMMANDS.join(", ")}.`);
  if (options.by !== undefined && !(METRIC_GROUPS as readonly string[]).includes(options.by)) throw new UsageError(`--by must be one of ${METRIC_GROUPS.join(", ")}.`);
  if (options.format === "csv" && !options.by) throw new UsageError("--format csv needs --by command, week or model.");
  const filter = { ...(since !== undefined ? { since } : {}), ...(options.command ? { command: options.command as MetricCommand } : {}) };
  if (options.by) {
    const by = options.by as MetricGroup;
    const rows = groupMetrics(deps.read(), by, filter);
    deps.out(options.format === "json" ? JSON.stringify({ by, ...(options.since ? { since: new Date(since!).toISOString() } : {}), rows }, null, 2) : options.format === "csv" ? renderGroupsCsv(by, rows) : renderGroups(by, rows));
    return;
  }
  const summary = summarizeMetrics(deps.read(), filter);
  deps.out(options.format === "json" ? JSON.stringify({ ...summary, ...(options.since ? { since: new Date(since!).toISOString() } : {}) }, null, 2) : renderMetrics(summary));
}

export function registerFindingsMetricsCommand(parent: Command, deps: FindingsMetricsDeps = defaults): void {
  parent.command("metrics")
    .description("Show what scan, fix and verify runs cost and produced: cost per proposed fix and the share that passed their checks")
    .option("--since <when>", "Only runs since then: 36h, 7d, 2w or a date such as 2026-11-01")
    .option("--command <name>", `Only this command: ${METRIC_COMMANDS.join(", ")}`)
    .addOption(new Option("--by <group>", "One row per command, week (Monday start) or model").choices([...METRIC_GROUPS]))
    .addOption(new Option("--format <format>", "Output: text, json, or csv (with --by)").choices(["text", "json", "csv"]))
    .addHelpText("after", "\nEach run adds one line of counts, cost and finding ids to ~/.0/metrics.ndjson (no finding text or paths). The file keeps about 2 MB of history.")
    .action((options: FindingsMetricsOptions) => {
      try { runFindingsMetrics(options, deps); } catch (error) { finishWithError(error, { err: text => process.stderr.write(`${text}\n` ) }, options.format === "json"); }
    });
}
