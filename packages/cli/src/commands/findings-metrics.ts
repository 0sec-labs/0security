import { Option, type Command } from "commander";
import { METRIC_COMMANDS, parseSince, readRunMetrics, renderMetrics, summarizeMetrics, type MetricCommand, type RunMetric } from "../run-metrics.js";
import { finishWithError, UsageError } from "./output.js";

export interface FindingsMetricsOptions { since?: string; command?: string; format?: string }
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
  const summary = summarizeMetrics(deps.read(), { ...(since !== undefined ? { since } : {}), ...(options.command ? { command: options.command as MetricCommand } : {}) });
  deps.out(options.format === "json" ? JSON.stringify({ ...summary, ...(options.since ? { since: new Date(since!).toISOString() } : {}) }, null, 2) : renderMetrics(summary));
}

export function registerFindingsMetricsCommand(parent: Command, deps: FindingsMetricsDeps = defaults): void {
  parent.command("metrics")
    .description("Show what scan, fix and verify runs cost and produced: cost per proposed fix and the share that passed their checks")
    .option("--since <when>", "Only runs since then: 36h, 7d, 2w or a date such as 2026-11-01")
    .option("--command <name>", `Only this command: ${METRIC_COMMANDS.join(", ")}`)
    .addOption(new Option("--format <format>", "Output: text or json").choices(["text", "json"]))
    .addHelpText("after", "\nEach run adds one line of counts, cost and finding ids to ~/.0/metrics.ndjson (no finding text or paths). The file keeps about 2 MB of history.")
    .action((options: FindingsMetricsOptions) => {
      try { runFindingsMetrics(options, deps); } catch (error) { finishWithError(error, { err: text => process.stderr.write(`${text}\n` ) }, options.format === "json"); }
    });
}
