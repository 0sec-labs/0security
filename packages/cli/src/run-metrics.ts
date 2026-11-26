import { metricPullRequest } from "./metric-pr.js";
import { summarizeHostReceipts, type MetricHostObservation, type HostReceiptSummary } from "./metric-host-receipts.js";
/**
 * One metrics record per `0 scan`, `0 findings fix` and `0 findings verify` run, appended to
 * `~/.0/metrics.ndjson` (owner-only, one JSON object per line).
 *
 * A record holds numbers, the command name, the model id and finding ids. It never holds finding text, file paths,
 * prompts or credentials: every field is rebuilt from a fixed list on the way in and on the way out. When the file
 * passes the size cap it moves to `metrics.ndjson.1` (replacing the older copy), so history is bounded.
 */
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";
import { homeStateDir } from "@0/engine/shared";

export const METRICS_FILE = "metrics.ndjson";
export const METRICS_MAX_BYTES = 1024 * 1024;
export const METRIC_COMMANDS = ["scan", "fix", "verify", "sentinel"] as const;
export type MetricCommand = (typeof METRIC_COMMANDS)[number];
const STATUSES = ["ok", "budget", "timeout", "failed", "skipped", "prepass_only"] as const;
export type MetricStatus = (typeof STATUSES)[number];
const MAX_IDS = 50;

export interface MetricIdentity { sentinelId?: string; triggerId?: string; activationId?: string }
const metricId = (value: unknown): string | undefined => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value) && !["__proto__", "constructor", "prototype"].includes(value) ? value : undefined;
export function metricIdentity(raw: MetricIdentity): MetricIdentity {
  return Object.fromEntries(Object.entries(raw).filter(([key, value]) => ["sentinelId", "triggerId", "activationId"].includes(key) && metricId(value)));
}
export function metricIdentityFromEnv(env: NodeJS.ProcessEnv = process.env): MetricIdentity {
  return metricIdentity({ sentinelId: env.ZERO_METRIC_SENTINEL_ID, triggerId: env.ZERO_METRIC_TRIGGER_ID, activationId: env.ZERO_METRIC_ACTIVATION_ID });
}
export function metricIdentityEnv(identity: MetricIdentity): NodeJS.ProcessEnv {
  const clean = metricIdentity(identity);
  return { ZERO_METRIC_SENTINEL_ID: clean.sentinelId, ZERO_METRIC_TRIGGER_ID: clean.triggerId, ZERO_METRIC_ACTIVATION_ID: clean.activationId };
}
export interface RunMetric extends MetricIdentity {
  pullRequestUrl?: string;
  repositoryId?: string;
  version: 1;
  /** When the run started, ISO 8601. */
  at: string;
  command: MetricCommand;
  model: string;
  budgetUsd: number | null;
  costUsd: number | null;
  durationSeconds: number;
  /** Findings the run worked on: 1 for a fix, the checked findings for verify, not recorded for a scan. */
  findingsAttempted: number | null;
  /** Findings the run produced something for: a committed fix, a verdict, or a reported finding. */
  findingsProposed: number | null;
  /** Proposed fixes whose checks all passed. Fix runs only. */
  checksPassed: number | null;
  tokens: number | null;
  /** Usage is immutable; later code-host observations live in their separate timestamped ledger. */
  ci: "unknown";
  status: MetricStatus;
  findingIds: string[];
}

export function metricsPath(home?: string): string { return join(homeStateDir(home), METRICS_FILE); }

const count = (value: unknown): number | null => typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.round(value) : null;
const money = (value: unknown): number | null => typeof value === "number" && Number.isFinite(value) && value >= 0 ? Number(value.toFixed(6)) : null;

/** Keep only the known fields, with known shapes. Anything else, in particular free text, is dropped. */
export function sanitizeMetric(raw: unknown): RunMetric | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (!METRIC_COMMANDS.includes(r.command as MetricCommand)) return undefined;
  if (typeof r.at !== "string" || !Number.isFinite(Date.parse(r.at))) return undefined;
  const model = typeof r.model === "string" && /^[\w.:/@+-]{1,100}$/.test(r.model) ? r.model : "unknown";
  const ids = Array.isArray(r.findingIds) ? r.findingIds.filter((id): id is string => typeof id === "string" && /^[\w.:-]{1,128}$/.test(id)).slice(0, MAX_IDS) : [];
  return {
    ...(metricPullRequest(r.pullRequestUrl) ?? {}), ...metricIdentity(r as MetricIdentity), version: 1, at: new Date(r.at).toISOString(), command: r.command as MetricCommand, model,
    budgetUsd: money(r.budgetUsd), costUsd: money(r.costUsd), durationSeconds: count(r.durationSeconds) ?? 0,
    findingsAttempted: count(r.findingsAttempted), findingsProposed: count(r.findingsProposed), checksPassed: count(r.checksPassed), tokens: count(r.tokens),
    ci: "unknown", status: STATUSES.includes(r.status as MetricStatus) ? (r.status as MetricStatus) : "failed", findingIds: ids,
  };
}

/** Append one record. Never throws: a full disk or a read-only home must not fail a scan or a fix. */
export function appendRunMetric(record: Omit<RunMetric, "version" | "ci"> & Partial<Pick<RunMetric, "version" | "ci">>, home?: string): void {
  try {
    const clean = sanitizeMetric({ ...metricIdentityFromEnv(), ...record });
    if (!clean) return;
    const path = metricsPath(home);
    mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
    if (existsSync(path) && statSync(path).size >= METRICS_MAX_BYTES) renameSync(path, `${path}.1`);
    appendFileSync(path, `${JSON.stringify(clean)}\n`, { mode: 0o600 });
    chmodSync(path, 0o600);
  } catch { /* metrics are best effort */ }
}

/** Records from the rotated and the current file, oldest first. Lines that are not valid records are skipped. */
export function readRunMetrics(home?: string): RunMetric[] {
  const path = metricsPath(home);
  const out: RunMetric[] = [];
  for (const file of [`${path}.1`, path]) {
    if (!existsSync(file)) continue;
    let text = "";
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try { const record = sanitizeMetric(JSON.parse(line)); if (record) out.push(record); } catch { /* a torn line */ }
    }
  }
  return out.sort((a, b) => a.at.localeCompare(b.at));
}

/** `7d`, `36h`, `2w`, or a date such as `2026-11-01`, as a point in time. Undefined when it is none of those. */
export function parseSince(text: string, now: number): number | undefined {
  const relative = /^(\d+)([hdw])$/.exec(text.trim());
  if (relative) return now - Number(relative[1]) * { h: 3_600_000, d: 86_400_000, w: 604_800_000 }[relative[2] as "h" | "d" | "w"];
  const at = Date.parse(text);
  return Number.isFinite(at) ? at : undefined;
}

export interface CommandSummary { unknownCostRuns?: number; unknownTokenRuns?: number; runs: number; costUsd: number; durationSeconds: number; attempted: number; proposed: number; checksPassed: number; tokens: number; failed: number }
export interface MetricsSummary {
  host?: HostReceiptSummary;
  unknownCostRuns?: number; unknownTokenRuns?: number;
  runs: number; since?: string; command?: MetricCommand;
  byCommand: Partial<Record<MetricCommand, CommandSummary>>;
  costUsd: number;
  /** Fix runs: cost of all fix runs divided by the fixes they proposed. Null when none was proposed. */
  costPerProposedFix: number | null;
  /** Fix runs: proposed fixes whose checks all passed, divided by proposed fixes. Null when none was proposed. */
  shareVerified: number | null;
  /** Verify runs: findings with a verdict. */
  verdicts: number;
}

export function summarizeMetrics(records: RunMetric[], filter: { since?: number; command?: MetricCommand } = {}, observations: MetricHostObservation[] = []): MetricsSummary {
  const rows = records.filter(r => (filter.command === undefined || r.command === filter.command) && (filter.since === undefined || Date.parse(r.at) >= filter.since));
  const byCommand: MetricsSummary["byCommand"] = {};
  for (const r of rows) {
    const s = byCommand[r.command] ??= { runs: 0, costUsd: 0, durationSeconds: 0, attempted: 0, proposed: 0, checksPassed: 0, tokens: 0, failed: 0, unknownCostRuns: 0, unknownTokenRuns: 0 };
    s.unknownCostRuns = (s.unknownCostRuns ?? 0) + Number(r.costUsd === null); s.unknownTokenRuns = (s.unknownTokenRuns ?? 0) + Number(r.tokens === null);
    s.runs++; s.costUsd += r.costUsd ?? 0; s.durationSeconds += r.durationSeconds; s.attempted += r.findingsAttempted ?? 0;
    s.proposed += r.findingsProposed ?? 0; s.checksPassed += r.checksPassed ?? 0; s.tokens += r.tokens ?? 0; if (r.status === "failed") s.failed++;
  }
  const fix = byCommand.fix;
  return {
    host: summarizeHostReceipts(rows, observations),
    unknownCostRuns: rows.filter(row => row.costUsd === null).length, unknownTokenRuns: rows.filter(row => row.tokens === null).length,
    runs: rows.length, ...(filter.command ? { command: filter.command } : {}), byCommand,
    costUsd: Number(Object.values(byCommand).reduce((a, s) => a + s.costUsd, 0).toFixed(6)),
    costPerProposedFix: fix && fix.proposed > 0 && !fix.unknownCostRuns ? Number((fix.costUsd / fix.proposed).toFixed(6)) : null,
    shareVerified: fix && fix.proposed > 0 ? fix.checksPassed / fix.proposed : null,
    verdicts: byCommand.verify?.proposed ?? 0,
  };
}

export const METRIC_GROUPS = ["command", "week", "model", "sentinel", "trigger"] as const;
export type MetricGroup = (typeof METRIC_GROUPS)[number];
export interface GroupRow extends CommandSummary {
  host?: HostReceiptSummary;
  key: string;
  /** Fix runs in the group: their cost divided by the fixes they proposed. Null when none was proposed. */
  costPerProposedFix: number | null;
  /** Fix runs in the group: proposed fixes whose checks all passed, divided by proposed fixes. Null when none was proposed. */
  shareVerified: number | null;
}

/** The Monday (UTC) of the week a run started in, as a date such as 2026-11-16. */
export function weekStart(at: string): string {
  const day = new Date(at);
  day.setUTCHours(0, 0, 0, 0);
  day.setUTCDate(day.getUTCDate() - ((day.getUTCDay() + 6) % 7));
  return day.toISOString().slice(0, 10);
}

/** One row per command, per week or per model, sorted by key. Cost per fix and share verified use fix runs only. */
export function groupMetrics(records: RunMetric[], by: MetricGroup, filter: { since?: number; command?: MetricCommand } = {}, observations: MetricHostObservation[] = []): GroupRow[] {
  const rows = records.filter(r => (filter.command === undefined || r.command === filter.command) && (filter.since === undefined || Date.parse(r.at) >= filter.since));
  const groups = new Map<string, { all: CommandSummary; fix: CommandSummary; records: RunMetric[] }>();
  const blank = (): CommandSummary => ({ runs: 0, costUsd: 0, durationSeconds: 0, attempted: 0, proposed: 0, checksPassed: 0, tokens: 0, failed: 0, unknownCostRuns: 0, unknownTokenRuns: 0 });
  const add = (s: CommandSummary, r: RunMetric) => {
    s.unknownCostRuns = (s.unknownCostRuns ?? 0) + Number(r.costUsd === null); s.unknownTokenRuns = (s.unknownTokenRuns ?? 0) + Number(r.tokens === null);
    s.runs++; s.costUsd += r.costUsd ?? 0; s.durationSeconds += r.durationSeconds; s.attempted += r.findingsAttempted ?? 0;
    s.proposed += r.findingsProposed ?? 0; s.checksPassed += r.checksPassed ?? 0; s.tokens += r.tokens ?? 0; if (r.status === "failed") s.failed++;
  };
  for (const r of rows) {
    const key = by === "command" ? r.command : by === "week" ? weekStart(r.at) : by === "sentinel" ? r.sentinelId ?? "unassigned" : by === "trigger" ? r.triggerId ?? "unassigned" : r.model;
    const g = groups.get(key) ?? { all: blank(), fix: blank(), records: [] };
    groups.set(key, g); g.records.push(r);
    add(g.all, r);
    if (r.command === "fix") add(g.fix, r);
  }
  return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, { all, fix, records: groupRecords }]) => ({
    host: summarizeHostReceipts(groupRecords, observations),
    key, ...all, costUsd: Number(all.costUsd.toFixed(6)),
    costPerProposedFix: fix.proposed > 0 && !fix.unknownCostRuns ? Number((fix.costUsd / fix.proposed).toFixed(6)) : null,
    shareVerified: fix.proposed > 0 ? fix.checksPassed / fix.proposed : null,
  }));
}

const csvCell = (value: string | number | null): string => value === null ? "" : /[",\n]/.test(String(value)) ? `"${String(value).replace(/"/g, '""')}"` : String(value);

/** Grouped rows as CSV with a header line. Empty cells mean not available. */
export function renderGroupsCsv(by: MetricGroup, rows: GroupRow[]): string {
  const header = [by, "runs", "cost_usd", "duration_seconds", "attempted", "proposed", "checks_passed", "tokens", "failed", "cost_per_proposed_fix", "share_verified", "unknown_cost_runs", "unknown_token_runs", "pull_requests", "merged_pull_requests", "closed_pull_requests", "open_pull_requests", "unknown_pull_requests", "share_merged", "ci_passing", "ci_failing", "ci_pending", "ci_none", "ci_unknown", "host_last_checked_at", "unlinked_fix_runs"];
  return [header.join(","), ...rows.map(r => [r.key, r.runs, r.unknownCostRuns === r.runs ? null : r.costUsd, r.durationSeconds, r.attempted, r.proposed, r.checksPassed, r.unknownTokenRuns === r.runs ? null : r.tokens, r.failed, r.costPerProposedFix, r.shareVerified === null ? null : Number(r.shareVerified.toFixed(4)), r.unknownCostRuns ?? 0, r.unknownTokenRuns ?? 0, r.host?.pullRequests ?? 0, r.host?.merged ?? 0, r.host?.closed ?? 0, r.host?.open ?? 0, r.host?.unknown ?? 0, r.host?.shareMerged ?? null, r.host?.ciPassing ?? 0, r.host?.ciFailing ?? 0, r.host?.ciPending ?? 0, r.host?.ciNone ?? 0, r.host?.ciUnknown ?? 0, r.host?.lastCheckedAt ?? null, r.host?.unlinkedFixRuns ?? 0].map(csvCell).join(","))].join("\n");
}

const knownCostText = (row: { runs: number; costUsd: number; unknownCostRuns?: number }): string =>
  row.runs > 0 && row.unknownCostRuns === row.runs ? "unknown" : `$${row.costUsd.toFixed(4)}${row.unknownCostRuns ? ` (+${row.unknownCostRuns} unknown)` : ""}`;

/** Grouped rows as a text table. */
export function renderGroups(by: MetricGroup, rows: GroupRow[]): string {
  if (!rows.length) return "No runs recorded yet. Metrics are written by 0security scan, 0security findings fix and 0security findings verify.";
  const usd = (n: number | null) => n === null ? "n/a" : `$${n.toFixed(4)}`;
  const width = Math.max(by.length, ...rows.map(r => r.key.length));
  return [
    `${by.padEnd(width)}  runs  cost        proposed  cost per fix  checks passed  merged share`,
    ...rows.map(r => `${r.key.padEnd(width)}  ${String(r.runs).padStart(4)}  ${knownCostText(r).padEnd(10)}  ${String(r.proposed).padStart(8)}  ${usd(r.costPerProposedFix).padStart(12)}  ${(r.shareVerified === null ? "n/a" : `${Math.round(r.shareVerified * 100)}%`).padStart(13)}  ${r.host?.shareMerged == null ? "unknown" : `${Math.round(r.host.shareMerged * 100)}% (${r.host.merged}/${r.host.pullRequests} PRs)`}`),
    `Missing receipts: ${rows.reduce((sum, row) => sum + (row.unknownCostRuns ?? 0), 0)} cost runs; ${rows.reduce((sum, row) => sum + (row.unknownTokenRuns ?? 0), 0)} token runs. Cost values are known subtotals.`,
  ].join("\n");
}

export function renderMetrics(summary: MetricsSummary): string {
  if (!summary.runs) return "No runs recorded yet. Metrics are written by 0security scan, 0security findings fix and 0security findings verify.";
  const usd = (n: number | null) => n === null ? "n/a" : `$${n.toFixed(4)}`;
  const lines = [
    "command  runs  cost        avg time  attempted  proposed  checks passed  failed",
    ...METRIC_COMMANDS.filter(c => summary.byCommand[c]).map(c => {
      const s = summary.byCommand[c]!;
      return `${c.padEnd(8)} ${String(s.runs).padStart(4)}  ${knownCostText(s).padEnd(10)}  ${`${Math.round(s.durationSeconds / s.runs)}s`.padStart(8)}  ${String(s.attempted).padStart(9)}  ${String(s.proposed).padStart(8)}  ${c === "fix" ? String(s.checksPassed).padStart(13) : "-".padStart(13)}  ${String(s.failed).padStart(6)}`;
    }),
    "",
    `Known cost subtotal ${knownCostText(summary)}. Cost per proposed fix ${usd(summary.costPerProposedFix)}. Share of proposed fixes with all checks passing ${summary.shareVerified === null ? "n/a" : `${Math.round(summary.shareVerified * 100)}%`}.`,
    `Missing receipts: ${summary.unknownCostRuns ?? 0} cost runs; ${summary.unknownTokenRuns ?? 0} token runs.`,
    `Merged share of unique recorded PRs: ${summary.host?.shareMerged == null ? "unknown" : `${Math.round(summary.host.shareMerged * 100)}% (${summary.host.merged}/${summary.host.pullRequests})`}. Host CI and lifecycle use explicit timestamped refreshes; local checks are separate.`,
    "Read host receipts with metrics --refresh-host --repo <checkout>. Missing observations remain unknown; merged does not establish human approval or fix correctness.",
  ];
  return lines.join("\n");
}

export type MetricSink = (record: Omit<RunMetric, "version" | "ci">) => void;
/** Receipts are cumulative; a queued turn takes its baseline when it actually starts. */
export function usageTokens(usage: { inputTokens?: number; outputTokens?: number } | undefined): number | null {
  return typeof usage?.inputTokens === "number" && typeof usage.outputTokens === "number" && Number.isFinite(usage.inputTokens) && Number.isFinite(usage.outputTokens) ? Math.max(0, usage.inputTokens + usage.outputTokens) : null;
}
