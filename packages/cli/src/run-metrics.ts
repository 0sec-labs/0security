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
export const METRIC_COMMANDS = ["scan", "fix", "verify"] as const;
export type MetricCommand = (typeof METRIC_COMMANDS)[number];
const STATUSES = ["ok", "budget", "timeout", "failed", "skipped", "prepass_only"] as const;
export type MetricStatus = (typeof STATUSES)[number];
const MAX_IDS = 50;

export interface RunMetric {
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
  /** The CI result of a proposed change is not known to the run that makes it. */
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
    version: 1, at: new Date(r.at).toISOString(), command: r.command as MetricCommand, model,
    budgetUsd: money(r.budgetUsd), costUsd: money(r.costUsd), durationSeconds: count(r.durationSeconds) ?? 0,
    findingsAttempted: count(r.findingsAttempted), findingsProposed: count(r.findingsProposed), checksPassed: count(r.checksPassed), tokens: count(r.tokens),
    ci: "unknown", status: STATUSES.includes(r.status as MetricStatus) ? (r.status as MetricStatus) : "failed", findingIds: ids,
  };
}

/** Append one record. Never throws: a full disk or a read-only home must not fail a scan or a fix. */
export function appendRunMetric(record: Omit<RunMetric, "version" | "ci"> & Partial<Pick<RunMetric, "version" | "ci">>, home?: string): void {
  try {
    const clean = sanitizeMetric(record);
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

export interface CommandSummary { runs: number; costUsd: number; durationSeconds: number; attempted: number; proposed: number; checksPassed: number; tokens: number; failed: number }
export interface MetricsSummary {
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

export function summarizeMetrics(records: RunMetric[], filter: { since?: number; command?: MetricCommand } = {}): MetricsSummary {
  const rows = records.filter(r => (filter.command === undefined || r.command === filter.command) && (filter.since === undefined || Date.parse(r.at) >= filter.since));
  const byCommand: MetricsSummary["byCommand"] = {};
  for (const r of rows) {
    const s = byCommand[r.command] ??= { runs: 0, costUsd: 0, durationSeconds: 0, attempted: 0, proposed: 0, checksPassed: 0, tokens: 0, failed: 0 };
    s.runs++; s.costUsd += r.costUsd ?? 0; s.durationSeconds += r.durationSeconds; s.attempted += r.findingsAttempted ?? 0;
    s.proposed += r.findingsProposed ?? 0; s.checksPassed += r.checksPassed ?? 0; s.tokens += r.tokens ?? 0; if (r.status === "failed") s.failed++;
  }
  const fix = byCommand.fix;
  return {
    runs: rows.length, ...(filter.command ? { command: filter.command } : {}), byCommand,
    costUsd: Number(Object.values(byCommand).reduce((a, s) => a + s.costUsd, 0).toFixed(6)),
    costPerProposedFix: fix && fix.proposed > 0 ? Number((fix.costUsd / fix.proposed).toFixed(6)) : null,
    shareVerified: fix && fix.proposed > 0 ? fix.checksPassed / fix.proposed : null,
    verdicts: byCommand.verify?.proposed ?? 0,
  };
}

export const METRIC_GROUPS = ["command", "week", "model"] as const;
export type MetricGroup = (typeof METRIC_GROUPS)[number];
export interface GroupRow extends CommandSummary {
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
export function groupMetrics(records: RunMetric[], by: MetricGroup, filter: { since?: number; command?: MetricCommand } = {}): GroupRow[] {
  const rows = records.filter(r => (filter.command === undefined || r.command === filter.command) && (filter.since === undefined || Date.parse(r.at) >= filter.since));
  const groups = new Map<string, { all: CommandSummary; fix: CommandSummary }>();
  const blank = (): CommandSummary => ({ runs: 0, costUsd: 0, durationSeconds: 0, attempted: 0, proposed: 0, checksPassed: 0, tokens: 0, failed: 0 });
  const add = (s: CommandSummary, r: RunMetric) => {
    s.runs++; s.costUsd += r.costUsd ?? 0; s.durationSeconds += r.durationSeconds; s.attempted += r.findingsAttempted ?? 0;
    s.proposed += r.findingsProposed ?? 0; s.checksPassed += r.checksPassed ?? 0; s.tokens += r.tokens ?? 0; if (r.status === "failed") s.failed++;
  };
  for (const r of rows) {
    const key = by === "command" ? r.command : by === "week" ? weekStart(r.at) : r.model;
    const g = groups.get(key) ?? { all: blank(), fix: blank() };
    groups.set(key, g);
    add(g.all, r);
    if (r.command === "fix") add(g.fix, r);
  }
  return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, { all, fix }]) => ({
    key, ...all, costUsd: Number(all.costUsd.toFixed(6)),
    costPerProposedFix: fix.proposed > 0 ? Number((fix.costUsd / fix.proposed).toFixed(6)) : null,
    shareVerified: fix.proposed > 0 ? fix.checksPassed / fix.proposed : null,
  }));
}

const csvCell = (value: string | number | null): string => value === null ? "" : /[",\n]/.test(String(value)) ? `"${String(value).replace(/"/g, '""')}"` : String(value);

/** Grouped rows as CSV with a header line. Empty cells mean not available. */
export function renderGroupsCsv(by: MetricGroup, rows: GroupRow[]): string {
  const header = [by, "runs", "cost_usd", "duration_seconds", "attempted", "proposed", "checks_passed", "tokens", "failed", "cost_per_proposed_fix", "share_verified"];
  return [header.join(","), ...rows.map(r => [r.key, r.runs, r.costUsd, r.durationSeconds, r.attempted, r.proposed, r.checksPassed, r.tokens, r.failed, r.costPerProposedFix, r.shareVerified === null ? null : Number(r.shareVerified.toFixed(4))].map(csvCell).join(","))].join("\n");
}

/** Grouped rows as a text table. */
export function renderGroups(by: MetricGroup, rows: GroupRow[]): string {
  if (!rows.length) return "No runs recorded yet. Metrics are written by 0security scan, 0security findings fix and 0security findings verify.";
  const usd = (n: number | null) => n === null ? "n/a" : `$${n.toFixed(4)}`;
  const width = Math.max(by.length, ...rows.map(r => r.key.length));
  return [
    `${by.padEnd(width)}  runs  cost        proposed  cost per fix  checks passed`,
    ...rows.map(r => `${r.key.padEnd(width)}  ${String(r.runs).padStart(4)}  ${usd(r.costUsd).padEnd(10)}  ${String(r.proposed).padStart(8)}  ${usd(r.costPerProposedFix).padStart(12)}  ${(r.shareVerified === null ? "n/a" : `${Math.round(r.shareVerified * 100)}%`).padStart(13)}`),
  ].join("\n");
}

export function renderMetrics(summary: MetricsSummary): string {
  if (!summary.runs) return "No runs recorded yet. Metrics are written by 0security scan, 0security findings fix and 0security findings verify.";
  const usd = (n: number | null) => n === null ? "n/a" : `$${n.toFixed(4)}`;
  const lines = [
    "command  runs  cost        avg time  attempted  proposed  checks passed  failed",
    ...METRIC_COMMANDS.filter(c => summary.byCommand[c]).map(c => {
      const s = summary.byCommand[c]!;
      return `${c.padEnd(8)} ${String(s.runs).padStart(4)}  ${usd(s.costUsd).padEnd(10)}  ${`${Math.round(s.durationSeconds / s.runs)}s`.padStart(8)}  ${String(s.attempted).padStart(9)}  ${String(s.proposed).padStart(8)}  ${c === "fix" ? String(s.checksPassed).padStart(13) : "-".padStart(13)}  ${String(s.failed).padStart(6)}`;
    }),
    "",
    `Total cost ${usd(summary.costUsd)}. Cost per proposed fix ${usd(summary.costPerProposedFix)}. Share of proposed fixes with all checks passing ${summary.shareVerified === null ? "n/a" : `${Math.round(summary.shareVerified * 100)}%`}.`,
    "CI results are not recorded: a run does not see the pipeline of the pull request it opens.",
  ];
  return lines.join("\n");
}
