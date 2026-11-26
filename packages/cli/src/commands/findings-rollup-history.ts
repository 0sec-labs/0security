/** Dated complete repository snapshots. Finding lastSeen is not the time a triage state was captured. */
import { z } from "zod";
import { mergeRows, rollupExportSchema, summarise, type RollupExport, type RollupRow, type RollupSummary } from "./findings-rollup-core.js";
export const HISTORY_SCHEMA = "0.findings-rollup.history.v1";
export const REPORT_SCHEMA = "0.findings-rollup.report.v1";
const snapshotSchema = rollupExportSchema.extend({ source: z.string().min(1).max(300) });
const historySchema = z.object({ schema: z.literal(HISTORY_SCHEMA), snapshots: z.array(snapshotSchema).max(10_000) });
export type RollupSnapshot = z.infer<typeof snapshotSchema>;
export type TrendPoint = { at: string; sources: string[]; repositories: string[]; summary: RollupSummary };
export type RollupReport = RollupSummary & { schema: typeof REPORT_SCHEMA; snapshots: Array<{ at: string; source: string; repositories: string[] }>; observations: Array<{ repository: string; at: string; sources: string[] }>; snapshotTrend: TrendPoint[] };

export function parseHistory(value: unknown): RollupSnapshot[] {
  const parsed = historySchema.safeParse(value);
  if (!parsed.success) throw new Error(`Invalid ${HISTORY_SCHEMA} archive: ${parsed.error.issues[0]?.path.join(".")}.`);
  if (parsed.data.snapshots.reduce((total, item) => total + item.findings.length, 0) > 200_000) throw new Error("History exceeds 200000 finding rows.");
  return parsed.data.snapshots;
}
export function snapshotRepositories(snapshot: RollupExport): string[] {
  return [...new Set([...(snapshot.repositories ?? []), ...snapshot.findings.map(item => item.repository)])].sort();
}

/** Latest complete snapshot wins per repository, even when its rows have unchanged lastSeen timestamps or are empty. */
export function latestSnapshotRows(snapshots: RollupSnapshot[]): { rows: RollupRow[]; repositories: string[] } {
  const latest = new Map<string, { at: number; rows: RollupRow[] }>();
  for (const snapshot of snapshots) {
    const at = Date.parse(snapshot.exportedAt);
    const groups = new Map<string, RollupRow[]>((snapshot.repositories ?? []).map(repository => [repository, []]));
    for (const finding of snapshot.findings) {
      const group = groups.get(finding.repository);
      if (group) group.push(finding); else groups.set(finding.repository, [finding]);
    }
    for (const [repository, rows] of groups) {
      const have = latest.get(repository);
      if (!have || at > have.at) latest.set(repository, { at, rows });
      else if (at === have.at) have.rows.push(...rows);
    }
  }
  return { rows: mergeRows([...latest.values()].flatMap(item => item.rows)), repositories: [...latest.keys()].sort() };
}

export function buildRollupReport(snapshots: RollupSnapshot[], now: Date, earlier?: RollupExport): RollupReport {
  const current = latestSnapshotRows(snapshots);
  const groups = new Map<string, RollupSnapshot[]>();
  for (const snapshot of snapshots) {
    const at = new Date(snapshot.exportedAt).toISOString();
    groups.set(at, [...(groups.get(at) ?? []), snapshot]);
  }
  const trend = [...groups].sort(([a], [b]) => a.localeCompare(b)).map(([at, group]) => {
    const view = latestSnapshotRows(group); const summary = summarise(view.rows, new Date(at)); summary.repositories = view.repositories.length;
    return { at, sources: [...new Set(group.map(item => item.source))].sort(), repositories: view.repositories, summary };
  });
  const observed = new Map<string, { repository: string; at: string; sources: string[] }>();
  for (const snapshot of snapshots) {
    const at = new Date(snapshot.exportedAt).toISOString();
    for (const repository of snapshotRepositories(snapshot)) {
      const have = observed.get(repository);
      if (!have || at > have.at) observed.set(repository, { repository, at, sources: [snapshot.source] });
      else if (at === have.at && !have.sources.includes(snapshot.source)) have.sources.push(snapshot.source);
    }
  }
  const observations = [...observed.values()].sort((a, b) => a.repository.localeCompare(b.repository)).map(item => ({ ...item, sources: item.sources.sort() }));
  return { ...summarise(current.rows, now, earlier, current.repositories), repositories: current.repositories.length, schema: REPORT_SCHEMA, observations, snapshots: snapshots.map(item => ({ at: item.exportedAt, source: item.source, repositories: snapshotRepositories(item) })), snapshotTrend: trend };
}
const clean = (value: string) => value.replace(/[\u0000-\u001f\u007f]/g, " ");
export function trendText(report: RollupReport): string {
  return `\nCurrent repository observations: ${report.observations.map(item => `${clean(item.repository)} at ${item.at}`).join("; ")}\nSnapshot trend (only repositories observed at each timestamp; coverage may differ):\n${report.snapshotTrend.map(point => `  ${point.at}  ${point.summary.open} open  ${point.summary.bySeverity.find(item => item.name === "critical")?.count ?? 0} critical  repositories: ${point.repositories.map(clean).join(", ")}  sources: ${point.sources.map(clean).join(", ")}`).join("\n")}`;
}
/** Stable long-form counts: directly importable by spreadsheets and dashboard CSV readers, no remote connector implied. */
export function rollupCsv(report: RollupReport): string {
  const rows: string[][] = [["schema", "snapshot_at", "scope", "dimension", "label", "count", "repositories", "sources"]];
  const quote = (value: string) => `"${(/^\s*[=+@-]/.test(value) ? "'" : "") + value.replace(/"/g, '""')}"`;
  const points = [{ at: report.generatedAt, repositories: [...new Set(report.snapshots.flatMap(item => item.repositories))].sort(), sources: [...new Set(report.observations.flatMap(item => item.sources))].sort(), summary: report, scope: "current" }, ...report.snapshotTrend.map(point => ({ ...point, scope: "snapshot" }))];
  for (const point of points) {
    const prefix = [REPORT_SCHEMA, point.at, point.scope]; const suffix = [JSON.stringify(point.repositories), JSON.stringify(point.sources)];
    rows.push([...prefix, "headline", "open", String(point.summary.open), ...suffix]);
    for (const dimension of ["bySeverity", "byCategory", "byAge", "byOwner", "byRepository", "byTeam", "byTier"] as const) {
      for (const item of point.summary[dimension]) rows.push([...prefix, dimension, item.name, String(item.count), ...suffix]);
    }
    for (const [label, count] of Object.entries(point.summary.excluded)) rows.push([...prefix, "excluded", label, String(count), ...suffix]);
  }
  if (report.trend) {
    const suffix = [JSON.stringify(report.observations.map(item => item.repository)), JSON.stringify([`since ${report.trend.since}`])];
    for (const label of ["opened", "fixed", "net"] as const) rows.push([REPORT_SCHEMA, report.generatedAt, "comparison", "trend", label, String(report.trend[label]), ...suffix]);
    for (const dimension of ["bySeverity", "byRepository"] as const) for (const item of report.trend[dimension]) {
      for (const label of ["opened", "fixed", "net"] as const) rows.push([REPORT_SCHEMA, report.generatedAt, "comparison", `trend.${dimension}`, `${item.name}:${label}`, String(item[label]), ...suffix]);
    }
  }
  return `${rows.map(row => row.map(quote).join(",")).join("\n")}\n`;
}
