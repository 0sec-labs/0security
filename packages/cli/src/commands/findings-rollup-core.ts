/**
 * The rollup export format and the counting rules behind `0 findings rollup`.
 *
 * An export is a plain JSON file with one row per finding and no evidence. Several of them, or several findings
 * databases, merge into counts by severity, category, age, owner and repository. Everything here is pure; the
 * command reads and writes the files.
 */
import { z } from "zod";

export const ROLLUP_SCHEMA = "0.findings-rollup.v1";
export const MAX_ROLLUP_ROWS = 200_000;
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const AGE_BUCKETS = ["under 7 days", "7 to 30 days", "30 to 90 days", "over 90 days"] as const;
/** What is left out of the open count, and why. */
export const EXCLUSIONS = ["fixed", "false-positive", "accepted", "suppressed"] as const;
export type Exclusion = (typeof EXCLUSIONS)[number];

const text = (max: number) => z.string().max(max);
const row = z.object({
  repository: text(200).min(1),
  /** Stable across runs of the same flaw. Falls back to the finding id. */
  fingerprint: text(200).min(1),
  title: text(300),
  severity: text(20),
  category: text(100),
  /** Finding status: discovered, verified, confirmed, scored, reported, fixed, false-positive. */
  status: text(40),
  /** Triage state: new, accepted or suppressed. A lapsed acceptance is written as new. */
  triage: text(20),
  owner: text(100).nullable(),
  /** ISO time the finding was first seen. */
  firstSeen: z.iso.datetime({ offset: true }),
  /** ISO time it was last seen. */
  lastSeen: z.iso.datetime({ offset: true }),
});
export const rollupExportSchema = z.object({
  schema: z.literal(ROLLUP_SCHEMA),
  exportedAt: z.iso.datetime({ offset: true }),
  findings: z.array(row).max(MAX_ROLLUP_ROWS),
});
export type RollupRow = z.infer<typeof row>;
export type RollupExport = z.infer<typeof rollupExportSchema>;

export function buildExport(findings: RollupRow[], now: Date): RollupExport {
  return { schema: ROLLUP_SCHEMA, exportedAt: now.toISOString(), findings };
}

/** Parses an export file. Throws a plain message that names the first problem. */
export function parseExport(source: string, label: string): RollupExport {
  let value: unknown;
  try { value = JSON.parse(source); } catch { throw new Error(`${label} is not JSON.`); }
  if (value && typeof value === "object" && (value as { schema?: unknown }).schema !== ROLLUP_SCHEMA) throw new Error(`${label} is not a ${ROLLUP_SCHEMA} export.`);
  const parsed = rollupExportSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`${label} is not a valid ${ROLLUP_SCHEMA} export: ${issue?.path.join(".") || "document"} ${issue?.message ?? "is invalid"}.`);
  }
  return parsed.data;
}

const rank = (severity: string): number => { const at = (SEVERITIES as readonly string[]).indexOf(severity); return at < 0 ? SEVERITIES.length : at; };
const earlier = (a: string, b: string): string => (Date.parse(a) <= Date.parse(b) ? a : b);
const later = (a: string, b: string): string => (Date.parse(a) >= Date.parse(b) ? a : b);

/**
 * Counts one flaw once per repository: rows with the same repository and fingerprint merge, even across files.
 * The same fingerprint in two repositories stays two findings, because it is two pieces of code to fix.
 * The newest row decides the state; the oldest first-seen time decides the age.
 */
export function mergeRows(rows: readonly RollupRow[]): RollupRow[] {
  const merged = new Map<string, RollupRow>();
  for (const next of rows) {
    const key = `${next.repository}\u0000${next.fingerprint}`;
    const have = merged.get(key);
    if (!have) { merged.set(key, { ...next }); continue; }
    const newest = Date.parse(next.lastSeen) >= Date.parse(have.lastSeen) ? next : have;
    merged.set(key, { ...newest, owner: newest.owner ?? have.owner ?? next.owner, firstSeen: earlier(have.firstSeen, next.firstSeen), lastSeen: later(have.lastSeen, next.lastSeen) });
  }
  return [...merged.values()];
}

/** Why a finding is not in the open count, or null when it is open. */
export function exclusionOf(row: Pick<RollupRow, "status" | "triage">): Exclusion | null {
  if (row.status === "fixed") return "fixed";
  if (row.status === "false-positive") return "false-positive";
  if (row.triage === "accepted") return "accepted";
  if (row.triage === "suppressed") return "suppressed";
  return null;
}

export function ageBucket(firstSeen: string, now: Date): (typeof AGE_BUCKETS)[number] {
  const days = Math.max(0, (now.getTime() - Date.parse(firstSeen)) / 86_400_000);
  return days < 7 ? AGE_BUCKETS[0] : days < 30 ? AGE_BUCKETS[1] : days < 90 ? AGE_BUCKETS[2] : AGE_BUCKETS[3];
}

export interface Count { name: string; count: number }
export interface RollupSummary {
  generatedAt: string;
  repositories: number;
  /** Findings after merging, open or not. */
  total: number;
  /** The headline number: findings that are still open. */
  open: number;
  excluded: Record<Exclusion, number>;
  /** Open findings by severity, most severe first. Every known severity appears, even at zero. */
  bySeverity: Count[];
  byCategory: Count[];
  /** Open findings by time since first seen. Every bucket appears, even at zero. */
  byAge: Count[];
  /** Open findings by owner; findings with no owner count as unassigned. */
  byOwner: Count[];
  byRepository: Count[];
}

const tally = (names: string[]): Count[] => {
  const counts = new Map<string, number>();
  for (const name of names) counts.set(name, (counts.get(name) ?? 0) + 1);
  return [...counts].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
};

/** Fills a missing owner from an operator-supplied map of repository to owner. A finding's own owner wins. */
export function applyOwners(rows: readonly RollupRow[], owners: Readonly<Record<string, string>>): RollupRow[] {
  return rows.map(r => r.owner ? r : { ...r, owner: Object.hasOwn(owners, r.repository) ? owners[r.repository]! : null });
}

export function summarise(rows: readonly RollupRow[], now: Date): RollupSummary {
  const merged = mergeRows(rows);
  const excluded: Record<Exclusion, number> = { fixed: 0, "false-positive": 0, accepted: 0, suppressed: 0 };
  const open: RollupRow[] = [];
  for (const r of merged) { const why = exclusionOf(r); if (why) excluded[why] += 1; else open.push(r); }
  const severities = tally(open.map(r => r.severity));
  const bySeverity = [
    ...SEVERITIES.map(name => ({ name: name as string, count: severities.find(s => s.name === name)?.count ?? 0 })),
    ...severities.filter(s => !(SEVERITIES as readonly string[]).includes(s.name)).sort((a, b) => rank(a.name) - rank(b.name)),
  ];
  const ages = tally(open.map(r => ageBucket(r.firstSeen, now)));
  return {
    generatedAt: now.toISOString(),
    repositories: new Set(merged.map(r => r.repository)).size,
    total: merged.length,
    open: open.length,
    excluded,
    bySeverity,
    byCategory: tally(open.map(r => r.category || "uncategorised")),
    byAge: AGE_BUCKETS.map(name => ({ name, count: ages.find(a => a.name === name)?.count ?? 0 })),
    byOwner: tally(open.map(r => r.owner ?? "unassigned")),
    byRepository: tally(open.map(r => r.repository)),
  };
}

/** Strips control characters so a crafted name cannot move the cursor or fake a line. */
const plain = (value: string): string => value.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ");

const section = (title: string, counts: Count[]): string[] => {
  const width = Math.max(0, ...counts.map(c => plain(c.name).length));
  return ["", title, ...(counts.length ? counts.map(c => `  ${plain(c.name).padEnd(width)}  ${c.count}`) : ["  none"])];
};

export function renderText(summary: RollupSummary): string {
  const ex = summary.excluded;
  return [
    `${summary.open} open findings across ${summary.repositories} ${summary.repositories === 1 ? "repository" : "repositories"}`,
    `Left out of the open count: ${ex.fixed} fixed, ${ex["false-positive"]} false positive, ${ex.accepted} accepted, ${ex.suppressed} suppressed.`,
    ...section("By severity", summary.bySeverity), ...section("By category", summary.byCategory), ...section("By age", summary.byAge),
    ...section("By owner", summary.byOwner), ...section("By repository", summary.byRepository),
  ].join("\n");
}

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** A single self-contained page: no scripts, no external requests. */
export function renderHtml(summary: RollupSummary): string {
  const table = (title: string, counts: Count[]) => `<h2>${escapeHtml(title)}</h2><table>${counts.length ? counts.map(c => `<tr><td>${escapeHtml(plain(c.name))}</td><td class="n">${c.count}</td></tr>`).join("") : "<tr><td>none</td><td class=\"n\">0</td></tr>"}</table>`;
  const ex = summary.excluded;
  const repos = `${summary.repositories} ${summary.repositories === 1 ? "repository" : "repositories"}`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Findings rollup</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}h1{font-size:1.6rem}h2{font-size:1.1rem;margin-top:1.6rem}table{border-collapse:collapse;width:100%}td{padding:.25rem .5rem;border-bottom:1px solid #ddd}.n{text-align:right;font-variant-numeric:tabular-nums}.big{font-size:2.4rem;font-weight:600}</style></head><body><h1>Findings rollup</h1><p class="big">${summary.open}</p><p>open findings across ${repos}. Left out: ${ex.fixed} fixed, ${ex["false-positive"]} false positive, ${ex.accepted} accepted, ${ex.suppressed} suppressed.</p>${table("By severity", summary.bySeverity)}${table("By category", summary.byCategory)}${table("By age", summary.byAge)}${table("By owner", summary.byOwner)}${table("By repository", summary.byRepository)}<p>Generated ${escapeHtml(summary.generatedAt)}.</p></body></html>\n`;
}
