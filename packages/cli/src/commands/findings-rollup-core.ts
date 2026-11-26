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
  /** Added after the first release of the format. Older files do not have them; they still read. */
  team: text(100).nullable().optional(),
  tier: text(40).nullable().optional(),
});
export const rollupExportSchema = z.object({
  schema: z.literal(ROLLUP_SCHEMA),
  exportedAt: z.iso.datetime({ offset: true }),
  findings: z.array(row).max(MAX_ROLLUP_ROWS),
  /** Repository coverage, including repositories observed with zero findings. */
  repositories: z.array(text(200).min(1)).max(MAX_ROLLUP_ROWS).optional(),
});
export type RollupRow = z.infer<typeof row>;
/** A row while the command runs. The path comes from a SARIF input and is used for labels only; it is never exported. */
export type WorkRow = RollupRow & { path?: string };
export type RollupExport = z.infer<typeof rollupExportSchema>;

export function buildExport(findings: WorkRow[], now: Date, repositories?: string[]): RollupExport {
  return { schema: ROLLUP_SCHEMA, exportedAt: now.toISOString(), findings: findings.map(({ path: _path, ...rest }) => rest), ...(repositories ? { repositories } : {}) };
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
export function mergeRows<T extends RollupRow>(rows: readonly T[]): T[] {
  const merged = new Map<string, T>();
  for (const next of rows) {
    const key = `${next.repository}\u0000${next.fingerprint}`;
    const have = merged.get(key);
    if (!have) { merged.set(key, { ...next }); continue; }
    const newest = Date.parse(next.lastSeen) >= Date.parse(have.lastSeen) ? next : have;
    merged.set(key, { ...newest, owner: newest.owner ?? have.owner ?? next.owner, team: newest.team ?? have.team ?? next.team, tier: newest.tier ?? have.tier ?? next.tier, firstSeen: earlier(have.firstSeen, next.firstSeen), lastSeen: later(have.lastSeen, next.lastSeen) });
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
  /** Open findings by team and tier from the labels file. Unlabelled findings count as unlabelled. */
  byTeam: Count[];
  byTier: Count[];
  /** Present when an earlier export was given. */
  trend?: RollupTrend;
}

export interface TrendCount { name: string; opened: number; fixed: number; net: number }
export interface RollupTrend {
  /** When the earlier export was written. */
  since: string;
  opened: number;
  fixed: number;
  /** Opened minus fixed. Above zero means more open findings than before. */
  net: number;
  bySeverity: TrendCount[];
  /** Repositories with any change, largest change first. */
  byRepository: TrendCount[];
  /** Repositories in the earlier export and not in this rollup. Their findings are not counted as fixed. */
  missingRepositories: string[];
  /** Repositories in this rollup and not in the earlier export. Their open findings count as opened. */
  newRepositories: string[];
}

const tally = (names: string[]): Count[] => {
  const counts = new Map<string, number>();
  for (const name of names) counts.set(name, (counts.get(name) ?? 0) + 1);
  return [...counts].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
};

/** Fills a missing owner from an operator-supplied map of repository to owner. A finding's own owner wins. */
export function applyOwners<T extends RollupRow>(rows: readonly T[], owners: Readonly<Record<string, string>>): T[] {
  return rows.map(r => r.owner ? r : { ...r, owner: Object.hasOwn(owners, r.repository) ? owners[r.repository]! : null });
}

export interface LabelRule { pattern: string; path: boolean; team?: string; tier?: string }

/** A glob as a regular expression: `*` stays inside one path segment, `**` crosses them, `?` is one character. */
function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*" && glob[i + 1] === "*") { source += ".*"; i++; } else if (c === "*") source += "[^/]*"; else if (c === "?") source += "[^/]"; else source += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${source}$`);
}
const literalLength = (glob: string): number => glob.replace(/[*?]/g, "").length;
const hasWildcard = (glob: string): boolean => /[*?]/.test(glob);

/**
 * Labels from an operator-named file. A key is a repository name or glob, or `path:` and a glob for files inside a repository.
 * For each of team and tier the most specific matching rule wins: a path rule, then an exact repository name, then the repository
 * glob with the most literal characters. A tie goes to the rule that comes first in the file.
 */
export function applyLabels<T extends RollupRow & { path?: string }>(rows: readonly T[], rules: readonly LabelRule[]): T[] {
  if (!rules.length) return [...rows];
  const compiled = rules.map(rule => ({ rule, regex: globToRegExp(rule.pattern) }));
  const pick = (r: T, field: "team" | "tier"): string | undefined => {
    let best: { score: number; value: string } | undefined;
    for (const { rule, regex } of compiled) {
      const value = rule[field];
      if (value === undefined) continue;
      let score: number;
      if (rule.path) { if (!r.path || !regex.test(r.path)) continue; score = 2_000_000 + literalLength(rule.pattern); } else {
        if (!regex.test(r.repository)) continue;
        score = hasWildcard(rule.pattern) ? literalLength(rule.pattern) : 1_000_000;
      }
      if (!best || score > best.score) best = { score, value };
    }
    return best?.value;
  };
  return rows.map(r => ({ ...r, team: pick(r, "team") ?? r.team ?? null, tier: pick(r, "tier") ?? r.tier ?? null }));
}

const openKey = (r: RollupRow): string => `${r.repository}\u0000${r.fingerprint}`;
const trendCounts = (entries: Map<string, { opened: number; fixed: number }>): TrendCount[] =>
  [...entries].map(([name, c]) => ({ name, opened: c.opened, fixed: c.fixed, net: c.opened - c.fixed }));

/**
 * What changed between an earlier export and now. A finding that is open now and was not open then is opened. A finding that was
 * open then and is not open now is fixed, whether it was fixed, marked false positive, accepted, suppressed or is gone from the file.
 * A repository that is missing from one side is listed instead of counted, so a missing file does not read as a clean-up.
 */
export function computeTrend(earlier: RollupExport, current: readonly RollupRow[], currentRepositories?: readonly string[]): RollupTrend {
  const before = mergeRows(earlier.findings);
  const after = mergeRows(current);
  const beforeRepos = new Set([...(earlier.repositories ?? []), ...before.map(r => r.repository)]);
  const afterRepos = new Set([...(currentRepositories ?? []), ...after.map(r => r.repository)]);
  const openBefore = new Map(before.filter(r => !exclusionOf(r)).map(r => [openKey(r), r] as const));
  const openAfter = new Map(after.filter(r => !exclusionOf(r)).map(r => [openKey(r), r] as const));
  const severities = new Map<string, { opened: number; fixed: number }>(SEVERITIES.map(s => [s as string, { opened: 0, fixed: 0 }]));
  const repositories = new Map<string, { opened: number; fixed: number }>();
  const bump = (map: Map<string, { opened: number; fixed: number }>, name: string, kind: "opened" | "fixed") => {
    const entry = map.get(name) ?? { opened: 0, fixed: 0 };
    entry[kind] += 1; map.set(name, entry);
  };
  let opened = 0; let fixed = 0;
  for (const [key, r] of openAfter) if (!openBefore.has(key)) { opened++; bump(severities, r.severity, "opened"); bump(repositories, r.repository, "opened"); }
  for (const [key, r] of openBefore) if (!openAfter.has(key) && afterRepos.has(r.repository)) { fixed++; bump(severities, r.severity, "fixed"); bump(repositories, r.repository, "fixed"); }
  const bySeverity = trendCounts(severities);
  const known = (name: string) => (SEVERITIES as readonly string[]).includes(name);
  return {
    since: earlier.exportedAt, opened, fixed, net: opened - fixed,
    bySeverity: [...bySeverity.filter(c => known(c.name)).sort((a, b) => rank(a.name) - rank(b.name)), ...bySeverity.filter(c => !known(c.name)).sort((a, b) => a.name.localeCompare(b.name))],
    byRepository: trendCounts(repositories).sort((a, b) => b.opened + b.fixed - (a.opened + a.fixed) || a.name.localeCompare(b.name)),
    missingRepositories: [...beforeRepos].filter(n => !afterRepos.has(n)).sort(),
    newRepositories: [...afterRepos].filter(n => !beforeRepos.has(n)).sort(),
  };
}

export function summarise(rows: readonly RollupRow[], now: Date, earlier?: RollupExport, repositories?: readonly string[]): RollupSummary {
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
    repositories: new Set([...(repositories ?? []), ...merged.map(r => r.repository)]).size,
    total: merged.length,
    open: open.length,
    excluded,
    bySeverity,
    byCategory: tally(open.map(r => r.category || "uncategorised")),
    byAge: AGE_BUCKETS.map(name => ({ name, count: ages.find(a => a.name === name)?.count ?? 0 })),
    byOwner: tally(open.map(r => r.owner ?? "unassigned")),
    byRepository: tally(open.map(r => r.repository)),
    byTeam: tally(open.map(r => r.team ?? "unlabelled")),
    byTier: tally(open.map(r => r.tier ?? "unlabelled")),
    ...(earlier ? { trend: computeTrend(earlier, rows, repositories) } : {}),
  };
}

/** Strips control characters so a crafted name cannot move the cursor or fake a line. */
const plain = (value: string): string => value.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ");

const section = (title: string, counts: Count[]): string[] => {
  const width = Math.max(0, ...counts.map(c => plain(c.name).length));
  return ["", title, ...(counts.length ? counts.map(c => `  ${plain(c.name).padEnd(width)}  ${c.count}`) : ["  none"])];
};

/** The team and tier breakdowns show only when some finding has a label. */
const labelled = (counts: Count[]): boolean => counts.some(c => c.name !== "unlabelled");
const signed = (n: number): string => (n > 0 ? `+${n}` : String(n));
const listNames = (names: string[]): string => `${names.slice(0, 10).map(plain).join(", ")}${names.length > 10 ? `, and ${names.length - 10} more` : ""}`;

function trendText(t: RollupTrend): string[] {
  const rows = (counts: TrendCount[]): string[] => {
    const width = Math.max(0, ...counts.map(c => plain(c.name).length));
    return counts.length ? counts.map(c => `  ${plain(c.name).padEnd(width)}  opened ${c.opened}  fixed ${c.fixed}  net ${signed(c.net)}`) : ["  none"];
  };
  return [
    "", `Trend since ${t.since}: ${t.opened} opened, ${t.fixed} fixed, net ${signed(t.net)}`,
    "", "Trend by severity", ...rows(t.bySeverity), "", "Trend by repository", ...rows(t.byRepository),
    ...(t.newRepositories.length ? ["", `Not in the earlier export, so all counted as opened: ${listNames(t.newRepositories)}`] : []),
    ...(t.missingRepositories.length ? ["", `Not in this rollup, so not counted as fixed: ${listNames(t.missingRepositories)}`] : []),
  ];
}

export function renderText(summary: RollupSummary): string {
  const ex = summary.excluded;
  return [
    `${summary.open} open findings across ${summary.repositories} ${summary.repositories === 1 ? "repository" : "repositories"}`,
    `Left out of the open count: ${ex.fixed} fixed, ${ex["false-positive"]} false positive, ${ex.accepted} accepted, ${ex.suppressed} suppressed.`,
    ...section("By severity", summary.bySeverity), ...section("By category", summary.byCategory), ...section("By age", summary.byAge),
    ...section("By owner", summary.byOwner), ...section("By repository", summary.byRepository),
    ...(labelled(summary.byTeam) ? section("By team", summary.byTeam) : []), ...(labelled(summary.byTier) ? section("By tier", summary.byTier) : []),
    ...(summary.trend ? trendText(summary.trend) : []),
  ].join("\n");
}

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** A single self-contained page: no scripts, no external requests. */
export function renderHtml(summary: RollupSummary): string {
  const table = (title: string, counts: Count[]) => `<h2>${escapeHtml(title)}</h2><table>${counts.length ? counts.map(c => `<tr><td>${escapeHtml(plain(c.name))}</td><td class="n">${c.count}</td></tr>`).join("") : "<tr><td>none</td><td class=\"n\">0</td></tr>"}</table>`;
  const trendTable = (title: string, counts: TrendCount[]) => `<h2>${escapeHtml(title)}</h2><table><tr><th></th><th class="n">Opened</th><th class="n">Fixed</th><th class="n">Net</th></tr>${counts.map(c => `<tr><td>${escapeHtml(plain(c.name))}</td><td class="n">${c.opened}</td><td class="n">${c.fixed}</td><td class="n">${signed(c.net)}</td></tr>`).join("")}</table>`;
  const t = summary.trend;
  const trend = t ? `<h2>Trend</h2><p>Since ${escapeHtml(t.since)}: ${t.opened} opened, ${t.fixed} fixed, net ${signed(t.net)}.</p>${trendTable("Trend by severity", t.bySeverity)}${trendTable("Trend by repository", t.byRepository)}${t.newRepositories.length ? `<p>Not in the earlier export, so all counted as opened: ${escapeHtml(listNames(t.newRepositories))}.</p>` : ""}${t.missingRepositories.length ? `<p>Not in this rollup, so not counted as fixed: ${escapeHtml(listNames(t.missingRepositories))}.</p>` : ""}` : "";
  const labels = `${labelled(summary.byTeam) ? table("By team", summary.byTeam) : ""}${labelled(summary.byTier) ? table("By tier", summary.byTier) : ""}`;
  const ex = summary.excluded;
  const repos = `${summary.repositories} ${summary.repositories === 1 ? "repository" : "repositories"}`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Findings rollup</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}h1{font-size:1.6rem}h2{font-size:1.1rem;margin-top:1.6rem}table{border-collapse:collapse;width:100%}td{padding:.25rem .5rem;border-bottom:1px solid #ddd}.n{text-align:right;font-variant-numeric:tabular-nums}.big{font-size:2.4rem;font-weight:600}</style></head><body><h1>Findings rollup</h1><p class="big">${summary.open}</p><p>open findings across ${repos}. Left out: ${ex.fixed} fixed, ${ex["false-positive"]} false positive, ${ex.accepted} accepted, ${ex.suppressed} suppressed.</p>${table("By severity", summary.bySeverity)}${table("By category", summary.byCategory)}${table("By age", summary.byAge)}${table("By owner", summary.byOwner)}${table("By repository", summary.byRepository)}${labels}${trend}<p>Generated ${escapeHtml(summary.generatedAt)}.</p></body></html>\n`;
}
