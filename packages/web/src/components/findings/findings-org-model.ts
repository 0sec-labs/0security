// Model of the Org tab (shared findings server): response types and the small pure helpers the view uses.
import { SEVERITY_LABELS, SEVERITY_ORDER, normalizeSeverity, type SeverityLevel } from "./findings-model";

export type OrgTriage = "new" | "accepted" | "suppressed";

export type OrgFinding = {
  fingerprint: string; id: string; title: string; severity: string; category: string;
  triageStatus: OrgTriage | string; triageNote: string | null; triageExpiresAt: string | null; triageApprover: string | null;
  repo: string; source: string | null; tool: string | null; firstSeen: number; lastSeen: number;
};
export type OrgRepoSummary = { repo: string; total: number; open: number; bySeverity: Record<string, number> };
export type OrgSummary = {
  total: number; open: number; bySeverity: Record<string, number>; byStatus: Record<string, number>;
  byRepo: OrgRepoSummary[];
  suppressions: Array<{ fingerprint: string; title: string; repo: string; severity: string; reason: string | null; expiresAt: string | null }>;
};
export type OrgOverview =
  | { available: false; canWrite: false; message: string }
  | { available: true; canWrite: boolean; repos: string[]; summary: OrgSummary; findings: OrgFinding[]; truncated: boolean };
export type OrgHistoryRow = { id: string; ts: string; actor: string; action: string; reason: string | null; expiresAt: string | null; prevState: string | null; newState: string | null; repo: string | null; source: string | null };

export const OVERVIEW_PATH = "/api/findings-server/overview";
export const overviewPath = (repo: string | null): string => repo ? `${OVERVIEW_PATH}?repo=${encodeURIComponent(repo)}` : OVERVIEW_PATH;
export const historyPath = (fingerprint: string): string => `/api/findings-server/history/${encodeURIComponent(fingerprint)}`;

export const triageLabel = (status: string): string => status === "accepted" ? "Accepted" : status === "suppressed" ? "Suppressed" : "Open";

/** Severities with their counts in display order, zero rows kept so the bar and the legend line up. */
export function severityShares(bySeverity: Record<string, number>): Array<{ severity: SeverityLevel; label: string; count: number; percent: number }> {
  const total = SEVERITY_ORDER.reduce((sum, level) => sum + (bySeverity[level] ?? 0), 0);
  return SEVERITY_ORDER.map(level => {
    const count = bySeverity[level] ?? 0;
    return { severity: level, label: SEVERITY_LABELS[level], count, percent: total === 0 ? 0 : Math.round((count / total) * 100) };
  });
}

const ACTION_VERB: Record<string, string> = { open: "First seen", reopen: "Reopened", accept: "Accepted", suppress: "Suppressed", fixed: "Marked fixed", seen: "Seen again" };

/** One line of the history: what happened and who did it. */
export function describeHistory(row: Pick<OrgHistoryRow, "action" | "actor" | "source">): string {
  const verb = ACTION_VERB[row.action] ?? row.action;
  if (row.action === "open") return row.source ? `${verb} from ${row.source}` : verb;
  return `${verb} by ${row.actor}`;
}

/** Worst severity first, then newest. */
export function sortOrgFindings(rows: readonly OrgFinding[]): OrgFinding[] {
  const rank = (row: OrgFinding) => SEVERITY_ORDER.indexOf(normalizeSeverity(row.severity));
  return [...rows].sort((a, b) => rank(a) - rank(b) || b.lastSeen - a.lastSeen || a.title.localeCompare(b.title));
}

/** "3 days ago" style age for a timestamp in ms. */
export function ageLabel(timestamp: number, now = Date.now()): string {
  const minutes = Math.max(0, Math.floor((now - timestamp) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

/** The repository name that a filter value can take, or null for "all repositories". */
export const repoFilter = (value: string | null | undefined, repos: readonly string[]): string | null => value && repos.includes(value) ? value : null;
