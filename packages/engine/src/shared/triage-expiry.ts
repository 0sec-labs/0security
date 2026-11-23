import type { FindingTriageStatus } from "./types.js";

export const MAX_TRIAGE_REASON_LENGTH = 500;
export const MAX_TRIAGE_APPROVER_LENGTH = 80;
const DAY_MS = 24 * 60 * 60 * 1000;

/** The part of a finding that decides whether an acceptance still holds. */
export interface TriageExpiryFields { triageStatus?: string | null; triageExpiresAt?: string | null }

/**
 * The triage status to act on at `now`. An accepted risk whose expiry has passed is open again ("new");
 * everything else is as stored. A missing or unreadable expiry never lapses.
 */
export function effectiveTriageStatus(finding: TriageExpiryFields, now: Date | number = Date.now()): FindingTriageStatus {
  const stored = finding.triageStatus === "accepted" || finding.triageStatus === "suppressed" ? finding.triageStatus : "new";
  if (stored !== "accepted" || !finding.triageExpiresAt) return stored;
  const expires = Date.parse(finding.triageExpiresAt);
  const at = typeof now === "number" ? now : now.getTime();
  return Number.isFinite(expires) && expires <= at ? "new" : stored;
}

/** True when an acceptance was recorded and its expiry has passed. */
export function acceptanceExpired(finding: TriageExpiryFields, now: Date | number = Date.now()): boolean {
  return finding.triageStatus === "accepted" && effectiveTriageStatus(finding, now) === "new";
}

/** True when an acceptance is still in force and lapses within `days` days of `now`. */
export function acceptanceExpiresWithin(finding: TriageExpiryFields, days: number, now: Date | number = Date.now()): boolean {
  if (effectiveTriageStatus(finding, now) !== "accepted" || !finding.triageExpiresAt) return false;
  const expires = Date.parse(finding.triageExpiresAt);
  const at = typeof now === "number" ? now : now.getTime();
  return Number.isFinite(expires) && expires - at <= days * DAY_MS;
}

/**
 * Parse `--expires`: a calendar date (`2026-12-31`, lapses at the end of that day UTC), a full ISO time, or a
 * number of days from now (`90d`). Returns an ISO string, or throws with a message fit for the operator.
 */
export function parseTriageExpiry(text: string, now: Date | number = Date.now()): string {
  const value = text.trim();
  const at = typeof now === "number" ? now : now.getTime();
  const days = /^(\d{1,4})d$/i.exec(value);
  let expires: number;
  if (days) {
    const n = Number(days[1]);
    if (n < 1 || n > 3650) throw new Error("--expires days must be between 1d and 3650d.");
    expires = at + n * DAY_MS;
  } else if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const start = Date.parse(`${value}T00:00:00.000Z`);
    if (!Number.isFinite(start) || new Date(start).toISOString().slice(0, 10) !== value) throw new Error(`--expires '${value}' is not a real date.`);
    expires = start + DAY_MS - 1;
  } else if (/^\d{4}-\d{2}-\d{2}T[\d:.]+(Z|[+-]\d{2}:?\d{2})$/.test(value) && Number.isFinite(Date.parse(value))) {
    expires = Date.parse(value);
  } else throw new Error(`--expires must be a date like 2026-12-31 or a number of days like 90d, not '${value.slice(0, 40)}'.`);
  if (expires <= at) throw new Error("--expires must be in the future.");
  return new Date(expires).toISOString();
}
