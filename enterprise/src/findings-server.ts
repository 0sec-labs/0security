// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Rules of the shared findings server that need no database: what an upload may contain, how a finding
// is identified across uploads, when a suppression needs a reason, and how the org rollup is counted.
// The routes that call these live in packages/cli and check `hasFeature("findings-server")` first.
import { createHash } from "node:crypto";

export const INGEST_LIMITS = {
  /** Largest request body, in bytes. Same limit as `findings import`. */
  maxBytes: 20 * 1024 * 1024,
  /** Most findings one upload may carry. */
  maxFindings: 5000,
} as const;

/** The key scope that allows sending findings to the server. */
export const WRITE_FINDINGS_SCOPE = "write:findings";

/** Shortest suppression reason the server accepts. */
export const MIN_SUPPRESSION_REASON = 8;

export class IngestError extends Error {
  constructor(message: string, readonly statusCode = 400) {
    super(message);
    this.name = "IngestError";
  }
}

export interface IngestLabels {
  repo: string;
  source: string;
  ref?: string;
  commit?: string;
}

const REPO = /^[A-Za-z0-9._-]{1,100}(?:\/[A-Za-z0-9._-]{1,100}){1,2}$/;
const SOURCE = /^[A-Za-z0-9._:/@-]{1,80}$/;
const REF = /^[A-Za-z0-9._/@+-]{1,200}$/;
const COMMIT = /^[0-9a-f]{7,64}$/;

/** Validate the labels of an upload (`repo`, `source`, `ref`, `commit` query parameters). `defaultSource` is used when `source` is absent. */
export function parseIngestLabels(params: { get(name: string): string | null }, defaultSource: string): IngestLabels {
  const repo = (params.get("repo") ?? "").trim();
  if (!REPO.test(repo)) throw new IngestError("Name the repository with ?repo=owner/name (letters, digits, dots, dashes and underscores).");
  const source = (params.get("source") ?? "").trim() || defaultSource;
  if (!SOURCE.test(source)) throw new IngestError("The source label may hold letters, digits and . _ : / @ - (at most 80).");
  const ref = (params.get("ref") ?? "").trim();
  if (ref && !REF.test(ref)) throw new IngestError("The ref is not valid.");
  const commit = (params.get("commit") ?? "").trim().toLowerCase();
  if (commit && !COMMIT.test(commit)) throw new IngestError("The commit must be a hexadecimal sha of 7 to 64 characters.");
  return { repo, source, ...(ref ? { ref } : {}), ...(commit ? { commit } : {}) };
}

export type IngestFormat = "sarif" | "findings-json";

export interface ParsedIngestBody {
  format: IngestFormat;
  document: Record<string, unknown>;
  /** Number of results or findings the document carries. */
  count: number;
}

/** Check the size, parse the JSON and tell SARIF from the findings JSON the CLI writes. */
export function parseIngestBody(text: string): ParsedIngestBody {
  if (Buffer.byteLength(text, "utf8") > INGEST_LIMITS.maxBytes) throw new IngestError(`The upload is larger than ${INGEST_LIMITS.maxBytes / (1024 * 1024)} MB.`, 413);
  let document: unknown;
  try { document = JSON.parse(text); } catch { throw new IngestError("The body is not valid JSON."); }
  if (!document || typeof document !== "object" || Array.isArray(document)) throw new IngestError("The body must be a JSON object: a SARIF 2.1.0 log or findings JSON.");
  const root = document as Record<string, unknown>;
  let format: IngestFormat;
  let count = 0;
  if (Array.isArray(root.runs)) {
    format = "sarif";
    for (const run of root.runs as unknown[]) {
      const results = run && typeof run === "object" ? (run as { results?: unknown }).results : undefined;
      if (Array.isArray(results)) count += results.length;
    }
  } else if (Array.isArray(root.findings)) {
    format = "findings-json";
    count = root.findings.length;
  } else {
    throw new IngestError("Send a SARIF 2.1.0 log (runs) or findings JSON (findings).");
  }
  if (count > INGEST_LIMITS.maxFindings) throw new IngestError(`The upload has ${count} findings; the limit is ${INGEST_LIMITS.maxFindings}. Split it.`, 413);
  return { format, document: root, count };
}

/** Identity of a finding across uploads: the same repository and the same stable key give the same fingerprint. */
export function ingestFingerprint(repo: string, key: string): string {
  return `fx:${createHash("sha256").update(`${repo}\n${key}`).digest("hex").slice(0, 32)}`;
}

/** Identity of one upload, so that sending the same file twice stores it once. */
export function ingestDigest(repo: string, source: string, body: string): string {
  return createHash("sha256").update(`${repo}\n${source}\n`).update(body).digest("hex");
}

/** The error to show when a suppression has no usable reason, or null when it is fine. */
export function suppressionReasonError(triageStatus: string, note: unknown): string | null {
  if (triageStatus !== "suppressed") return null;
  const reason = typeof note === "string" ? note.trim() : "";
  if (reason.length >= MIN_SUPPRESSION_REASON) return null;
  return `A reason of at least ${MIN_SUPPRESSION_REASON} characters is required to suppress a finding.`;
}

export type HistoryAction = "open" | "reopen" | "accept" | "suppress" | "fixed" | "seen";

/** The history action for a change of triage state. */
export function triageHistoryAction(newState: string): HistoryAction {
  return newState === "accepted" ? "accept" : newState === "suppressed" ? "suppress" : "reopen";
}

export interface OrgRow {
  fingerprint: string;
  title: string;
  severity: string;
  triageStatus: string;
  triageNote: string | null;
  triageExpiresAt: string | null;
  repo: string;
  lastSeen: number;
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const STATUSES = ["new", "accepted", "suppressed"] as const;

export interface OrgSummary {
  total: number;
  open: number;
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  byRepo: Array<{ repo: string; total: number; open: number; bySeverity: Record<string, number> }>;
  /** Suppressed findings with their reason, newest first. */
  suppressions: Array<{ fingerprint: string; title: string; repo: string; severity: string; reason: string | null; expiresAt: string | null }>;
}

const zero = (keys: readonly string[]): Record<string, number> => Object.fromEntries(keys.map((key) => [key, 0]));

/** Counts for the org dashboard. "Open" means not suppressed (accepted risk still counts as open). */
export function summarizeOrg(rows: readonly OrgRow[]): OrgSummary {
  const bySeverity = zero(SEVERITIES);
  const byStatus = zero(STATUSES);
  const repos = new Map<string, { repo: string; total: number; open: number; bySeverity: Record<string, number> }>();
  const suppressions: OrgSummary["suppressions"] = [];
  let open = 0;
  for (const row of rows) {
    bySeverity[row.severity] = (bySeverity[row.severity] ?? 0) + 1;
    byStatus[row.triageStatus] = (byStatus[row.triageStatus] ?? 0) + 1;
    const entry = repos.get(row.repo) ?? { repo: row.repo, total: 0, open: 0, bySeverity: zero(SEVERITIES) };
    entry.total++;
    entry.bySeverity[row.severity] = (entry.bySeverity[row.severity] ?? 0) + 1;
    if (row.triageStatus !== "suppressed") { entry.open++; open++; }
    repos.set(row.repo, entry);
    if (row.triageStatus === "suppressed") suppressions.push({ fingerprint: row.fingerprint, title: row.title, repo: row.repo, severity: row.severity, reason: row.triageNote, expiresAt: row.triageExpiresAt });
  }
  return {
    total: rows.length, open, bySeverity, byStatus,
    byRepo: [...repos.values()].sort((a, b) => b.open - a.open || a.repo.localeCompare(b.repo)),
    suppressions,
  };
}
