/**
 * Executed proof of concept: data model, wording and claim rules (pure).
 *
 * After a high or critical finding is saved, the harness tries to build a PoC
 * from the finding's own steps and run it in the sandbox. Three outcomes only:
 *
 *  - `executed-proven`: the PoC ran in a container with the network off and its
 *    expected output appeared. Needs a complete container run record.
 *  - `executed-failed`: the PoC ran in a container and its expectation did not hold.
 *    This never means the finding is false; it means this PoC did not work here.
 *  - `static-only`: nothing was proven by execution (no runnable steps, no
 *    sandbox, budget spent, or the run could not finish). The finding stands on
 *    its static evidence alone and must never be presented as proven.
 *
 * Only the harness writes this record. The parser refuses an `executed-proven`
 * record that lacks container isolation, a pinned image digest and a passing run.
 */

export const EXECUTED_POC_OUTCOMES = ["executed-proven", "executed-failed", "static-only"] as const;
export type ExecutedPocOutcome = typeof EXECUTED_POC_OUTCOMES[number];

/** Identifies a record as written by the executed-PoC harness. */
export const EXECUTED_POC_HARNESS = "0security-executed-poc/1";

/** The verifier run behind an executed outcome: the same fields the verifier records. */
export interface ExecutedPocRun {
  status: "pass" | "fail" | "not-run" | "error";
  reason: string;
  command: string;
  isolation: "container" | "host";
  /** `sha256:` and 64 hex digits of the pinned image. */
  imageDigest?: string;
  durationMs: number;
  /** Last 2 KB of output, secrets redacted. */
  logTail: string;
  exitCode?: number | null;
}

export interface ExecutedPoc {
  schemaVersion: 1;
  harness: typeof EXECUTED_POC_HARNESS;
  outcome: ExecutedPocOutcome;
  /** Short machine-readable cause, for example expectation-met, expectation-not-met, no-sandbox-image, budget-exhausted. */
  reason: string;
  /** Ids of the PoC steps that were run. Empty for static-only. */
  stepIds: string[];
  /** Present for executed outcomes and for runs that could not finish. */
  run?: ExecutedPocRun;
  startedAt: string;
  finishedAt: string;
}

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const LOG_LIMIT = 2048;
const RUN_STATUSES = ["pass", "fail", "not-run", "error"];

function isoMs(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : t;
}

function parseRun(value: unknown): ExecutedPocRun | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const r = value as Record<string, unknown>;
  if (!RUN_STATUSES.includes(String(r.status)) || typeof r.reason !== "string" || typeof r.command !== "string") return undefined;
  if (r.isolation !== "container" && r.isolation !== "host") return undefined;
  if (typeof r.durationMs !== "number" || typeof r.logTail !== "string") return undefined;
  return {
    status: r.status as ExecutedPocRun["status"], reason: r.reason, command: r.command.slice(0, 4096), isolation: r.isolation, durationMs: r.durationMs,
    logTail: r.logTail.length > LOG_LIMIT ? r.logTail.slice(r.logTail.length - LOG_LIMIT) : r.logTail,
    ...(typeof r.imageDigest === "string" && SHA256_DIGEST.test(r.imageDigest) ? { imageDigest: r.imageDigest } : {}),
    ...(typeof r.exitCode === "number" || r.exitCode === null ? { exitCode: r.exitCode as number | null } : {}),
  };
}

/**
 * The only way to turn stored or untrusted data into a record. An executed
 * outcome needs a run record that agrees with it; `executed-proven` also needs
 * container isolation and a pinned image digest. Anything less is absent,
 * never downgraded or guessed.
 */
export function parseExecutedPoc(value: unknown): ExecutedPoc | undefined {
  let v = value;
  if (typeof v === "string") {
    if (!v) return undefined;
    try { v = JSON.parse(v); } catch { return undefined; }
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
  const r = v as Record<string, unknown>;
  if (r.schemaVersion !== 1 || r.harness !== EXECUTED_POC_HARNESS) return undefined;
  if (!(EXECUTED_POC_OUTCOMES as readonly string[]).includes(String(r.outcome))) return undefined;
  if (typeof r.reason !== "string") return undefined;
  const start = isoMs(r.startedAt);
  const end = isoMs(r.finishedAt);
  if (start === undefined || end === undefined || end < start) return undefined;
  const outcome = r.outcome as ExecutedPocOutcome;
  const run = parseRun(r.run);
  if (outcome === "executed-proven") {
    if (!run || run.status !== "pass" || run.isolation !== "container" || !run.imageDigest) return undefined;
  }
  if (outcome === "executed-failed" && (!run || run.status !== "fail" || run.isolation !== "container")) return undefined;
  if (outcome === "static-only" && run && run.status === "pass") return undefined;
  const stepIds = Array.isArray(r.stepIds) ? r.stepIds.filter((s): s is string => typeof s === "string").slice(0, 50) : [];
  return {
    schemaVersion: 1, harness: EXECUTED_POC_HARNESS, outcome, reason: r.reason, stepIds,
    ...(run ? { run } : {}), startedAt: r.startedAt as string, finishedAt: r.finishedAt as string,
  };
}

/** True only for a complete harness record of a passing container run. */
export function isExecutedProven(value: unknown): boolean {
  return parseExecutedPoc(value)?.outcome === "executed-proven";
}

/** Findings of these severities get a PoC attempt. */
export function isPocEligibleSeverity(severity: string | undefined): boolean {
  return severity === "high" || severity === "critical";
}

const short = (hex: string, n = 12) => hex.replace(/^sha256:/, "").slice(0, n);
const why = (reason: string) => reason.replace(/-/g, " ");

/**
 * What to show for a finding: the stored record, or for a high or critical
 * finding with none, a derived static-only record that says no PoC was
 * attempted. Lower severities show nothing. Never derives a proven outcome.
 */
export function executedPocFor(finding: { severity?: string }, stored: ExecutedPoc | undefined): ExecutedPoc | undefined {
  if (stored) return stored;
  if (!isPocEligibleSeverity(finding.severity)) return undefined;
  return { schemaVersion: 1, harness: EXECUTED_POC_HARNESS, outcome: "static-only", reason: "not-attempted", stepIds: [], startedAt: "", finishedAt: "" };
}

/** Short label for a list row. */
export function executedPocLabel(record: ExecutedPoc | undefined): string | undefined {
  if (!record) return undefined;
  switch (record.outcome) {
    case "executed-proven": return "executed-proven (PoC ran in the sandbox)";
    case "executed-failed": return "executed-failed (PoC ran and did not hold; not proof of safety)";
    default: return "static-only (not proven by execution)";
  }
}

/** The one honest line for a record. Only a complete container run earns "proven". */
export function executedPocLine(record: ExecutedPoc | undefined): string {
  if (!record) return "No PoC execution was recorded";
  const image = record.run?.imageDigest ? ` (image ${short(record.run.imageDigest)})` : "";
  switch (record.outcome) {
    case "executed-proven": return `Executed, proven: the PoC ran in a container with the network off and its expected output appeared${image}. This is an observation of the app as run`;
    case "executed-failed": return `Executed, failed: the PoC ran in a container and its expected output did not appear${image}. This does not mean the issue is absent`;
    default: return `Static only: not proven by execution (${why(record.reason)}). The finding rests on static evidence`;
  }
}
