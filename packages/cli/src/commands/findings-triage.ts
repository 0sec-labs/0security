/**
 * Triage decisions for `0 findings accept|suppress|reopen` (and `findings update`): validation, the audit record and
 * the one-line label a list shows. An accepted risk needs a reason and an expiry; the approver is a free-text label
 * the operator types and is not authenticated.
 */
import { userInfo } from "node:os";
import { acceptanceExpired, effectiveTriageStatus, MAX_TRIAGE_APPROVER_LENGTH, MAX_TRIAGE_REASON_LENGTH, parseTriageExpiry } from "@0/engine/shared";
import type { FindingTriageStatus } from "@0/engine/shared";
import { recordAudit } from "@0/engine/storage";
import { shortFindingId, shortFingerprint } from "../finding-id.js";
import { UsageError } from "./output.js";

export interface TriageDetails { expiresAt?: string; approver?: string }
export interface TriageRequest { status: FindingTriageStatus; note: string | undefined; details: TriageDetails }
export interface TriageFlags { reason?: string; note?: string; expires?: string; approver?: string }

/** One line, no control characters. */
const oneLine = (text: string): string => text.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();

export function buildTriageRequest(status: FindingTriageStatus, flags: TriageFlags, now: Date | number = Date.now()): TriageRequest {
  const reasonText = flags.reason ?? flags.note;
  const note = reasonText === undefined ? undefined : oneLine(reasonText);
  if (note !== undefined && note.length > MAX_TRIAGE_REASON_LENGTH) throw new UsageError(`The reason is ${note.length} characters; keep it under ${MAX_TRIAGE_REASON_LENGTH}.`);
  const approver = flags.approver === undefined ? undefined : oneLine(flags.approver);
  if (approver !== undefined && (!approver || approver.length > MAX_TRIAGE_APPROVER_LENGTH)) throw new UsageError(`--approver must be 1 to ${MAX_TRIAGE_APPROVER_LENGTH} characters.`);
  if (status === "new") {
    if (flags.expires !== undefined || approver !== undefined) throw new UsageError("--expires and --approver apply to accepted findings, not to reopening.");
    return { status, note: note || undefined, details: {} };
  }
  if (status === "suppressed") {
    if (flags.expires !== undefined) throw new UsageError("--expires applies to accepted findings. A suppression has no expiry.");
    return { status, note: note || undefined, details: approver ? { approver } : {} };
  }
  if (!note) throw new UsageError("Accepting a risk needs a reason: add --reason <text>.");
  if (flags.expires === undefined) throw new UsageError("Accepting a risk needs an expiry: add --expires <date|90d>, for example --expires 2026-12-31 or --expires 90d.");
  let expiresAt: string;
  try { expiresAt = parseTriageExpiry(flags.expires, now); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  return { status, note, details: { expiresAt, ...(approver ? { approver } : {}) } };
}

type TriageRow = { triageStatus?: string | null; triageExpiresAt?: string | null; triageApprover?: string | null };

/** What a list shows for the triage column. */
export function triageLabel(row: TriageRow, now: Date | number = Date.now()): string {
  if (acceptanceExpired(row, now)) return `open (acceptance expired ${String(row.triageExpiresAt).slice(0, 10)})`;
  const status = effectiveTriageStatus(row, now);
  if (status === "accepted" && row.triageExpiresAt) return `accepted until ${row.triageExpiresAt.slice(0, 10)}`;
  return status;
}

/** One audit entry per triage change (ids are shortened: the audit log redacts long identifier-like strings), in the local audit log (`0 config get audit`). The actor is the operating-system user; the approver label is recorded alongside. */
export function auditTriage(input: { findingId: string; fingerprint: string; from: string; request: TriageRequest }): void {
  let actor = "cli";
  try { actor = userInfo().username || "cli"; } catch { /* no user entry */ }
  recordAudit({
    actor, action: `finding.triage.${input.request.status}`, subject: shortFindingId(input.findingId),
    detail: {
      fingerprint: shortFingerprint(input.fingerprint), old: input.from, new: input.request.status,
      ...(input.request.note ? { reason: input.request.note } : {}),
      ...(input.request.details.expiresAt ? { expires: input.request.details.expiresAt } : {}),
      ...(input.request.details.approver ? { name: input.request.details.approver } : {}),
    },
  });
}
