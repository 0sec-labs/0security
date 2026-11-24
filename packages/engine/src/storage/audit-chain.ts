/**
 * Hash chain for the audit log. Every row stores the hash of the row before it and a hash of its own content, so
 * changing, removing or reordering a row breaks the chain from that point on. Rotation records a checkpoint (the
 * hash of the last dropped row) so the retained rows still verify.
 *
 * This proves the log is consistent, not that it is honest: someone who can rewrite the whole database file can
 * rewrite the chain too. Keep a copy somewhere they cannot reach (a SIEM, see audit-sink.ts) to close that gap.
 * Verification is free and works offline on any copy of the database.
 */
import { createHash } from "node:crypto";

/** The `prev_hash` of the very first chained row. */
export const AUDIT_GENESIS_HASH = "0".repeat(64);

export interface AuditChainRow {
  id: number;
  ts: string;
  actor: string;
  action: string;
  subject: string;
  outcome: string;
  detailJson: string;
  prevHash: string | null;
  hash: string | null;
}

export interface AuditCheckpoint {
  id: number;
  /** Highest row id that rotation removed. */
  throughId: number;
  /** The `hash` of that row. */
  throughHash: string;
  /** Rows removed by this rotation. */
  dropped: number;
  ts: string;
  prevCheckpointHash: string;
  hash: string;
}

export const auditRowHash = (prevHash: string, row: Pick<AuditChainRow, "id" | "ts" | "actor" | "action" | "subject" | "outcome" | "detailJson">): string =>
  createHash("sha256").update(`0.audit.chain.v1\n${prevHash}\n${JSON.stringify([row.id, row.ts, row.actor, row.action, row.subject, row.outcome, row.detailJson])}`).digest("hex");

export const auditCheckpointHash = (c: Pick<AuditCheckpoint, "prevCheckpointHash" | "throughId" | "throughHash" | "dropped" | "ts">): string =>
  createHash("sha256").update(`0.audit.checkpoint.v1\n${c.prevCheckpointHash}\n${JSON.stringify([c.throughId, c.throughHash, c.dropped, c.ts])}`).digest("hex");

export interface AuditChainBreak {
  /** Row id where the chain stops matching, or null when the break is not at one row. */
  id: number | null;
  reason: string;
}

export interface AuditChainReport {
  ok: boolean;
  /** Rows checked. */
  rows: number;
  /** Older rows written before the chain existed. They are counted, not verified. */
  unchainedRows: number;
  checkpoints: number;
  /** Rows removed by rotation, from the checkpoints. */
  rotatedRows: number;
  firstId: number | null;
  lastId: number | null;
  /** Hash of the newest row. Keep a copy elsewhere to detect a rewritten log. */
  headHash: string | null;
  firstBreak: AuditChainBreak | null;
}

export interface AuditChainInput {
  rows: readonly AuditChainRow[];
  checkpoints: readonly AuditCheckpoint[];
  /** Highest id the database ever handed out (SQLite sequence), or null when unknown. */
  highestIdEver: number | null;
}

/** Pure check over rows ordered by id. Reports the first break only. */
export function checkAuditChain(input: AuditChainInput): AuditChainReport {
  const { rows, checkpoints } = input;
  const report: AuditChainReport = {
    ok: true, rows: rows.length, unchainedRows: 0, checkpoints: checkpoints.length,
    rotatedRows: checkpoints.reduce((n, c) => n + c.dropped, 0),
    firstId: rows[0]?.id ?? null, lastId: rows.at(-1)?.id ?? null, headHash: null, firstBreak: null,
  };
  const fail = (id: number | null, reason: string): AuditChainReport => ({ ...report, ok: false, firstBreak: { id, reason } });

  let cpHash = AUDIT_GENESIS_HASH;
  let lastThrough = 0;
  for (const cp of checkpoints) {
    if (cp.prevCheckpointHash !== cpHash || cp.hash !== auditCheckpointHash(cp)) return fail(null, `rotation checkpoint ${cp.id} does not match the one before it`);
    if (cp.throughId <= lastThrough) return fail(null, `rotation checkpoint ${cp.id} goes backwards`);
    cpHash = cp.hash; lastThrough = cp.throughId;
  }
  const checkpoint = checkpoints.at(-1);

  let i = 0;
  while (i < rows.length && rows[i]!.hash === null && rows[i]!.prevHash === null) i += 1;
  report.unchainedRows = i;
  if (i > 0 && checkpoint) return fail(rows[0]!.id, "unchained rows remain after a rotation checkpoint");
  const chained = rows.slice(i);
  const newestKnown = rows.at(-1)?.id ?? checkpoint?.throughId ?? 0;
  if (!chained.length) {
    if (input.highestIdEver !== null && input.highestIdEver > newestKnown) return fail(null, `rows after id ${newestKnown} were removed`);
    return report;
  }

  let prev: AuditChainRow | undefined;
  for (const row of chained) {
    if (row.hash === null || row.prevHash === null) return fail(row.id, "row has no hash although earlier rows do");
    let expectedPrev: string;
    if (!prev) {
      if (checkpoint) {
        if (row.id !== checkpoint.throughId + 1) return fail(row.id, `rows between the rotation checkpoint (id ${checkpoint.throughId}) and id ${row.id} are missing`);
        expectedPrev = checkpoint.throughHash;
      } else expectedPrev = AUDIT_GENESIS_HASH;
    } else {
      if (row.id !== prev.id + 1) return fail(row.id, `rows between id ${prev.id} and id ${row.id} are missing`);
      expectedPrev = prev.hash!;
    }
    if (row.prevHash !== expectedPrev) return fail(row.id, "row does not link to the row before it");
    if (row.hash !== auditRowHash(row.prevHash, row)) return fail(row.id, "row content does not match its hash");
    prev = row;
  }
  report.headHash = prev!.hash;
  if (input.highestIdEver !== null && input.highestIdEver > prev!.id) return fail(null, `rows after id ${prev!.id} were removed`);
  return report;
}
