/**
 * The chain file: NDJSON audit rows with their hashes and a trailer. It is the format of an audit export with proof
 * and of the archive that retention writes before it removes old rows. Anyone can check it offline with
 * checkAuditChainFile, so an auditor needs no license and no access to the database.
 */
import { auditRowHash, type AuditChainBreak, type AuditChainRow } from "./audit-chain.js";

export const AUDIT_CHAIN_SCHEMA = "0.audit.chain.v1";

/** The last line of a chain file. It lets a reader notice a file that was cut short. */
export interface AuditChainTrailer {
  schema: typeof AUDIT_CHAIN_SCHEMA;
  kind: "proof";
  /** Chained rows in the file. */
  rows: number;
  /** Rows from before the chain existed. They are in the file as `legacy` lines and cannot be verified. */
  legacyRows: number;
  firstId: number | null;
  lastId: number | null;
  /** The `prevHash` of the first chained row: the file proves nothing about what came before it. */
  startsAfterHash: string | null;
  headHash: string | null;
  createdAt: string;
}

/** Text of a chain file: one line per row, then the trailer. Rows must be oldest first. */
export function formatAuditChainFile(rows: readonly AuditChainRow[], createdAt: string): string {
  const lines: string[] = [];
  const chained = rows.filter(row => row.hash !== null && row.prevHash !== null);
  for (const row of rows) {
    const base = { schema: AUDIT_CHAIN_SCHEMA, id: row.id, ts: row.ts, actor: row.actor, action: row.action, subject: row.subject, outcome: row.outcome, detailJson: row.detailJson };
    lines.push(JSON.stringify(row.hash === null || row.prevHash === null ? { ...base, legacy: true } : { ...base, prevHash: row.prevHash, hash: row.hash }));
  }
  const trailer: AuditChainTrailer = {
    schema: AUDIT_CHAIN_SCHEMA, kind: "proof", rows: chained.length, legacyRows: rows.length - chained.length,
    firstId: chained[0]?.id ?? null, lastId: chained.at(-1)?.id ?? null, startsAfterHash: chained[0]?.prevHash ?? null, headHash: chained.at(-1)?.hash ?? null, createdAt,
  };
  lines.push(JSON.stringify(trailer));
  return `${lines.join("\n")}\n`;
}

export interface AuditChainFileReport {
  ok: boolean;
  rows: number;
  legacyRows: number;
  firstId: number | null;
  lastId: number | null;
  startsAfterHash: string | null;
  headHash: string | null;
  firstBreak: AuditChainBreak | null;
}

/** Verifies a chain file offline: every link, every hash, consecutive ids, and the trailer. Never throws. */
export function checkAuditChainFile(text: string): AuditChainFileReport {
  const report: AuditChainFileReport = { ok: true, rows: 0, legacyRows: 0, firstId: null, lastId: null, startsAfterHash: null, headHash: null, firstBreak: null };
  const fail = (id: number | null, reason: string): AuditChainFileReport => ({ ...report, ok: false, firstBreak: { id, reason } });
  const lines = text.split("\n").filter(line => line.trim() !== "");
  if (!lines.length) return fail(null, "the file is empty");
  let trailer: Partial<AuditChainTrailer> | undefined;
  let prev: { id: number; hash: string } | undefined;
  for (let i = 0; i < lines.length; i++) {
    let line: Record<string, unknown>;
    try { line = JSON.parse(lines[i]!) as Record<string, unknown>; } catch { return fail(null, `line ${i + 1} is not JSON`); }
    if (!line || typeof line !== "object" || line.schema !== AUDIT_CHAIN_SCHEMA) return fail(null, `line ${i + 1} is not a ${AUDIT_CHAIN_SCHEMA} line`);
    if (line.kind === "proof") {
      if (i !== lines.length - 1) return fail(null, "lines follow the trailer");
      trailer = line as Partial<AuditChainTrailer>;
      continue;
    }
    const id = line.id;
    if (typeof id !== "number" || !Number.isSafeInteger(id) || ![line.ts, line.actor, line.action, line.subject, line.outcome, line.detailJson].every(v => typeof v === "string")) return fail(null, `line ${i + 1} is not an audit row`);
    if (line.legacy === true) {
      if (prev) return fail(id, "a row without a hash follows chained rows");
      report.legacyRows += 1;
      continue;
    }
    if (typeof line.prevHash !== "string" || typeof line.hash !== "string") return fail(id, "row has no hash");
    const row = { id, ts: line.ts as string, actor: line.actor as string, action: line.action as string, subject: line.subject as string, outcome: line.outcome as string, detailJson: line.detailJson as string };
    if (prev) {
      if (id !== prev.id + 1) return fail(id, `rows between id ${prev.id} and id ${id} are missing`);
      if (line.prevHash !== prev.hash) return fail(id, "row does not link to the row before it");
    } else {
      report.firstId = id;
      report.startsAfterHash = line.prevHash;
    }
    if (line.hash !== auditRowHash(line.prevHash, row)) return fail(id, "row content does not match its hash");
    prev = { id, hash: line.hash };
    report.rows += 1;
    report.lastId = id;
    report.headHash = line.hash;
  }
  if (!trailer) return fail(null, "the trailer line is missing, so the file may have been cut short");
  if (trailer.rows !== report.rows || trailer.lastId !== report.lastId || trailer.headHash !== report.headHash || trailer.firstId !== report.firstId || trailer.startsAfterHash !== report.startsAfterHash) return fail(null, "the trailer does not match the rows in the file");
  return report;
}
