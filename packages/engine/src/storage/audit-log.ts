import { ensureDatabaseDirectory } from "./db-directory.js";
import { resolveOsecDbPath } from "./database.js";
import { AUDIT_GENESIS_HASH, auditCheckpointHash, auditRowHash, checkAuditChain, type AuditChainReport, type AuditChainRow, type AuditCheckpoint } from "./audit-chain.js";
import { createShimmedDatabase, type ShimmedDatabase } from "./wasm-shim.js";

/** Rows kept in the local audit log. Older rows are rotated out; nothing else ever deletes or edits a row. */
export const AUDIT_MAX_ROWS = 50_000;
export const AUDIT_FIELD_MAX = 200;
export const AUDIT_DETAIL_MAX_BYTES = 4_000;

export type AuditOutcome = "ok" | "denied" | "error";
export interface AuditEvent { id: number; ts: string; actor: string; action: string; subject: string; outcome: AuditOutcome; detail: Record<string, unknown> }
export interface AuditInput { actor: string; action: string; subject?: string; outcome?: AuditOutcome; detail?: Record<string, unknown>; ts?: string }
export interface AuditTarget { dbPath?: string; /** Row cap override (tests). */ maxRows?: number }

/** Only these detail keys are ever stored. Anything else a caller passes is dropped. */
export const AUDIT_DETAIL_KEYS: ReadonlySet<string> = new Set([
  "key", "keys", "old", "new", "scope", "enabled", "approved", "decision", "fingerprint", "name", "transport", "envKeys", "headerKeys",
  "callerKind", "route", "method", "status", "code", "kind", "id", "sentinelId", "triggerId", "trigger", "reason", "role", "autonomy",
  "expires", "seed", "preset", "count", "source", "repo", "sessionId", "decisionId", "path", "version", "client",
]);
const SECRET_KEY = /secret|token|passw|api[-_]?key|authorization|credential|private[-_]?key|cookie|bearer|session[-_]?key/i;
const SECRET_VALUE: readonly RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{12,}/g, /\bgh[pousr]_[A-Za-z0-9]{16,}/g, /\bgithub_pat_[A-Za-z0-9_]{20,}/g, /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g, /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g, /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/g, /\b(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{40,}={0,2}/g,
  /\b(?:password|passwd|secret|token|api[-_]?key|authorization)\s*[=:]\s*\S+/gi,
];

export function isSecretName(name: string): boolean { return SECRET_KEY.test(name); }

/** The redaction every audit text field goes through: secret-looking values become [redacted], then the field is truncated. */
export function scrubAuditText(value: string): string { return scrub(value); }
function scrub(value: string): string {
  let out = value;
  for (const pattern of SECRET_VALUE) out = out.replace(pattern, "[redacted]");
  return out.length > AUDIT_FIELD_MAX ? `${out.slice(0, AUDIT_FIELD_MAX - 1)}…` : out;
}
function scalar(value: unknown): string | number | boolean | null | undefined {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "string") return scrub(value);
  return undefined;
}

/** Whitelists keys, keeps scalars and short scalar arrays, truncates strings, strips secret-looking values. */
export function redactAuditDetail(detail: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!detail || typeof detail !== "object") return out;
  const secretSubject = typeof detail.key === "string" && isSecretName(detail.key);
  for (const [name, raw] of Object.entries(detail)) {
    if (!AUDIT_DETAIL_KEYS.has(name)) continue;
    if ((name === "old" || name === "new") && secretSubject && typeof raw !== "boolean") { out[name] = "[redacted]"; continue; }
    if (Array.isArray(raw)) {
      const items = raw.slice(0, 20).map(scalar).filter(item => item !== undefined);
      out[name] = items;
      continue;
    }
    const value = scalar(raw);
    if (value !== undefined) out[name] = value;
  }
  let json = JSON.stringify(out);
  while (json.length > AUDIT_DETAIL_MAX_BYTES) { delete out[Object.keys(out).at(-1)!]; json = JSON.stringify(out); }
  return out;
}

const handles = new Map<string, { db: ShimmedDatabase; inserts: number }>();
function open(path: string) {
  const known = handles.get(path);
  if (known) return known;
  if (path !== ":memory:") ensureDatabaseDirectory(path);
  const db = createShimmedDatabase(path);
  db.pragma("busy_timeout = 5000");
  db.exec(`CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, outcome TEXT NOT NULL, detail_json TEXT NOT NULL, prev_hash TEXT, hash TEXT);
    CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events(ts);
    CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
    CREATE TABLE IF NOT EXISTS audit_checkpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, through_id INTEGER NOT NULL, through_hash TEXT NOT NULL, dropped INTEGER NOT NULL, ts TEXT NOT NULL, prev_checkpoint_hash TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_update BEFORE UPDATE ON audit_checkpoints BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;`);
  // A database made before the hash chain has no hash columns. Add them; old rows stay unchained.
  const columns = (db.prepare("PRAGMA table_info(audit_events)").all() as Array<Record<string, unknown>>).map(row => String(row.name));
  for (const column of ["prev_hash", "hash"]) {
    if (columns.includes(column)) continue;
    try { db.exec(`ALTER TABLE audit_events ADD COLUMN ${column} TEXT`); } catch { /* another process added it first */ }
  }
  const entry = { db, inserts: 0 };
  handles.set(path, entry);
  return entry;
}
/** Removes rows up to `throughId` and records a checkpoint with the hash of the last removed row, so the chain still verifies. */
function rotate(db: ShimmedDatabase, throughId: number): void {
  if (throughId < 1) return;
  const last = db.prepare("SELECT id, hash FROM audit_events WHERE id <= ? ORDER BY id DESC LIMIT 1").get(throughId) as { id?: number; hash?: string | null } | undefined;
  if (!last?.id) return;
  const dropped = Number((db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE id <= ?").get(last.id) as { n?: number } | undefined)?.n ?? 0);
  // A dropped row from before the chain has no hash; the chain then starts after it, from the genesis hash.
  const previous = db.prepare("SELECT hash FROM audit_checkpoints ORDER BY id DESC LIMIT 1").get() as { hash?: string } | undefined;
  const cp = { throughId: last.id, throughHash: last.hash ?? AUDIT_GENESIS_HASH, dropped, ts: new Date().toISOString(), prevCheckpointHash: previous?.hash ?? AUDIT_GENESIS_HASH };
  db.prepare("INSERT INTO audit_checkpoints (through_id, through_hash, dropped, ts, prev_checkpoint_hash, hash) VALUES (?, ?, ?, ?, ?, ?)")
    .run(cp.throughId, cp.throughHash, cp.dropped, cp.ts, cp.prevCheckpointHash, auditCheckpointHash(cp));
  db.prepare("DELETE FROM audit_events WHERE id <= ?").run(last.id);
}
const resolvePath = (target?: AuditTarget) => target?.dbPath === ":memory:" ? ":memory:" : resolveOsecDbPath(target?.dbPath);

/** Releases cached connections (database reset, tests). */
export function closeAuditLog(dbPath?: string): void {
  const paths = dbPath === undefined ? [...handles.keys()] : [dbPath === ":memory:" ? ":memory:" : resolveOsecDbPath(dbPath)];
  for (const path of paths) { try { handles.get(path)?.db.close(); } catch { /* already closed */ } handles.delete(path); }
}

/** Appends one audit event. Never throws: auditing must not break the action it records. */
export function recordAudit(input: AuditInput, target?: AuditTarget): void {
  try {
    const entry = open(resolvePath(target));
    const maxRows = Math.max(1, target?.maxRows ?? AUDIT_MAX_ROWS);
    const outcome: AuditOutcome = input.outcome === "denied" || input.outcome === "error" ? input.outcome : "ok";
    const row = {
      ts: input.ts ?? new Date().toISOString(), actor: scrub(String(input.actor ?? "system")), action: scrub(String(input.action ?? "unknown")),
      subject: scrub(String(input.subject ?? "")), outcome, detailJson: JSON.stringify(redactAuditDetail(input.detail)),
    };
    const { db } = entry;
    // One immediate transaction: another process cannot write between reading the previous hash and inserting.
    db.transaction(() => {
      const last = db.prepare("SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1").get() as { id?: number; hash?: string | null } | undefined;
      const seq = db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'").get() as { seq?: number } | undefined;
      const checkpoint = db.prepare("SELECT through_hash FROM audit_checkpoints ORDER BY id DESC LIMIT 1").get() as { through_hash?: string } | undefined;
      const id = Math.max(Number(seq?.seq ?? 0), Number(last?.id ?? 0)) + 1;
      const prevHash = last ? (last.hash ?? AUDIT_GENESIS_HASH) : (checkpoint?.through_hash ?? AUDIT_GENESIS_HASH);
      const hash = auditRowHash(prevHash, { id, ...row });
      db.prepare("INSERT INTO audit_events (id, ts, actor, action, subject, outcome, detail_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(id, row.ts, row.actor, row.action, row.subject, row.outcome, row.detailJson, prevHash, hash);
      entry.inserts += 1;
      if (entry.inserts % Math.min(100, maxRows) === 0) rotate(db, id - maxRows);
    }).immediate();
  } catch { /* never surface */ }
}

export interface AuditQuery { limit?: number; before?: number; q?: string }
export interface AuditPage { events: AuditEvent[]; nextBefore: number | null }

/** Newest first. `before` is an exclusive id cursor; `q` matches action, subject or actor. */
export function listAudit(query: AuditQuery = {}, target?: AuditTarget): AuditPage {
  try {
    const { db } = open(resolvePath(target));
    const limit = Math.min(500, Math.max(1, Math.trunc(query.limit ?? 100) || 100));
    const where: string[] = []; const args: unknown[] = [];
    if (typeof query.before === "number" && Number.isFinite(query.before)) { where.push("id < ?"); args.push(query.before); }
    const q = query.q?.trim().slice(0, 100);
    if (q) { const like = `%${q.replace(/[\\%_]/g, "\\$&")}%`; where.push("(action LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\')"); args.push(like, like, like); }
    const rows = db.prepare(`SELECT id, ts, actor, action, subject, outcome, detail_json FROM audit_events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`).all(...args, limit + 1) as Array<Record<string, unknown>>;
    const page = rows.slice(0, limit).map((row): AuditEvent => {
      let detail: Record<string, unknown> = {};
      try { detail = JSON.parse(String(row.detail_json)) as Record<string, unknown>; } catch { /* keep empty */ }
      return { id: Number(row.id), ts: String(row.ts), actor: String(row.actor), action: String(row.action), subject: String(row.subject), outcome: row.outcome as AuditOutcome, detail };
    });
    return { events: page, nextBefore: rows.length > limit ? page.at(-1)!.id : null };
  } catch { return { events: [], nextBefore: null }; }
}

export interface AuditRangeQuery {
  /** Inclusive ISO lower bound on the event time. */
  since?: string;
  /** Exclusive ISO upper bound on the event time. */
  until?: string;
  /** Exact action names or dotted prefixes: `extension` matches `extension.install`. */
  types?: readonly string[];
  /** Only events with a larger id. */
  afterId?: number;
  limit?: number;
}

const rowToEvent = (row: Record<string, unknown>): AuditEvent => {
  let detail: Record<string, unknown> = {};
  try { detail = JSON.parse(String(row.detail_json)) as Record<string, unknown>; } catch { /* keep empty */ }
  return { id: Number(row.id), ts: String(row.ts), actor: String(row.actor), action: String(row.action), subject: String(row.subject), outcome: row.outcome as AuditOutcome, detail };
};

/**
 * Oldest first. With `afterId` the limit keeps the oldest matches (resume a stream); otherwise it keeps the newest
 * matches, still returned oldest first. Throws when the log cannot be read, unlike listAudit.
 */
export function queryAuditEvents(query: AuditRangeQuery = {}, target?: AuditTarget): AuditEvent[] {
  const { db } = open(resolvePath(target));
  const where: string[] = []; const args: unknown[] = [];
  if (typeof query.afterId === "number" && Number.isFinite(query.afterId)) { where.push("id > ?"); args.push(query.afterId); }
  if (query.since) { where.push("ts >= ?"); args.push(query.since); }
  if (query.until) { where.push("ts < ?"); args.push(query.until); }
  const types = (query.types ?? []).map(type => type.trim()).filter(Boolean);
  if (types.length) {
    where.push(`(${types.map(() => "(action = ? OR action LIKE ? ESCAPE '\\')").join(" OR ")})`);
    for (const type of types) args.push(type, `${type.replace(/[\\%_]/g, "\\$&")}.%`);
  }
  const limit = query.limit !== undefined && Number.isSafeInteger(query.limit) && query.limit > 0 ? query.limit : undefined;
  const newest = limit !== undefined && query.afterId === undefined;
  const sql = `SELECT id, ts, actor, action, subject, outcome, detail_json FROM audit_events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id ${newest ? "DESC" : "ASC"}${limit !== undefined ? " LIMIT ?" : ""}`;
  const rows = db.prepare(sql).all(...args, ...(limit !== undefined ? [limit] : [])) as Array<Record<string, unknown>>;
  const events = rows.map(rowToEvent);
  return newest ? events.reverse() : events;
}

/** The newest event id, or 0 when the log is empty or unreadable. */
export function latestAuditId(target?: AuditTarget): number {
  try {
    const row = open(resolvePath(target)).db.prepare("SELECT MAX(id) AS id FROM audit_events").get() as { id?: number | null } | undefined;
    return Number(row?.id ?? 0) || 0;
  } catch { return 0; }
}

/**
 * Checks the hash chain of the audit log. Read-only and free: it needs no license and no network.
 * Throws when the database cannot be read.
 */
export function verifyAuditLog(target?: AuditTarget): AuditChainReport {
  const { db } = open(resolvePath(target));
  const rows = (db.prepare("SELECT id, ts, actor, action, subject, outcome, detail_json, prev_hash, hash FROM audit_events ORDER BY id ASC").all() as Array<Record<string, unknown>>)
    .map((row): AuditChainRow => ({ id: Number(row.id), ts: String(row.ts), actor: String(row.actor), action: String(row.action), subject: String(row.subject), outcome: String(row.outcome), detailJson: String(row.detail_json), prevHash: row.prev_hash === null ? null : String(row.prev_hash), hash: row.hash === null ? null : String(row.hash) }));
  const checkpoints = (db.prepare("SELECT id, through_id, through_hash, dropped, ts, prev_checkpoint_hash, hash FROM audit_checkpoints ORDER BY id ASC").all() as Array<Record<string, unknown>>)
    .map((row): AuditCheckpoint => ({ id: Number(row.id), throughId: Number(row.through_id), throughHash: String(row.through_hash), dropped: Number(row.dropped), ts: String(row.ts), prevCheckpointHash: String(row.prev_checkpoint_hash), hash: String(row.hash) }));
  const seq = db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'").get() as { seq?: number } | undefined;
  return checkAuditChain({ rows, checkpoints, highestIdEver: seq?.seq === undefined ? null : Number(seq.seq) });
}

const rowToChainRow = (row: Record<string, unknown>): AuditChainRow => ({
  id: Number(row.id), ts: String(row.ts), actor: String(row.actor), action: String(row.action), subject: String(row.subject), outcome: String(row.outcome), detailJson: String(row.detail_json),
  prevHash: row.prev_hash === null || row.prev_hash === undefined ? null : String(row.prev_hash), hash: row.hash === null || row.hash === undefined ? null : String(row.hash),
});

/** Rows with their hashes, oldest first, for an export with proof. Time bounds as in queryAuditEvents. Throws when the log cannot be read. */
export function queryAuditChainRows(query: { since?: string; until?: string; limit?: number } = {}, target?: AuditTarget): AuditChainRow[] {
  const { db } = open(resolvePath(target));
  const where: string[] = []; const args: unknown[] = [];
  if (query.since) { where.push("ts >= ?"); args.push(query.since); }
  if (query.until) { where.push("ts < ?"); args.push(query.until); }
  const limit = query.limit !== undefined && Number.isSafeInteger(query.limit) && query.limit > 0 ? query.limit : undefined;
  const sql = `SELECT id, ts, actor, action, subject, outcome, detail_json, prev_hash, hash FROM audit_events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id ${limit !== undefined ? "DESC LIMIT ?" : "ASC"}`;
  const rows = (db.prepare(sql).all(...args, ...(limit !== undefined ? [limit] : [])) as Array<Record<string, unknown>>).map(rowToChainRow);
  return limit !== undefined ? rows.reverse() : rows;
}

/** The oldest rows older than `before` (ISO time), as one run from the start of the log. At least the newest row is always kept. */
export function planAuditPrune(before: string, target?: AuditTarget): AuditChainRow[] {
  const { db } = open(resolvePath(target));
  const newest = latestAuditId(target);
  const rows = (db.prepare("SELECT id, ts, actor, action, subject, outcome, detail_json, prev_hash, hash FROM audit_events WHERE id < ? ORDER BY id ASC").all(newest) as Array<Record<string, unknown>>).map(rowToChainRow);
  // Rotation removes a run from the oldest row, so stop at the first row that is not older than the cutoff.
  const end = rows.findIndex(row => !(row.ts < before));
  return end === -1 ? rows : rows.slice(0, end);
}

export interface AuditPruneResult { pruned: number; throughId: number | null; throughHash: string | null }

/**
 * Removes the rows older than `before` and records a rotation checkpoint, so the log still verifies. `archive` receives
 * the rows first and must store them durably; when it throws nothing is removed. Runs in one write transaction.
 */
export function pruneAuditLog(before: string, archive: (rows: AuditChainRow[]) => void, target?: AuditTarget): AuditPruneResult {
  const { db } = open(resolvePath(target));
  return db.transaction((): AuditPruneResult => {
    const rows = planAuditPrune(before, target);
    if (!rows.length) return { pruned: 0, throughId: null, throughHash: null };
    archive(rows);
    const last = rows.at(-1)!;
    rotate(db, last.id);
    return { pruned: rows.length, throughId: last.id, throughHash: last.hash };
  }).immediate();
}

/** The hash of the last row that rotation or retention removed, by row id; null when no checkpoint covers it. */
export function auditCheckpointHashAt(throughId: number, target?: AuditTarget): string | null {
  try {
    const row = open(resolvePath(target)).db.prepare("SELECT through_hash FROM audit_checkpoints WHERE through_id = ?").get(throughId) as { through_hash?: string } | undefined;
    return row?.through_hash ?? null;
  } catch { return null; }
}
