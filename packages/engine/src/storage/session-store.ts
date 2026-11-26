// Server sign-in sessions behind one small async interface. SQLite is the default and the only
// backend in the open product. A shared database for several replicas is an enterprise feature
// (`ha`) that implements this same interface; see docs/design/ha-server.md.
import { createHash } from "node:crypto";
import { ensureDatabaseDirectory } from "./db-directory.js";
import { resolveOsecDbPath } from "./database-lifecycle.js";
import { createShimmedDatabase, type ShimmedDatabase } from "./wasm-shim.js";

export interface SessionRecord {
  /** The opaque value the browser holds in its cookie. Stores keep only a hash of it. */
  id: string;
  userId: string;
  /** A role fixed for this session at sign-in (single sign-on). Absent when the account's role applies. */
  role?: string;
  /** Epoch milliseconds. */
  createdAt: number;
  /** Epoch milliseconds. A session is valid while this is later than now. */
  expiresAt: number;
}

export interface NewSession {
  id: string;
  userId: string;
  role?: string;
  expiresAt: number;
}

/** Thrown by `create` when a session with that id exists. The name is part of the contract. */
export class SessionConflictError extends Error {
  override readonly name = "SessionConflictError";
  constructor() { super("A session with this id already exists."); }
}

/**
 * Every call takes `now` so expiry is decided by the caller's clock and tests need no timers.
 * Implementations must keep only `sessionKey(id)` at rest, never the cookie value itself.
 */
export interface SessionStore {
  /** Add a session. Rejects with SessionConflictError when the id is taken. */
  create(session: NewSession, now: number): Promise<void>;
  /** The live session, or null when it is unknown or expired. */
  get(id: string, now: number): Promise<SessionRecord | null>;
  /** Remove one session. True when it existed. */
  delete(id: string): Promise<boolean>;
  /** Remove every session of one account. Returns how many were removed. */
  deleteForUser(userId: string): Promise<number>;
  /** Drop the fixed role of every session of one account, so the account's current role applies. */
  clearRoleForUser(userId: string): Promise<number>;
  /** Remove expired sessions. Returns how many were removed. */
  deleteExpired(now: number): Promise<number>;
  /** Live sessions, for a capacity limit. */
  count(now: number): Promise<number>;
  close(): Promise<void>;
}

/** The stored key for a cookie value: SHA-256 as hex. A leaked database does not leak usable cookies. */
export function sessionKey(id: string): string {
  return createHash("sha256").update(id).digest("hex");
}

/** Sessions in the server database file. One process owns the file. */
export class SqliteSessionStore implements SessionStore {
  readonly #db: ShimmedDatabase;
  constructor(dbPath?: string) {
    const path = dbPath === ":memory:" ? ":memory:" : resolveOsecDbPath(dbPath);
    if (path !== ":memory:") ensureDatabaseDirectory(path);
    this.#db = createShimmedDatabase(path);
    this.#db.pragma("busy_timeout = 5000");
    this.#db.exec(`CREATE TABLE IF NOT EXISTS server_sessions (key TEXT PRIMARY KEY, user_id TEXT NOT NULL, role TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS server_sessions_user ON server_sessions(user_id);
      CREATE INDEX IF NOT EXISTS server_sessions_expires ON server_sessions(expires_at);`);
  }

  async create(session: NewSession, now: number): Promise<void> {
    try {
      this.#db.prepare("INSERT INTO server_sessions (key, user_id, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
        .run(sessionKey(session.id), session.userId, session.role ?? null, now, session.expiresAt);
    } catch (error) {
      if (/UNIQUE|PRIMARY KEY|constraint/i.test(error instanceof Error ? error.message : String(error))) throw new SessionConflictError();
      throw error;
    }
  }

  async get(id: string, now: number): Promise<SessionRecord | null> {
    const key = sessionKey(id);
    const row = this.#db.prepare("SELECT user_id, role, created_at, expires_at FROM server_sessions WHERE key = ?").get(key) as Record<string, unknown> | undefined;
    if (!row) return null;
    if (Number(row.expires_at) <= now) {
      this.#db.prepare("DELETE FROM server_sessions WHERE key = ?").run(key);
      return null;
    }
    return { id, userId: String(row.user_id), ...(row.role === null ? {} : { role: String(row.role) }), createdAt: Number(row.created_at), expiresAt: Number(row.expires_at) };
  }

  async delete(id: string): Promise<boolean> {
    return this.#db.prepare("DELETE FROM server_sessions WHERE key = ?").run(sessionKey(id)).changes > 0;
  }
  async deleteForUser(userId: string): Promise<number> {
    return Number(this.#db.prepare("DELETE FROM server_sessions WHERE user_id = ?").run(userId).changes);
  }
  async clearRoleForUser(userId: string): Promise<number> {
    return Number(this.#db.prepare("UPDATE server_sessions SET role = NULL WHERE user_id = ? AND role IS NOT NULL").run(userId).changes);
  }
  async deleteExpired(now: number): Promise<number> {
    return Number(this.#db.prepare("DELETE FROM server_sessions WHERE expires_at <= ?").run(now).changes);
  }
  async count(now: number): Promise<number> {
    return Number((this.#db.prepare("SELECT COUNT(*) AS n FROM server_sessions WHERE expires_at > ?").get(now) as { n: number }).n);
  }
  async close(): Promise<void> { try { this.#db.close(); } catch { /* already closed */ } }
}
