// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Sessions in the shared database, for several replicas. Same behaviour as the SQLite store in the open
// engine; one contract test runs against both. Only a SHA-256 of the cookie value is stored.
import { createHash } from "node:crypto";
import type { Pool } from "pg";

export interface HaSessionRecord { id: string; userId: string; role?: string; createdAt: number; expiresAt: number }
export interface HaNewSession { id: string; userId: string; role?: string; expiresAt: number }

/** Same name as the engine's error, so callers match on `name` and need no import from here. */
export class SessionConflictError extends Error {
  override readonly name = "SessionConflictError";
  constructor() { super("A session with this id already exists."); }
}

const keyOf = (id: string): string => createHash("sha256").update(id).digest("hex");

export class PostgresSessionStore {
  readonly #pool: Pool;
  readonly #ownsPool: boolean;
  constructor(pool: Pool, options: { ownsPool?: boolean } = {}) {
    this.#pool = pool;
    this.#ownsPool = options.ownsPool ?? false;
  }

  async create(session: HaNewSession, now: number): Promise<void> {
    try {
      await this.#pool.query(
        "INSERT INTO zero_ha_sessions (key, user_id, role, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)",
        [keyOf(session.id), session.userId, session.role ?? null, now, session.expiresAt],
      );
    } catch (error) {
      if ((error as { code?: string }).code === "23505") throw new SessionConflictError();
      throw error;
    }
  }

  async get(id: string, now: number): Promise<HaSessionRecord | null> {
    const key = keyOf(id);
    const found = await this.#pool.query("SELECT user_id, role, created_at, expires_at FROM zero_ha_sessions WHERE key = $1", [key]);
    const row = found.rows[0];
    if (!row) return null;
    if (Number(row.expires_at) <= now) {
      await this.#pool.query("DELETE FROM zero_ha_sessions WHERE key = $1 AND expires_at <= $2", [key, now]);
      return null;
    }
    return { id, userId: String(row.user_id), ...(row.role === null ? {} : { role: String(row.role) }), createdAt: Number(row.created_at), expiresAt: Number(row.expires_at) };
  }

  async delete(id: string): Promise<boolean> {
    return ((await this.#pool.query("DELETE FROM zero_ha_sessions WHERE key = $1", [keyOf(id)])).rowCount ?? 0) > 0;
  }
  async deleteForUser(userId: string): Promise<number> {
    return (await this.#pool.query("DELETE FROM zero_ha_sessions WHERE user_id = $1", [userId])).rowCount ?? 0;
  }
  async clearRoleForUser(userId: string): Promise<number> {
    return (await this.#pool.query("UPDATE zero_ha_sessions SET role = NULL WHERE user_id = $1 AND role IS NOT NULL", [userId])).rowCount ?? 0;
  }
  async deleteExpired(now: number): Promise<number> {
    return (await this.#pool.query("DELETE FROM zero_ha_sessions WHERE expires_at <= $1", [now])).rowCount ?? 0;
  }
  async count(now: number): Promise<number> {
    const result = await this.#pool.query("SELECT COUNT(*) AS n FROM zero_ha_sessions WHERE expires_at > $1", [now]);
    return Number(result.rows[0].n);
  }
  async close(): Promise<void> { if (this.#ownsPool) await this.#pool.end(); }
}
