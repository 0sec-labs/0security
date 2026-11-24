import { ensureDatabaseDirectory } from "./db-directory.js";
import { resolveOsecDbPath } from "./database.js";
import { createShimmedDatabase, type ShimmedDatabase } from "./wasm-shim.js";

/** Where a team account came from. `file` rows were imported from the team configuration file. */
export type TeamUserSource = "file" | "local" | "oidc";

export interface TeamUserRow {
  id: string;
  name: string;
  role: string;
  passwordHash: string | null;
  oidcSub: string | null;
  source: TeamUserSource;
  createdAt: string;
  updatedAt: string;
}

export type TeamUserInput = Omit<TeamUserRow, "createdAt" | "updatedAt"> & { createdAt?: string; updatedAt?: string };

export class TeamUserConflictError extends Error {
  constructor(readonly field: "id" | "oidcSub") { super(field === "id" ? "That account ID already exists" : "That OIDC subject is already linked to an account"); this.name = "TeamUserConflictError"; }
}

const COLUMNS = "id, name, role, password_hash, oidc_sub, source, created_at, updated_at";

function toRow(raw: Record<string, unknown>): TeamUserRow {
  return {
    id: String(raw.id), name: String(raw.name), role: String(raw.role),
    passwordHash: raw.password_hash === null ? null : String(raw.password_hash),
    oidcSub: raw.oidc_sub === null ? null : String(raw.oidc_sub),
    source: raw.source as TeamUserSource, createdAt: String(raw.created_at), updatedAt: String(raw.updated_at),
  };
}

/**
 * Team accounts in the server database. One row per account, no row cap. The table sits next to the
 * audit log in the same file and is created on first open. This class holds its own connection and
 * does no caching; the caller decides how much to keep in memory.
 */
export class TeamUserTable {
  private readonly db: ShimmedDatabase;
  constructor(dbPath?: string) {
    const path = dbPath === ":memory:" ? ":memory:" : resolveOsecDbPath(dbPath);
    if (path !== ":memory:") ensureDatabaseDirectory(path);
    this.db = createShimmedDatabase(path);
    this.db.pragma("busy_timeout = 5000");
    this.db.exec(`CREATE TABLE IF NOT EXISTS team_users (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, password_hash TEXT, oidc_sub TEXT UNIQUE,
      source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`);
  }
  count(): number { return Number((this.db.prepare("SELECT COUNT(*) AS n FROM team_users").get() as { n: number }).n); }
  list(): TeamUserRow[] { return (this.db.prepare(`SELECT ${COLUMNS} FROM team_users ORDER BY created_at, id`).all() as Array<Record<string, unknown>>).map(toRow); }
  get(id: string): TeamUserRow | null {
    const raw = this.db.prepare(`SELECT ${COLUMNS} FROM team_users WHERE id = ?`).get(id) as Record<string, unknown> | undefined;
    return raw ? toRow(raw) : null;
  }
  getByOidcSub(sub: string): TeamUserRow | null {
    const raw = this.db.prepare(`SELECT ${COLUMNS} FROM team_users WHERE oidc_sub = ?`).get(sub) as Record<string, unknown> | undefined;
    return raw ? toRow(raw) : null;
  }
  /** Insert one account. Throws TeamUserConflictError when the ID or the OIDC subject is taken. */
  insert(input: TeamUserInput): TeamUserRow {
    if (this.get(input.id)) throw new TeamUserConflictError("id");
    if (input.oidcSub && this.getByOidcSub(input.oidcSub)) throw new TeamUserConflictError("oidcSub");
    const now = new Date().toISOString();
    const row: TeamUserRow = { ...input, createdAt: input.createdAt ?? now, updatedAt: input.updatedAt ?? now };
    this.db.prepare(`INSERT INTO team_users (${COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(row.id, row.name, row.role, row.passwordHash, row.oidcSub, row.source, row.createdAt, row.updatedAt);
    return row;
  }
  /**
   * Insert the accounts whose ID is not stored yet, in one transaction. Existing rows are never changed:
   * the database wins over the file. Returns the rows that were added.
   */
  importMissing(rows: readonly TeamUserInput[]): TeamUserRow[] {
    const added: TeamUserRow[] = [];
    this.db.transaction(() => {
      for (const row of rows) {
        if (this.get(row.id)) continue;
        if (row.oidcSub && this.getByOidcSub(row.oidcSub)) continue;
        added.push(this.insert(row));
      }
    })();
    return added;
  }
  close(): void { try { this.db.close(); } catch { /* already closed */ } }
}
