// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Versioned schema migrations for the shared database. Every replica may run this at start. A session
// advisory lock lets one apply the pending migrations while the others wait, and each migration runs in
// its own transaction. A database that is newer than this build is refused, so an old replica cannot
// run against a schema it does not know.
import type { Pool } from "pg";

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

/** The one advisory-lock key for migrations. It is arbitrary but fixed, so every replica contends on it. */
export const MIGRATION_LOCK_KEY = 7_204_061_001;

export class MigrationError extends Error {
  override readonly name = "MigrationError";
}

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "server sessions",
    sql: `CREATE TABLE zero_ha_sessions (
      key TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      role TEXT,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL
    );
    CREATE INDEX zero_ha_sessions_user ON zero_ha_sessions(user_id);
    CREATE INDEX zero_ha_sessions_expires ON zero_ha_sessions(expires_at);`,
  },
];

/** Apply pending migrations. Returns the versions applied by this call. */
export async function runMigrations(pool: Pool, migrations: readonly Migration[] = MIGRATIONS): Promise<number[]> {
  const sorted = [...migrations].sort((a, b) => a.version - b.version);
  sorted.forEach((migration, index) => {
    if (migration.version !== index + 1) throw new MigrationError("Migration versions must run 1, 2, 3 with no gaps.");
  });
  const client = await pool.connect();
  const applied: number[] = [];
  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
    try {
      await client.query("CREATE TABLE IF NOT EXISTS zero_schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
      const done = await client.query("SELECT COALESCE(MAX(version), 0) AS v FROM zero_schema_migrations");
      const current = Number(done.rows[0].v);
      const newest = sorted.at(-1)?.version ?? 0;
      if (current > newest) throw new MigrationError(`The database is at schema version ${current}, newer than this build (${newest}). Upgrade this replica first.`);
      for (const migration of sorted) {
        if (migration.version <= current) continue;
        await client.query("BEGIN");
        try {
          await client.query(migration.sql);
          await client.query("INSERT INTO zero_schema_migrations (version, name) VALUES ($1, $2)", [migration.version, migration.name]);
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK").catch(() => undefined);
          throw error;
        }
        applied.push(migration.version);
      }
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY]).catch(() => undefined);
    }
  } finally {
    client.release();
  }
  return applied;
}
