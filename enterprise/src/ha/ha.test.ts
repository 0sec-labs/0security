// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { HA_DATABASE_URL_ENV, HA_DATABASE_URL_FILE_ENV, HaConfigError, parseHaDatabaseConfig } from "./config.js";
import { MIGRATIONS, MigrationError, runMigrations } from "./migrate.js";
import { createHaPool, setHaSchema } from "./postgres.js";
import { PostgresSessionStore } from "./postgres-session-store.js";

describe("parseHaDatabaseConfig", () => {
  it("names no database when nothing is set", () => {
    expect(parseHaDatabaseConfig({})).toBeNull();
    expect(parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: "  " })).toBeNull();
  });

  it("accepts a loopback database without TLS and prints no password", () => {
    const config = parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: "postgres://u:secret@127.0.0.1:5432/zero" })!;
    expect(config.label).toBe("127.0.0.1:5432/zero");
    expect(config.label).not.toContain("secret");
    expect(config.source).toBe("env");
  });

  it("refuses another machine without TLS and accepts it with TLS", () => {
    expect(() => parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: "postgres://u:p@db.internal/zero" })).toThrow(HaConfigError);
    expect(() => parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: "postgres://u:p@db.internal/zero?sslmode=disable" })).toThrow(/sslmode/);
    expect(parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: "postgres://u:p@db.internal/zero?sslmode=verify-full" })?.label).toBe("db.internal/zero");
  });

  it("refuses other schemes, a missing host and a malformed value, without echoing the value", () => {
    for (const value of ["mysql://u:p@h/db", "postgres:///zero", "not a url with secret-pw"]) {
      let message = "";
      try { parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: value }); } catch (error) { message = (error as Error).message; }
      expect(message).not.toBe("");
      expect(message).not.toContain("secret-pw");
    }
  });

  it("reads the file the environment names and refuses both settings at once", () => {
    const dir = mkdtempSync(join(tmpdir(), "zero-ha-config-"));
    try {
      const file = join(dir, "url");
      writeFileSync(file, "postgres://u:p@localhost/zero\n", { mode: 0o600 });
      expect(parseHaDatabaseConfig({ [HA_DATABASE_URL_FILE_ENV]: file })?.source).toBe("file");
      expect(() => parseHaDatabaseConfig({ [HA_DATABASE_URL_FILE_ENV]: file, [HA_DATABASE_URL_ENV]: "postgres://u:p@localhost/zero" })).toThrow(/only one/);
      expect(() => parseHaDatabaseConfig({ [HA_DATABASE_URL_FILE_ENV]: join(dir, "missing") })).toThrow(/readable file/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

const URL_UNDER_TEST = process.env.ZERO_TEST_POSTGRES_URL;

describe.skipIf(!URL_UNDER_TEST)("shared database (needs ZERO_TEST_POSTGRES_URL)", () => {
  const config = URL_UNDER_TEST ? parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: URL_UNDER_TEST })! : (null as never);
  const schemas: string[] = [];
  const fresh = async () => {
    const schema = `t_${randomBytes(6).toString("hex")}`;
    schemas.push(schema);
    await setHaSchema(config, schema, "create");
    return { schema, pool: createHaPool(config, { schema, max: 8 }) };
  };
  afterAll(async () => { for (const schema of schemas.splice(0)) await setHaSchema(config, schema, "drop"); });

  it("applies each migration once, even when many replicas start together", async () => {
    const { pool } = await fresh();
    try {
      const runs = await Promise.all(Array.from({ length: 6 }, () => runMigrations(pool)));
      expect(runs.flat().sort()).toEqual(MIGRATIONS.map(migration => migration.version));
      expect(await runMigrations(pool)).toEqual([]);
      const rows = await pool.query("SELECT version FROM zero_schema_migrations ORDER BY version");
      expect(rows.rows.map(row => row.version)).toEqual(MIGRATIONS.map(migration => migration.version));
    } finally { await pool.end(); }
  });

  it("rolls a failed migration back and leaves the version unchanged", async () => {
    const { pool } = await fresh();
    try {
      await runMigrations(pool);
      const broken = [...MIGRATIONS, { version: MIGRATIONS.length + 1, name: "broken", sql: "CREATE TABLE half_done (x INT); SELECT nope FROM missing_table;" }];
      await expect(runMigrations(pool, broken)).rejects.toThrow();
      const tables = await pool.query("SELECT to_regclass('half_done') AS t");
      expect(tables.rows[0].t).toBeNull();
      expect((await pool.query("SELECT MAX(version) AS v FROM zero_schema_migrations")).rows[0].v).toBe(MIGRATIONS.length);
      // The lock was released: a later run is not blocked.
      expect(await runMigrations(pool)).toEqual([]);
    } finally { await pool.end(); }
  });

  it("refuses a database that is newer than this build", async () => {
    const { pool } = await fresh();
    try {
      await runMigrations(pool);
      await pool.query("INSERT INTO zero_schema_migrations (version, name) VALUES ($1, 'from a newer build')", [MIGRATIONS.length + 1]);
      await expect(runMigrations(pool)).rejects.toBeInstanceOf(MigrationError);
    } finally { await pool.end(); }
  });

  it("stores a hash of the cookie value, never the value", async () => {
    const { pool } = await fresh();
    try {
      await runMigrations(pool);
      const store = new PostgresSessionStore(pool);
      const secret = `cookie-${randomBytes(12).toString("hex")}`;
      await store.create({ id: secret, userId: "alex", expiresAt: Date.now() + 60_000 }, Date.now());
      const rows = await pool.query("SELECT key, user_id FROM zero_ha_sessions");
      expect(rows.rows).toHaveLength(1);
      expect(rows.rows[0].key).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.stringify(rows.rows)).not.toContain(secret);
    } finally { await pool.end(); }
  });
});
