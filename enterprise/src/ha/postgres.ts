// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// The connection pool to the shared database. This is the only file that opens a network connection to it.
import pg from "pg";
import type { Pool } from "pg";
import { HaConfigError, type HaDatabaseConfig } from "./config.js";

const SCHEMA_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

export interface ConnectOptions {
  /** Tests give each run its own schema. The product leaves this unset and uses the database default. */
  schema?: string;
  max?: number;
}

/** A pool for the shared database. Nothing connects until the first query. */
export function createHaPool(config: HaDatabaseConfig, options: ConnectOptions = {}): Pool {
  if (options.schema !== undefined && !SCHEMA_NAME.test(options.schema)) throw new HaConfigError("The schema name is not valid.");
  const pool = new pg.Pool({
    connectionString: config.connectionString,
    max: options.max ?? 10,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 30_000,
    application_name: "0security",
    ...(options.schema ? { options: `-c search_path=${options.schema}` } : {}),
  });
  // An idle connection that the server drops must not crash the process. The next query opens a new one.
  pool.on("error", () => undefined);
  return pool;
}


/** Create or drop a schema, for tests that need an isolated copy of the tables. The product does not call this. */
export async function setHaSchema(config: HaDatabaseConfig, schema: string, action: "create" | "drop"): Promise<void> {
  if (!SCHEMA_NAME.test(schema)) throw new HaConfigError("The schema name is not valid.");
  const pool = createHaPool(config, { max: 1 });
  try {
    await pool.query(action === "create" ? `CREATE SCHEMA IF NOT EXISTS ${schema}` : `DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  } finally {
    await pool.end();
  }
}
