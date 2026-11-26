// Bridge to the key-gated enterprise package for high availability (see scripts/check-enterprise-boundary.mjs).
// Call sites outside this file are plain `if (!hasHighAvailability())` checks.
import {
  HaConfigError,
  PostgresSessionStore,
  createHaPool,
  featureMode,
  hasFeature,
  parseHaDatabaseConfig,
  requireFeature,
  runMigrations,
  setHaSchema,
} from "@0/enterprise";
import type { SessionStore } from "@0/engine/storage";

export { HaConfigError };

/** Drop the throwaway schema a test made. The product never calls this. */
export async function dropTestSchema(env: NodeJS.ProcessEnv, schema: string): Promise<void> {
  const config = parseHaDatabaseConfig(env);
  if (config) await setHaSchema(config, schema, "drop");
}

/** True when the license allows a shared database. Expired past the grace period, it is false. */
export function hasHighAvailability(): boolean {
  return hasFeature("ha");
}

/** The sentence to show when a shared database is named but the license does not allow it. */
export function highAvailabilityMessage(): string {
  return requireFeature("ha") ?? "High availability is available.";
}

export interface HaSessionStoreHandle {
  store: SessionStore;
  /** Where the sessions live, safe to print: host and database. */
  label: string;
  /** Migration versions this call applied. */
  migrated: number[];
}

/**
 * Open the session store in the shared database the environment names. Returns null when none is named, so the
 * caller keeps its single-node store. Throws when one is named and the license does not allow it, or when
 * the setting is refused. Nothing is read from a repository, a project file or the database.
 */
export async function openHaSessionStore(env: NodeJS.ProcessEnv = process.env, options: { schema?: string } = {}): Promise<HaSessionStoreHandle | null> {
  const config = parseHaDatabaseConfig(env);
  if (!config) return null;
  if (featureMode("ha", env) !== "full") throw new Error(requireFeature("ha", env) ?? "High availability needs an enterprise license.");
  if (options.schema) await setHaSchema(config, options.schema, "create");
  const pool = createHaPool(config, options.schema ? { schema: options.schema } : {});
  try {
    const migrated = await runMigrations(pool);
    // PostgresSessionStore has the same shape as SessionStore. This assignment is the compile-time proof.
    const store: SessionStore = new PostgresSessionStore(pool, { ownsPool: true });
    return { store, label: config.label, migrated };
  } catch (error) {
    await pool.end().catch(() => undefined);
    throw error;
  }
}
