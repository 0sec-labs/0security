// Bridge to the key-gated enterprise package for high availability (see scripts/check-enterprise-boundary.mjs).
// Call sites outside this file are plain `if (!hasHighAvailability())` checks.
import {
  HaConfigError,
  JobWorker,
  PostgresJobQueue,
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
import type { Job, JobHandler, JobQueue, JobWorkerOptions, StopResult } from "@0/enterprise";

export { HaConfigError };
export type { Job, JobHandler, JobQueue, StopResult };

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

interface OpenedPool { pool: ReturnType<typeof createHaPool>; label: string; migrated: number[] }

/** Check the license, open the pool and migrate. Returns null when no shared database is named. */
async function openPool(env: NodeJS.ProcessEnv, options: { schema?: string }): Promise<OpenedPool | null> {
  const config = parseHaDatabaseConfig(env);
  if (!config) return null;
  if (featureMode("ha", env) !== "full") throw new Error(requireFeature("ha", env) ?? "High availability needs an enterprise license.");
  if (options.schema) await setHaSchema(config, options.schema, "create");
  const pool = createHaPool(config, options.schema ? { schema: options.schema } : {});
  try {
    return { pool, label: config.label, migrated: await runMigrations(pool) };
  } catch (error) {
    await pool.end().catch(() => undefined);
    throw error;
  }
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
  const opened = await openPool(env, options);
  if (!opened) return null;
  // PostgresSessionStore has the same shape as SessionStore. This assignment is the compile-time proof.
  const store: SessionStore = new PostgresSessionStore(opened.pool, { ownsPool: true });
  return { store, label: opened.label, migrated: opened.migrated };
}

export interface HaJobsHandle {
  queue: JobQueue;
  /** A worker on this queue. The caller starts it and stops it on shutdown. */
  createWorker(options: Omit<JobWorkerOptions, "queue">): JobWorker;
  label: string;
  migrated: number[];
  close(): Promise<void>;
}

/** Open the durable job queue in the shared database the environment names, or null when none is named. */
export async function openHaJobs(env: NodeJS.ProcessEnv = process.env, options: { schema?: string } = {}): Promise<HaJobsHandle | null> {
  const opened = await openPool(env, options);
  if (!opened) return null;
  const queue = new PostgresJobQueue(opened.pool);
  return {
    queue,
    createWorker: workerOptions => new JobWorker({ ...workerOptions, queue }),
    label: opened.label,
    migrated: opened.migrated,
    close: () => opened.pool.end(),
  };
}
