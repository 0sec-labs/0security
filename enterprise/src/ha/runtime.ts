// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// What one server replica runs against the shared database: the job queue, a worker factory and the
// election for the scheduler role. The server asks this object whether it leads and shuts it down once.
import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { PostgresJobQueue, type JobQueue } from "./job-queue.js";
import { JobWorker, type JobWorkerOptions } from "./job-worker.js";
import { LEADER_KEYS, LeaderElector } from "./leader.js";

export interface HaRuntimeOptions {
  /** Where the database is, safe to print. */
  label: string;
  migrated: number[];
  /** Names this replica in job owners. Defaults to a random id. */
  instanceId?: string;
  leaderIntervalMs?: number;
  /** Tests use their own lock key so they do not contend with a running server. */
  schedulerKey?: number;
  onLeaderChange?: (leader: boolean) => void;
  onError?: (error: unknown) => void;
}

export class HaRuntime {
  readonly label: string;
  readonly migrated: number[];
  readonly instanceId: string;
  readonly queue: JobQueue;
  readonly #pool: Pool;
  readonly #scheduler: LeaderElector;
  readonly #workers = new Set<JobWorker>();
  readonly #onError: ((error: unknown) => void) | undefined;

  constructor(pool: Pool, options: HaRuntimeOptions) {
    this.#pool = pool;
    this.label = options.label;
    this.migrated = options.migrated;
    this.instanceId = options.instanceId ?? `replica-${randomUUID()}`;
    this.queue = new PostgresJobQueue(pool);
    this.#onError = options.onError;
    this.#scheduler = new LeaderElector({
      pool,
      key: options.schedulerKey ?? LEADER_KEYS.scheduler,
      ...(options.leaderIntervalMs ? { intervalMs: options.leaderIntervalMs } : {}),
      ...(options.onLeaderChange ? { onChange: options.onLeaderChange } : {}),
      ...(options.onError ? { onError: options.onError } : {}),
    });
  }

  /** Begin the election. Resolves after the first round. */
  start(): Promise<void> { return this.#scheduler.start(); }

  /** True while this replica holds the scheduler lock. Gate work that must run on one replica at a time. */
  isLeader(): boolean { return this.#scheduler.isLeader(); }

  createWorker(options: Omit<JobWorkerOptions, "queue" | "owner"> & { owner?: string }): JobWorker {
    const worker = new JobWorker({ onError: this.#onError, ...options, owner: options.owner ?? this.instanceId, queue: this.queue });
    this.#workers.add(worker);
    return worker;
  }

  /** Resign leadership, stop the workers, then close the pool. Safe to call twice. */
  async close(options: { graceMs?: number } = {}): Promise<void> {
    await this.#scheduler.stop();
    await Promise.all([...this.#workers].map(worker => worker.stop(options.graceMs ?? 0)));
    this.#workers.clear();
    await this.#pool.end().catch(() => undefined);
  }
}
