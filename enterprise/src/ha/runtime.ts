// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// What one server replica runs against the shared database: the job queue, a worker factory and the
// election for the scheduler role. The server asks this object whether it leads and shuts it down once.
import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { PostgresJobQueue, type JobQueue } from "./job-queue.js";
import { JobWorker, type JobWorkerOptions } from "./job-worker.js";
import { LEADER_KEYS, LeaderElector } from "./leader.js";

const PROBE_TIMEOUT_MS = 2_000;

export interface DrainResult {
  /** Jobs that finished while the replica drained. */
  finished: number;
  /** Jobs still running at the deadline, returned to the queue for another replica. */
  released: number;
}

export interface HaRuntimeOptions {
  /** Where the database is, safe to print. */
  label: string;
  migrated: number[];
  /** Names this replica in job owners. Defaults to a random id. */
  instanceId?: string;
  leaderIntervalMs?: number;
  /** How often to check that the database answers. */
  healthIntervalMs?: number;
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
  readonly #healthIntervalMs: number;
  #health = { ok: true, at: Date.now() };
  #healthTimer: ReturnType<typeof setInterval> | undefined;
  #probing = false;
  #closed = false;
  #draining: Promise<DrainResult> | undefined;

  constructor(pool: Pool, options: HaRuntimeOptions) {
    this.#pool = pool;
    this.label = options.label;
    this.migrated = options.migrated;
    this.instanceId = options.instanceId ?? `replica-${randomUUID()}`;
    this.queue = new PostgresJobQueue(pool);
    this.#onError = options.onError;
    this.#healthIntervalMs = options.healthIntervalMs ?? 2_000;
    if (this.#healthIntervalMs < 20) throw new Error("The health interval must be at least 20 milliseconds.");
    this.#scheduler = new LeaderElector({
      pool,
      key: options.schedulerKey ?? LEADER_KEYS.scheduler,
      ...(options.leaderIntervalMs ? { intervalMs: options.leaderIntervalMs } : {}),
      ...(options.onLeaderChange ? { onChange: options.onLeaderChange } : {}),
      ...(options.onError ? { onError: options.onError } : {}),
    });
  }

  /** Begin the health checks and the election. Resolves after the first round. */
  async start(): Promise<void> {
    if (this.#healthTimer || this.#closed) return;
    this.#healthTimer = setInterval(() => void this.#probe(), this.#healthIntervalMs);
    this.#healthTimer.unref();
    await this.#probe();
    await this.#scheduler.start();
  }

  /**
   * Whether the database answered the last check, and the check is recent. It answers from memory, so a
   * readiness probe returns at once even when the database hangs. A check that stops completing counts as a failure.
   */
  healthy(): boolean {
    return !this.#closed && !this.#draining && this.#health.ok && Date.now() - this.#health.at <= this.#healthIntervalMs * 3 + PROBE_TIMEOUT_MS;
  }

  async #probe(): Promise<void> {
    if (this.#probing || this.#closed) return;
    this.#probing = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      // Reading the migration table proves the connection, the credentials and the schema.
      await Promise.race([
        this.#pool.query("SELECT MAX(version) AS v FROM zero_schema_migrations"),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("The shared database did not answer in time.")), PROBE_TIMEOUT_MS); }),
      ]);
      this.#health = { ok: true, at: Date.now() };
    } catch (error) {
      if (this.#health.ok) this.#onError?.(error);
      this.#health = { ok: false, at: Date.now() };
    } finally { clearTimeout(timer); this.#probing = false; }
  }

  /** True while this replica holds the scheduler lock. Gate work that must run on one replica at a time. */
  isLeader(): boolean { return this.#scheduler.isLeader(); }

  createWorker(options: Omit<JobWorkerOptions, "queue" | "owner"> & { owner?: string }): JobWorker {
    const worker = new JobWorker({ onError: this.#onError, ...options, owner: options.owner ?? this.instanceId, queue: this.queue });
    this.#workers.add(worker);
    return worker;
  }

  /**
   * Leave the cluster without dropping work. Resign leadership first, so another replica takes the scheduler
   * role while this one finishes. Then stop claiming jobs, wait up to `graceMs` for the running ones, and
   * return the rest to the queue without using an attempt. After this, `healthy()` is false. Calling it again
   * returns the first result.
   */
  drain(options: { graceMs: number }): Promise<DrainResult> {
    this.#draining ??= (async () => {
      await this.#scheduler.stop();
      const results = await Promise.all([...this.#workers].map(worker => worker.stop(options.graceMs)));
      return { finished: results.reduce((n, r) => n + r.finished, 0), released: results.reduce((n, r) => n + r.released, 0) };
    })();
    return this.#draining;
  }

  /** Resign leadership, stop the workers, then close the pool. Safe to call twice. */
  async close(options: { graceMs?: number } = {}): Promise<void> {
    this.#closed = true;
    if (this.#healthTimer) clearInterval(this.#healthTimer);
    await this.#scheduler.stop();
    await Promise.all([...this.#workers].map(worker => worker.stop(options.graceMs ?? 0)));
    this.#workers.clear();
    await this.#pool.end().catch(() => undefined);
  }
}
