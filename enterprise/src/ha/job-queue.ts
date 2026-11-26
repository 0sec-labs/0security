// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// A durable job queue in the shared database. Any replica may enqueue. A replica takes one job with
// FOR UPDATE SKIP LOCKED, so two replicas never run the same job at once. The claim sets an owner and a
// lease. A running job renews its lease. A job whose lease lapsed returns to the queue. All times come
// from the database clock, so replicas with different clocks agree.
import type { Pool } from "pg";

export interface Job {
  id: string;
  kind: string;
  payload: unknown;
  /** Counts this claim, so the first run has attempts 1. */
  attempts: number;
  maxAttempts: number;
}

export interface EnqueueOptions {
  kind: string;
  payload?: unknown;
  /** While a job with the same kind and key is queued or running, a second enqueue returns that job. */
  dedupeKey?: string;
  /** Wait this long before the job may run. */
  delayMs?: number;
  maxAttempts?: number;
}

export type FailOutcome = "retry" | "dead" | "lost";

export interface QueueStats { queued: number; running: number; done: number; dead: number }

/** The operations a worker needs. The Postgres queue implements it; tests give workers an in-memory one. */
export interface JobQueue {
  enqueue(options: EnqueueOptions): Promise<{ id: string; created: boolean }>;
  claim(owner: string, options: { kinds?: readonly string[]; leaseMs: number }): Promise<Job | null>;
  /** False when this owner no longer holds the job. */
  renew(id: string, owner: string, leaseMs: number): Promise<boolean>;
  complete(id: string, owner: string): Promise<boolean>;
  /** Record a failure. The job runs again after `retryDelayMs` unless it used its attempts. */
  fail(id: string, owner: string, error: string, retryDelayMs: number): Promise<FailOutcome>;
  /** Put a running job back without counting the attempt. Used when a replica stops. */
  release(id: string, owner: string): Promise<boolean>;
  /** Return jobs whose lease lapsed to the queue, or to dead when they used their attempts. */
  requeueExpired(): Promise<{ requeued: number; dead: number }>;
  /** Delete finished jobs older than the age. */
  purge(olderThanMs: number): Promise<number>;
  stats(): Promise<QueueStats>;
}

export const MAX_JOB_KIND = 100;
export const MAX_DEDUPE_KEY = 200;
export const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_ERROR = 500;
const KIND = /^[a-z0-9][a-z0-9._:-]*$/i;

export class JobQueueError extends Error {
  override readonly name = "JobQueueError";
}

function validate(options: EnqueueOptions): { payload: string; maxAttempts: number; delayMs: number } {
  if (!KIND.test(options.kind) || options.kind.length > MAX_JOB_KIND) throw new JobQueueError("The job kind must be letters, digits and . _ : -, up to 100 characters.");
  if (options.dedupeKey !== undefined && (options.dedupeKey === "" || options.dedupeKey.length > MAX_DEDUPE_KEY)) throw new JobQueueError("The dedupe key must be 1 to 200 characters.");
  const maxAttempts = options.maxAttempts ?? 5;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 100) throw new JobQueueError("maxAttempts must be a whole number from 1 to 100.");
  const delayMs = options.delayMs ?? 0;
  if (!Number.isFinite(delayMs) || delayMs < 0 || delayMs > 365 * 86_400_000) throw new JobQueueError("delayMs must be between 0 and one year.");
  const payload = JSON.stringify(options.payload ?? {});
  if (payload === undefined || Buffer.byteLength(payload) > MAX_PAYLOAD_BYTES) throw new JobQueueError("The job payload must be JSON of 64 KB or less.");
  return { payload, maxAttempts, delayMs: Math.floor(delayMs) };
}

const clip = (text: string): string => (text.length > MAX_ERROR ? `${text.slice(0, MAX_ERROR)}...` : text);
const positive = (value: number, name: string): number => {
  if (!Number.isFinite(value) || value < 1) throw new JobQueueError(`${name} must be at least 1 millisecond.`);
  return Math.floor(value);
};

interface JobRow { id: string; kind: string; payload: unknown; attempts: number; max_attempts: number }
const toJob = (row: JobRow): Job => ({ id: String(row.id), kind: row.kind, payload: row.payload, attempts: Number(row.attempts), maxAttempts: Number(row.max_attempts) });

export class PostgresJobQueue implements JobQueue {
  readonly #pool: Pool;
  constructor(pool: Pool) { this.#pool = pool; }

  async enqueue(options: EnqueueOptions): Promise<{ id: string; created: boolean }> {
    const { payload, maxAttempts, delayMs } = validate(options);
    const insert = async (): Promise<string | null> => {
      const result = await this.#pool.query(
        `INSERT INTO zero_ha_jobs (kind, payload, dedupe_key, max_attempts, run_after)
         VALUES ($1, $2::jsonb, $3, $4, now() + $5 * interval '1 millisecond')
         ON CONFLICT (kind, dedupe_key) WHERE dedupe_key IS NOT NULL AND status IN ('queued', 'running') DO NOTHING
         RETURNING id`,
        [options.kind, payload, options.dedupeKey ?? null, maxAttempts, delayMs],
      );
      return result.rows[0] ? String(result.rows[0].id) : null;
    };
    const first = await insert();
    if (first) return { id: first, created: true };
    // The open job with this key may finish between the insert and the read, so look, then insert again.
    for (let attempt = 0; attempt < 3; attempt++) {
      const existing = await this.#pool.query("SELECT id FROM zero_ha_jobs WHERE kind = $1 AND dedupe_key = $2 AND status IN ('queued', 'running')", [options.kind, options.dedupeKey]);
      if (existing.rows[0]) return { id: String(existing.rows[0].id), created: false };
      const again = await insert();
      if (again) return { id: again, created: true };
    }
    throw new JobQueueError("Could not enqueue the job because of a conflict that kept changing.");
  }

  async claim(owner: string, options: { kinds?: readonly string[]; leaseMs: number }): Promise<Job | null> {
    const leaseMs = positive(options.leaseMs, "leaseMs");
    const result = await this.#pool.query(
      `WITH next AS (
         SELECT id FROM zero_ha_jobs
         WHERE status = 'queued' AND run_after <= now() AND ($3::text[] IS NULL OR kind = ANY($3::text[]))
         ORDER BY run_after, id
         FOR UPDATE SKIP LOCKED
         LIMIT 1
       )
       UPDATE zero_ha_jobs j
       SET status = 'running', owner = $1, attempts = j.attempts + 1,
           lease_expires_at = now() + $2 * interval '1 millisecond', updated_at = now()
       FROM next WHERE j.id = next.id
       RETURNING j.id, j.kind, j.payload, j.attempts, j.max_attempts`,
      [owner, leaseMs, options.kinds ? [...options.kinds] : null],
    );
    return result.rows[0] ? toJob(result.rows[0]) : null;
  }

  async renew(id: string, owner: string, leaseMs: number): Promise<boolean> {
    const result = await this.#pool.query(
      "UPDATE zero_ha_jobs SET lease_expires_at = now() + $3 * interval '1 millisecond', updated_at = now() WHERE id = $1 AND owner = $2 AND status = 'running' AND lease_expires_at > now()",
      [id, owner, positive(leaseMs, "leaseMs")],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async complete(id: string, owner: string): Promise<boolean> {
    const result = await this.#pool.query(
      "UPDATE zero_ha_jobs SET status = 'done', owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = now(), finished_at = now() WHERE id = $1 AND owner = $2 AND status = 'running'",
      [id, owner],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async fail(id: string, owner: string, error: string, retryDelayMs: number): Promise<FailOutcome> {
    const delay = Math.max(0, Math.floor(retryDelayMs));
    const result = await this.#pool.query(
      `UPDATE zero_ha_jobs SET
         status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
         run_after = CASE WHEN attempts >= max_attempts THEN run_after ELSE now() + $4 * interval '1 millisecond' END,
         finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
         owner = NULL, lease_expires_at = NULL, last_error = $3, updated_at = now()
       WHERE id = $1 AND owner = $2 AND status = 'running'
       RETURNING status`,
      [id, owner, clip(error), delay],
    );
    const row = result.rows[0];
    if (!row) return "lost";
    return row.status === "dead" ? "dead" : "retry";
  }

  async release(id: string, owner: string): Promise<boolean> {
    const result = await this.#pool.query(
      "UPDATE zero_ha_jobs SET status = 'queued', owner = NULL, lease_expires_at = NULL, attempts = GREATEST(attempts - 1, 0), run_after = now(), updated_at = now() WHERE id = $1 AND owner = $2 AND status = 'running'",
      [id, owner],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async requeueExpired(): Promise<{ requeued: number; dead: number }> {
    // The lease lapsed, so the owner is gone or stuck. The attempt it started counts against the job.
    const result = await this.#pool.query(
      `WITH lapsed AS (
         SELECT id FROM zero_ha_jobs WHERE status = 'running' AND lease_expires_at <= now() FOR UPDATE SKIP LOCKED
       )
       UPDATE zero_ha_jobs j SET
         status = CASE WHEN j.attempts >= j.max_attempts THEN 'dead' ELSE 'queued' END,
         run_after = now(),
         finished_at = CASE WHEN j.attempts >= j.max_attempts THEN now() ELSE NULL END,
         owner = NULL, lease_expires_at = NULL, last_error = 'The worker stopped renewing the job.', updated_at = now()
       FROM lapsed WHERE j.id = lapsed.id
       RETURNING j.status`,
    );
    const dead = result.rows.filter(row => row.status === "dead").length;
    return { requeued: result.rows.length - dead, dead };
  }

  async purge(olderThanMs: number): Promise<number> {
    const result = await this.#pool.query(
      "DELETE FROM zero_ha_jobs WHERE status IN ('done', 'dead') AND finished_at < now() - $1 * interval '1 millisecond'",
      [Math.max(0, Math.floor(olderThanMs))],
    );
    return result.rowCount ?? 0;
  }

  async stats(): Promise<QueueStats> {
    const result = await this.#pool.query("SELECT status, COUNT(*) AS n FROM zero_ha_jobs GROUP BY status");
    const stats: QueueStats = { queued: 0, running: 0, done: 0, dead: 0 };
    for (const row of result.rows) if (row.status in stats) stats[row.status as keyof QueueStats] = Number(row.n);
    return stats;
  }
}
