// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Runs jobs from a JobQueue on this replica. It claims up to `concurrency` jobs, renews each lease while
// the handler runs, and records the result. A handler that throws is retried with backoff until the job
// uses its attempts. If the lease is lost, the handler's signal aborts and the result is dropped, because
// another replica may already run the job.
import type { Job, JobQueue } from "./job-queue.js";

export type JobHandler = (job: Job, context: { signal: AbortSignal }) => Promise<void>;

export interface JobWorkerOptions {
  queue: JobQueue;
  /** Names this worker in the owner column. Unique per process. */
  owner: string;
  /** One handler per job kind. The worker claims only these kinds. */
  handlers: Readonly<Record<string, JobHandler>>;
  concurrency?: number;
  pollMs?: number;
  leaseMs?: number;
  /** How long to wait before a failed job runs again, from the attempt number. */
  retryDelayMs?: (attempt: number) => number;
  /** How often to return lapsed leases to the queue. */
  reapEveryMs?: number;
  onError?: (error: unknown) => void;
}

export interface StopResult {
  /** Jobs that finished while the worker waited. */
  finished: number;
  /** Jobs still running at the deadline, aborted and returned to the queue. */
  released: number;
}

const defaultRetryDelay = (attempt: number): number => Math.min(60_000, 1_000 * 2 ** Math.max(0, attempt - 1));

export class JobWorker {
  readonly #options: Required<Omit<JobWorkerOptions, "onError">> & Pick<JobWorkerOptions, "onError">;
  readonly #running = new Map<string, { controller: AbortController; done: Promise<void> }>();
  #timer: ReturnType<typeof setInterval> | undefined;
  #state: "idle" | "running" | "stopping" | "stopped" = "idle";
  #polling = false;
  #lastReap = 0;

  constructor(options: JobWorkerOptions) {
    const kinds = Object.keys(options.handlers);
    if (kinds.length === 0) throw new Error("A job worker needs at least one handler.");
    this.#options = {
      concurrency: 2,
      pollMs: 1_000,
      leaseMs: 30_000,
      reapEveryMs: 10_000,
      retryDelayMs: defaultRetryDelay,
      ...options,
    };
    if (!Number.isInteger(this.#options.concurrency) || this.#options.concurrency < 1) throw new Error("concurrency must be a whole number of at least 1.");
    if (this.#options.leaseMs < 3 * 10) throw new Error("leaseMs must be at least 30 milliseconds.");
  }

  get active(): number { return this.#running.size; }
  get state(): "idle" | "running" | "stopping" | "stopped" { return this.#state; }

  start(): void {
    if (this.#state !== "idle") return;
    this.#state = "running";
    this.#timer = setInterval(() => void this.poll(), this.#options.pollMs);
    this.#timer.unref();
    void this.poll();
  }

  /** Claim as many jobs as there is room for. Exposed so tests and a stopping server can drive it. */
  async poll(): Promise<void> {
    if (this.#state !== "running" || this.#polling) return;
    this.#polling = true;
    try {
      if (Date.now() - this.#lastReap >= this.#options.reapEveryMs) {
        this.#lastReap = Date.now();
        await this.#options.queue.requeueExpired();
      }
      const kinds = Object.keys(this.#options.handlers);
      while (this.#state === "running" && this.#running.size < this.#options.concurrency) {
        const job = await this.#options.queue.claim(this.#options.owner, { kinds, leaseMs: this.#options.leaseMs });
        if (!job) break;
        this.#run(job);
      }
    } catch (error) {
      this.#options.onError?.(error);
    } finally { this.#polling = false; }
  }

  #run(job: Job): void {
    const { queue, owner, leaseMs } = this.#options;
    const controller = new AbortController();
    let lost = false;
    const renewTimer = setInterval(() => {
      queue.renew(job.id, owner, leaseMs).then(
        held => { if (!held && !lost) { lost = true; controller.abort(); } },
        error => this.#options.onError?.(error),
      );
    }, Math.max(10, Math.floor(leaseMs / 3)));
    renewTimer.unref();
    const handler = this.#options.handlers[job.kind]!;
    const done = (async () => {
      let failure: unknown;
      try { await handler(job, { signal: controller.signal }); } catch (error) { failure = error ?? new Error("The job failed."); }
      clearInterval(renewTimer);
      // After an abort for a lost lease or a stop, the result is not ours to record.
      if (lost || controller.signal.aborted) return;
      try {
        if (failure === undefined) await queue.complete(job.id, owner);
        else await queue.fail(job.id, owner, failure instanceof Error ? failure.message : String(failure), this.#options.retryDelayMs(job.attempts));
      } catch (error) { this.#options.onError?.(error); }
    })().finally(() => { clearInterval(renewTimer); this.#running.delete(job.id); });
    this.#running.set(job.id, { controller, done });
  }

  /**
   * Stop claiming, wait up to `graceMs` for running jobs, then abort the rest and return them to the
   * queue without counting the attempt. Safe to call twice.
   */
  async stop(graceMs: number): Promise<StopResult> {
    if (this.#state === "stopped") return { finished: 0, released: 0 };
    this.#state = "stopping";
    if (this.#timer) clearInterval(this.#timer);
    const before = [...this.#running.keys()];
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<"expired">(resolve => { timeout = setTimeout(() => resolve("expired"), Math.max(0, graceMs)); });
    const settled = Promise.all([...this.#running.values()].map(entry => entry.done)).then(() => "settled" as const);
    const outcome = await Promise.race([settled, expired]);
    clearTimeout(timeout);
    let released = 0;
    if (outcome === "expired") {
      const leftover = [...this.#running.entries()];
      for (const [, entry] of leftover) entry.controller.abort();
      await Promise.all(leftover.map(async ([id]) => {
        try { if (await this.#options.queue.release(id, this.#options.owner)) released++; } catch (error) { this.#options.onError?.(error); }
      }));
      // A handler that ignores its signal must not hold the stop open.
      await Promise.race([Promise.all(leftover.map(([, entry]) => entry.done)), new Promise(resolve => setTimeout(resolve, 2_000).unref())]);
    }
    this.#state = "stopped";
    return { finished: before.length - released, released };
  }
}
