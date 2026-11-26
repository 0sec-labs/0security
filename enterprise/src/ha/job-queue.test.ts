// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { randomBytes } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { HA_DATABASE_URL_ENV, parseHaDatabaseConfig } from "./config.js";
import { JobQueueError, PostgresJobQueue, type EnqueueOptions, type FailOutcome, type Job, type JobQueue, type QueueStats } from "./job-queue.js";
import { JobWorker } from "./job-worker.js";
import { runMigrations } from "./migrate.js";
import { createHaPool, setHaSchema } from "./postgres.js";

/** A queue in memory with a clock the test moves. It follows the same rules as the Postgres queue. */
export class FakeJobQueue implements JobQueue {
  now = 1_000_000;
  #next = 1;
  jobs: Array<Job & { status: "queued" | "running" | "done" | "dead"; owner?: string; leaseUntil?: number; runAfter: number; dedupeKey?: string; lastError?: string }> = [];
  async enqueue(o: EnqueueOptions) {
    const open = o.dedupeKey === undefined ? undefined : this.jobs.find(j => j.kind === o.kind && j.dedupeKey === o.dedupeKey && (j.status === "queued" || j.status === "running"));
    if (open) return { id: open.id, created: false };
    const id = String(this.#next++);
    this.jobs.push({ id, kind: o.kind, payload: o.payload ?? {}, attempts: 0, maxAttempts: o.maxAttempts ?? 5, status: "queued", runAfter: this.now + (o.delayMs ?? 0), ...(o.dedupeKey ? { dedupeKey: o.dedupeKey } : {}) });
    return { id, created: true };
  }
  async claim(owner: string, o: { kinds?: readonly string[]; leaseMs: number }) {
    const job = this.jobs.filter(j => j.status === "queued" && j.runAfter <= this.now && (!o.kinds || o.kinds.includes(j.kind))).sort((a, b) => a.runAfter - b.runAfter || Number(a.id) - Number(b.id))[0];
    if (!job) return null;
    Object.assign(job, { status: "running", owner, attempts: job.attempts + 1, leaseUntil: this.now + o.leaseMs });
    return { id: job.id, kind: job.kind, payload: job.payload, attempts: job.attempts, maxAttempts: job.maxAttempts };
  }
  #mine(id: string, owner: string) { return this.jobs.find(j => j.id === id && j.owner === owner && j.status === "running"); }
  async renew(id: string, owner: string, leaseMs: number) { const j = this.#mine(id, owner); if (!j || (j.leaseUntil ?? 0) <= this.now) return false; j.leaseUntil = this.now + leaseMs; return true; }
  async complete(id: string, owner: string) { const j = this.#mine(id, owner); if (!j) return false; j.status = "done"; delete j.owner; return true; }
  async fail(id: string, owner: string, error: string, delay: number): Promise<FailOutcome> {
    const j = this.#mine(id, owner); if (!j) return "lost";
    j.lastError = error; delete j.owner;
    if (j.attempts >= j.maxAttempts) { j.status = "dead"; return "dead"; }
    j.status = "queued"; j.runAfter = this.now + delay; return "retry";
  }
  async release(id: string, owner: string) { const j = this.#mine(id, owner); if (!j) return false; Object.assign(j, { status: "queued", attempts: Math.max(0, j.attempts - 1), runAfter: this.now }); delete j.owner; return true; }
  async requeueExpired() {
    let requeued = 0, dead = 0;
    for (const j of this.jobs) if (j.status === "running" && (j.leaseUntil ?? 0) <= this.now) { delete j.owner; if (j.attempts >= j.maxAttempts) { j.status = "dead"; dead++; } else { j.status = "queued"; requeued++; } }
    return { requeued, dead };
  }
  async purge() { return 0; }
  async stats(): Promise<QueueStats> { const s = { queued: 0, running: 0, done: 0, dead: 0 }; for (const j of this.jobs) s[j.status]++; return s; }
}

const until = async (check: () => boolean, ms = 3000) => { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error("timed out"); await new Promise(r => setTimeout(r, 10)); } };

describe("JobWorker with an in-memory queue", () => {
  it("runs a job once and marks it done", async () => {
    const queue = new FakeJobQueue();
    const seen: unknown[] = [];
    const worker = new JobWorker({ queue, owner: "a", pollMs: 10, handlers: { echo: async job => { seen.push(job.payload); } } });
    await queue.enqueue({ kind: "echo", payload: { n: 1 } });
    worker.start();
    await until(() => queue.jobs[0]!.status === "done");
    await worker.stop(100);
    expect(seen).toEqual([{ n: 1 }]);
  });

  it("claims only kinds it has a handler for", async () => {
    const queue = new FakeJobQueue();
    const worker = new JobWorker({ queue, owner: "a", pollMs: 10, handlers: { known: async () => undefined } });
    await queue.enqueue({ kind: "other" });
    worker.start();
    await new Promise(r => setTimeout(r, 50));
    await worker.stop(100);
    expect(queue.jobs[0]!.status).toBe("queued");
  });

  it("retries a failing job and marks it dead after its attempts", async () => {
    const queue = new FakeJobQueue();
    let calls = 0;
    const worker = new JobWorker({ queue, owner: "a", pollMs: 5, retryDelayMs: () => 0, handlers: { bad: async () => { calls++; throw new Error("boom"); } } });
    await queue.enqueue({ kind: "bad", maxAttempts: 3 });
    worker.start();
    await until(() => queue.jobs[0]!.status === "dead");
    await worker.stop(100);
    expect(calls).toBe(3);
    expect(queue.jobs[0]!.lastError).toBe("boom");
  });

  it("limits how many jobs run at once", async () => {
    const queue = new FakeJobQueue();
    let running = 0, peak = 0;
    const worker = new JobWorker({ queue, owner: "a", pollMs: 5, concurrency: 2, handlers: { slow: async () => { running++; peak = Math.max(peak, running); await new Promise(r => setTimeout(r, 30)); running--; } } });
    for (let i = 0; i < 6; i++) await queue.enqueue({ kind: "slow" });
    worker.start();
    await until(() => queue.jobs.every(j => j.status === "done"));
    await worker.stop(100);
    expect(peak).toBe(2);
  });

  it("aborts the handler and drops the result when the lease is lost", async () => {
    const queue = new FakeJobQueue();
    let aborted = false;
    const worker = new JobWorker({
      queue, owner: "a", pollMs: 5, leaseMs: 60, concurrency: 1,
      handlers: { long: (_job, { signal }) => new Promise<void>(resolve => { signal.addEventListener("abort", () => { aborted = true; resolve(); }); }) },
    });
    await queue.enqueue({ kind: "long" });
    worker.start();
    await until(() => queue.jobs[0]!.status === "running");
    // Another replica's reaper takes the job after the lease lapsed.
    queue.now += 10_000;
    await queue.requeueExpired();
    await until(() => aborted);
    // The aborted run must not mark the job done. The worker may already have claimed it again.
    expect(queue.jobs[0]!.status).not.toBe("done");
    await worker.stop(50);
  });

  it("stop waits for a job that finishes within the grace period", async () => {
    const queue = new FakeJobQueue();
    const worker = new JobWorker({ queue, owner: "a", pollMs: 5, handlers: { quick: async () => { await new Promise(r => setTimeout(r, 40)); } } });
    await queue.enqueue({ kind: "quick" });
    worker.start();
    await until(() => worker.active === 1);
    expect(await worker.stop(2000)).toEqual({ finished: 1, released: 0 });
    expect(queue.jobs[0]!.status).toBe("done");
  });

  it("stop returns a job that outlives the grace period without using an attempt", async () => {
    const queue = new FakeJobQueue();
    const worker = new JobWorker({ queue, owner: "a", pollMs: 5, handlers: { hang: (_job, { signal }) => new Promise<void>(resolve => signal.addEventListener("abort", () => resolve())) } });
    await queue.enqueue({ kind: "hang" });
    worker.start();
    await until(() => worker.active === 1);
    expect(await worker.stop(20)).toEqual({ finished: 0, released: 1 });
    expect(queue.jobs[0]).toMatchObject({ status: "queued", attempts: 0 });
    expect(worker.state).toBe("stopped");
  });

  it("needs a handler", () => {
    expect(() => new JobWorker({ queue: new FakeJobQueue(), owner: "a", handlers: {} })).toThrow(/handler/);
  });
});

const URL_UNDER_TEST = process.env.ZERO_TEST_POSTGRES_URL;

describe.skipIf(!URL_UNDER_TEST)("PostgresJobQueue (needs ZERO_TEST_POSTGRES_URL)", () => {
  const config = URL_UNDER_TEST ? parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: URL_UNDER_TEST })! : (null as never);
  const schemas: string[] = [];
  const fresh = async () => {
    const schema = `t_${randomBytes(6).toString("hex")}`;
    schemas.push(schema);
    await setHaSchema(config, schema, "create");
    const pool = createHaPool(config, { schema, max: 12 });
    await runMigrations(pool);
    return { pool, queue: new PostgresJobQueue(pool) };
  };
  afterAll(async () => { for (const schema of schemas.splice(0)) await setHaSchema(config, schema, "drop"); });

  it("hands each job to exactly one of many competing claimers", async () => {
    const { pool, queue } = await fresh();
    try {
      for (let i = 0; i < 40; i++) await queue.enqueue({ kind: "work", payload: { i } });
      const taken: string[][] = await Promise.all(Array.from({ length: 8 }, async (_, w) => {
        const mine: string[] = [];
        for (;;) { const job = await queue.claim(`replica-${w}`, { leaseMs: 30_000 }); if (!job) return mine; mine.push(job.id); }
      }));
      const all = taken.flat();
      expect(all).toHaveLength(40);
      expect(new Set(all).size).toBe(40);
      expect(await queue.stats()).toMatchObject({ queued: 0, running: 40 });
    } finally { await pool.end(); }
  });

  it("returns the open job for a repeated dedupe key and allows a new one after it finishes", async () => {
    const { pool, queue } = await fresh();
    try {
      const first = await queue.enqueue({ kind: "scan", dedupeKey: "repo-1" });
      const again = await queue.enqueue({ kind: "scan", dedupeKey: "repo-1" });
      expect(first.created).toBe(true);
      expect(again).toEqual({ id: first.id, created: false });
      expect((await queue.enqueue({ kind: "other", dedupeKey: "repo-1" })).created).toBe(true);
      const concurrent = await Promise.all(Array.from({ length: 10 }, () => queue.enqueue({ kind: "scan", dedupeKey: "repo-2" })));
      expect(concurrent.filter(r => r.created)).toHaveLength(1);
      const job = (await queue.claim("a", { kinds: ["scan"], leaseMs: 1000 }))!;
      await queue.complete(job.id, "a");
      expect((await queue.enqueue({ kind: "scan", dedupeKey: "repo-1" })).created).toBe(true);
    } finally { await pool.end(); }
  });

  it("does not run a delayed job early and orders by due time", async () => {
    const { pool, queue } = await fresh();
    try {
      await queue.enqueue({ kind: "k", delayMs: 60_000 });
      expect(await queue.claim("a", { leaseMs: 1000 })).toBeNull();
      const now = await queue.enqueue({ kind: "k", payload: "now" });
      expect((await queue.claim("a", { leaseMs: 1000 }))?.id).toBe(now.id);
    } finally { await pool.end(); }
  });

  it("returns a job whose lease lapsed, and lets only the new owner finish it", async () => {
    const { pool, queue } = await fresh();
    try {
      await queue.enqueue({ kind: "k" });
      const job = (await queue.claim("dead-replica", { leaseMs: 30 }))!;
      await new Promise(r => setTimeout(r, 80));
      expect(await queue.renew(job.id, "dead-replica", 1000)).toBe(false);
      expect(await queue.requeueExpired()).toEqual({ requeued: 1, dead: 0 });
      const again = (await queue.claim("live-replica", { leaseMs: 5000 }))!;
      expect(again).toMatchObject({ id: job.id, attempts: 2 });
      expect(await queue.complete(job.id, "dead-replica")).toBe(false);
      expect(await queue.renew(job.id, "live-replica", 5000)).toBe(true);
      expect(await queue.complete(job.id, "live-replica")).toBe(true);
    } finally { await pool.end(); }
  });

  it("marks a job dead when its attempts are used, by failure or by lapsed lease", async () => {
    const { pool, queue } = await fresh();
    try {
      await queue.enqueue({ kind: "f", maxAttempts: 2 });
      const a = (await queue.claim("a", { leaseMs: 1000 }))!;
      expect(await queue.fail(a.id, "a", "first", 0)).toBe("retry");
      const b = (await queue.claim("a", { leaseMs: 1000 }))!;
      expect(await queue.fail(b.id, "a", "second", 0)).toBe("dead");
      expect(await queue.fail(b.id, "a", "again", 0)).toBe("lost");
      await queue.enqueue({ kind: "l", maxAttempts: 1 });
      await queue.claim("a", { leaseMs: 20 });
      await new Promise(r => setTimeout(r, 60));
      expect(await queue.requeueExpired()).toEqual({ requeued: 0, dead: 1 });
      expect(await queue.stats()).toMatchObject({ dead: 2, queued: 0, running: 0 });
    } finally { await pool.end(); }
  });

  it("release puts a job back without using an attempt", async () => {
    const { pool, queue } = await fresh();
    try {
      await queue.enqueue({ kind: "k" });
      const job = (await queue.claim("a", { leaseMs: 5000 }))!;
      expect(await queue.release(job.id, "b")).toBe(false);
      expect(await queue.release(job.id, "a")).toBe(true);
      expect((await queue.claim("b", { leaseMs: 5000 }))).toMatchObject({ id: job.id, attempts: 1 });
    } finally { await pool.end(); }
  });

  it("purges finished jobs by age and keeps open ones", async () => {
    const { pool, queue } = await fresh();
    try {
      await queue.enqueue({ kind: "k" });
      await queue.enqueue({ kind: "k" });
      const job = (await queue.claim("a", { leaseMs: 5000 }))!;
      await queue.complete(job.id, "a");
      await new Promise(r => setTimeout(r, 30));
      expect(await queue.purge(86_400_000)).toBe(0);
      expect(await queue.purge(10)).toBe(1);
      expect(await queue.stats()).toMatchObject({ queued: 1, done: 0 });
    } finally { await pool.end(); }
  });

  it("refuses a bad kind, key, size or attempt count", async () => {
    const { pool, queue } = await fresh();
    try {
      await expect(queue.enqueue({ kind: "bad kind!" })).rejects.toBeInstanceOf(JobQueueError);
      await expect(queue.enqueue({ kind: "k", dedupeKey: "" })).rejects.toBeInstanceOf(JobQueueError);
      await expect(queue.enqueue({ kind: "k", payload: "x".repeat(70_000) })).rejects.toBeInstanceOf(JobQueueError);
      await expect(queue.enqueue({ kind: "k", maxAttempts: 0 })).rejects.toBeInstanceOf(JobQueueError);
    } finally { await pool.end(); }
  });

  it("runs jobs from several workers on one queue, each once", async () => {
    const { pool, queue } = await fresh();
    try {
      const ran: string[] = [];
      const workers = ["a", "b", "c"].map(owner => new JobWorker({ queue, owner, pollMs: 20, concurrency: 3, handlers: { t: async job => { ran.push(job.id); await new Promise(r => setTimeout(r, 10)); } } }));
      for (let i = 0; i < 30; i++) await queue.enqueue({ kind: "t" });
      workers.forEach(w => w.start());
      await until(() => ran.length >= 30, 8000);
      await Promise.all(workers.map(w => w.stop(1000)));
      expect(new Set(ran).size).toBe(30);
      expect(ran).toHaveLength(30);
      expect(await queue.stats()).toMatchObject({ done: 30, queued: 0, running: 0 });
    } finally { await pool.end(); }
  });
});
