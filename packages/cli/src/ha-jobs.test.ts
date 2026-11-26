// The job queue is opened through the bridge, as the server opens it. The Postgres run needs ZERO_TEST_POSTGRES_URL
// and a throwaway `ha` license made in the test.
import { randomBytes } from "node:crypto";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { dropTestSchema, openHaJobs, openHaRuntime } from "./ha-bridge.js";
import { applyTestLicense } from "./web/__fixtures__/test-license.js";

const POSTGRES_URL = process.env.ZERO_TEST_POSTGRES_URL;
const restores: Array<() => void> = [];
afterEach(() => { for (const restore of restores.splice(0)) restore(); });

describe("job queue gate", () => {
  it("names no database, so no queue opens", async () => {
    expect(await openHaJobs({})).toBeNull();
    expect(await openHaRuntime({})).toBeNull();
  });

  it("refuses a named database for the runtime when the license lacks the feature", async () => {
    restores.push(applyTestLicense(["rbac"]));
    await expect(openHaRuntime({ ...process.env, ZERO_HA_DATABASE_URL: "postgres://u:p@127.0.0.1:1/zero" })).rejects.toThrow(/high availability/i);
  });

  it("refuses a named database when the license lacks the feature", async () => {
    restores.push(applyTestLicense(["rbac"]));
    await expect(openHaJobs({ ...process.env, ZERO_HA_DATABASE_URL: "postgres://u:p@127.0.0.1:1/zero" })).rejects.toThrow(/high availability/i);
  });
});

describe.skipIf(!POSTGRES_URL)("job queue through the bridge (needs ZERO_TEST_POSTGRES_URL)", () => {
  const schema = `t_${randomBytes(6).toString("hex")}`;
  const env = () => ({ ...process.env, ZERO_HA_DATABASE_URL: POSTGRES_URL! });
  afterAll(async () => { await dropTestSchema(env(), schema); });

  it("runs an enqueued job on a worker", async () => {
    restores.push(applyTestLicense(["ha"]));
    const jobs = (await openHaJobs(env(), { schema }))!;
    try {
      const seen: unknown[] = [];
      const worker = jobs.createWorker({ owner: "test", pollMs: 20, handlers: { ping: async job => { seen.push(job.payload); } } });
      await jobs.queue.enqueue({ kind: "ping", payload: { ok: true } });
      worker.start();
      const end = Date.now() + 5000;
      while (seen.length === 0 && Date.now() < end) await new Promise(r => setTimeout(r, 20));
      expect(await worker.stop(500)).toEqual({ finished: 0, released: 0 });
      expect(seen).toEqual([{ ok: true }]);
      expect(await jobs.queue.stats()).toMatchObject({ done: 1, queued: 0 });
    } finally { await jobs.close(); }
  });

  it("elects one leader among replicas and passes the role on when the leader closes", async () => {
    restores.push(applyTestLicense(["ha"]));
    const key = 900_000_000 + Math.floor(Math.random() * 1_000_000_000);
    const open = async () => (await openHaRuntime(env(), { schema, schedulerKey: key, leaderIntervalMs: 40 }))!;
    const a = await open(); const b = await open(); const c = await open();
    try {
      await Promise.all([a.start(), b.start(), c.start()]);
      const replicas = [a, b, c];
      expect(replicas.filter(r => r.isLeader())).toHaveLength(1);
      const leader = replicas.find(r => r.isLeader())!;
      await leader.close();
      const rest = replicas.filter(r => r !== leader);
      const end = Date.now() + 5000;
      while (rest.filter(r => r.isLeader()).length !== 1 && Date.now() < end) await new Promise(r => setTimeout(r, 20));
      expect(rest.filter(r => r.isLeader())).toHaveLength(1);
    } finally { await Promise.all([a, b, c].map(r => r.close())); }
  });

  it("reports unhealthy when the schema is gone, so readiness can drop the replica", async () => {
    restores.push(applyTestLicense(["ha"]));
    const own = `t_${randomBytes(6).toString("hex")}`;
    const r = (await openHaRuntime(env(), { schema: own, schedulerKey: 900_000_000 + Math.floor(Math.random() * 1_000_000_000), healthIntervalMs: 50, leaderIntervalMs: 200 }))!;
    try {
      await r.start();
      expect(r.healthy()).toBe(true);
      await dropTestSchema(env(), own);
      const end = Date.now() + 5000;
      while (r.healthy() && Date.now() < end) await new Promise(res => setTimeout(res, 20));
      expect(r.healthy()).toBe(false);
    } finally { await r.close(); }
  });

  it("drains: finishes quick jobs, returns slow ones for another replica, and hands over the scheduler role", async () => {
    restores.push(applyTestLicense(["ha"]));
    const own = `t_${randomBytes(6).toString("hex")}`;
    const key = 900_000_000 + Math.floor(Math.random() * 1_000_000_000);
    const open = async () => (await openHaRuntime(env(), { schema: own, schedulerKey: key, leaderIntervalMs: 40, healthIntervalMs: 100 }))!;
    const a = await open();
    const b = await open();
    try {
      await a.start();
      expect(a.isLeader()).toBe(true);
      await b.start();
      expect(b.isLeader()).toBe(false);
      const ran: string[] = [];
      const hang = (name: string) => async (_job: { id: string }, { signal }: { signal: AbortSignal }) => { ran.push(name); await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve())); };
      const workerA = a.createWorker({ pollMs: 20, handlers: { quick: async () => { await new Promise(r => setTimeout(r, 30)); }, slow: hang("a") } });
      workerA.start();
      const quick = await a.queue.enqueue({ kind: "quick" });
      const slow = await a.queue.enqueue({ kind: "slow" });
      const end = Date.now() + 5000;
      while ((await a.queue.stats()).running < 1 && Date.now() < end) await new Promise(r => setTimeout(r, 20));
      while (!ran.includes("a") && Date.now() < end) await new Promise(r => setTimeout(r, 20));
      const drained = await a.drain({ graceMs: 100 });
      expect(drained.released).toBe(1);
      expect(drained.finished).toBeLessThanOrEqual(1);
      expect(a.isLeader()).toBe(false);
      expect(a.healthy()).toBe(false);
      expect(await a.queue.stats()).toMatchObject({ done: 1, queued: 1, running: 0 });
      // The other replica now leads and runs the returned job, from its first attempt.
      const workerB = b.createWorker({ pollMs: 20, handlers: { slow: async job => { ran.push(`b${job.attempts}`); } } });
      workerB.start();
      while (!ran.includes("b1") && Date.now() < end) await new Promise(r => setTimeout(r, 20));
      expect(ran).toContain("b1");
      while (!b.isLeader() && Date.now() < end) await new Promise(r => setTimeout(r, 20));
      expect(b.isLeader()).toBe(true);
      expect(quick.id).not.toBe(slow.id);
    } finally { await Promise.all([a.close(), b.close()]); }
  });
});
