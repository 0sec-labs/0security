// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { afterEach, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { HaRuntime } from "./runtime.js";

/** A pool that answers, fails or hangs on demand. */
function fakePool() {
  const state = { mode: "ok" as "ok" | "fail" | "hang", queries: 0 };
  const pool = {
    query: async () => { state.queries++; if (state.mode === "hang") return new Promise(() => undefined); if (state.mode === "fail") throw new Error("connection refused"); return { rows: [{ v: 2 }] }; },
    connect: async () => ({ on: () => undefined, query: async () => ({ rows: [{ ok: true }] }), release: () => undefined }),
    end: async () => undefined,
  } as unknown as Pool;
  return { pool, state };
}
const wait = (ms: number) => new Promise(r => setTimeout(r, ms));
const open: HaRuntime[] = [];
afterEach(async () => { for (const r of open.splice(0)) await r.close(); });
const runtime = (pool: Pool, errors: unknown[] = []) => { const r = new HaRuntime(pool, { label: "db/zero", migrated: [], healthIntervalMs: 20, leaderIntervalMs: 50, onError: e => errors.push(e) }); open.push(r); return r; };

describe("HaRuntime health", () => {
  it("is healthy after the first check and answers from memory", async () => {
    const { pool, state } = fakePool();
    const r = runtime(pool);
    await r.start();
    expect(r.healthy()).toBe(true);
    const before = state.queries;
    for (let i = 0; i < 1000; i++) r.healthy();
    expect(state.queries).toBe(before);
  });

  it("turns unhealthy when the database fails, reports it once, and recovers", async () => {
    const { pool, state } = fakePool();
    const errors: unknown[] = [];
    const r = runtime(pool, errors);
    await r.start();
    state.mode = "fail";
    await wait(80);
    expect(r.healthy()).toBe(false);
    await wait(60);
    expect(errors.filter(e => (e as Error).message === "connection refused")).toHaveLength(1);
    state.mode = "ok";
    await wait(80);
    expect(r.healthy()).toBe(true);
  });

  it("turns unhealthy when the database stops answering", async () => {
    const { pool, state } = fakePool();
    const r = runtime(pool);
    await r.start();
    state.mode = "hang";
    // The check times out at 2 s; the stale result expires at 3 intervals plus that timeout.
    await wait(2_300);
    expect(r.healthy()).toBe(false);
  }, 10_000);

  it("is unhealthy after close", async () => {
    const { pool } = fakePool();
    const r = runtime(pool);
    await r.start();
    await r.close();
    expect(r.healthy()).toBe(false);
  });

  it("refuses a very short health interval", () => {
    expect(() => new HaRuntime(fakePool().pool, { label: "x", migrated: [], healthIntervalMs: 1 })).toThrow(/health interval/);
  });
});

describe("HaRuntime drain", () => {
  it("resigns leadership, turns unready and returns the same result when called twice", async () => {
    const { pool } = fakePool();
    const changes: boolean[] = [];
    const r = new HaRuntime(pool, { label: "db/zero", migrated: [], healthIntervalMs: 20, leaderIntervalMs: 50, onLeaderChange: v => changes.push(v) });
    open.push(r);
    await r.start();
    expect(r.isLeader()).toBe(true);
    const first = r.drain({ graceMs: 10 });
    expect(r.drain({ graceMs: 10 })).toBe(first);
    expect(await first).toEqual({ finished: 0, released: 0 });
    expect(r.isLeader()).toBe(false);
    expect(r.healthy()).toBe(false);
    expect(changes).toEqual([true, false]);
  });
});
