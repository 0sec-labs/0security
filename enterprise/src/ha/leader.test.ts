// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { randomInt } from "node:crypto";
import { EventEmitter } from "node:events";
import { afterAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { HA_DATABASE_URL_ENV, parseHaDatabaseConfig } from "./config.js";
import { LeaderElector } from "./leader.js";
import { createHaPool } from "./postgres.js";

/** A pool whose one lock is shared by every connection it hands out. A connection that is killed frees the lock. */
class FakeServer {
  holder: FakeClient | null = null;
  down = false;
  hang = false;
  clients: FakeClient[] = [];
  pool = { connect: async () => { if (this.down) throw new Error("connection refused"); const c = new FakeClient(this); this.clients.push(c); return c; } } as unknown as Pool;
}
class FakeClient extends EventEmitter {
  released = false;
  constructor(private server: FakeServer) { super(); }
  async query(sql: string) {
    if (this.server.hang) return new Promise(() => undefined);
    if (this.server.down || this.released) throw new Error("connection lost");
    if (sql.includes("pg_try_advisory_lock")) { const ok = this.server.holder === null || this.server.holder === this; if (ok) this.server.holder = this; return { rows: [{ ok }] }; }
    if (sql.includes("pg_advisory_unlock")) { if (this.server.holder === this) this.server.holder = null; return { rows: [{}] }; }
    return { rows: [{}] };
  }
  release(destroy?: boolean) { if (this.released) throw new Error("already released"); this.released = true; if (destroy && this.server.holder === this) this.server.holder = null; }
}

describe("LeaderElector against a fake server", () => {
  it("elects one of two replicas and hands over when the leader resigns", async () => {
    const server = new FakeServer();
    const a = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 20 });
    const b = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 20 });
    await a.tick(); await b.tick();
    expect([a.isLeader(), b.isLeader()]).toEqual([true, false]);
    await a.stop();
    expect(a.isLeader()).toBe(false);
    await b.tick();
    expect(b.isLeader()).toBe(true);
    await b.stop();
    expect(server.holder).toBeNull();
  });

  it("keeps leadership across rounds and reports each change once", async () => {
    const server = new FakeServer();
    const changes: boolean[] = [];
    const a = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 20, onChange: v => changes.push(v) });
    await a.tick(); await a.tick(); await a.tick();
    expect(changes).toEqual([true]);
    await a.stop();
    expect(changes).toEqual([true, false]);
  });

  it("gives up leadership when the connection drops, and takes it back when the database returns", async () => {
    const server = new FakeServer();
    const errors: unknown[] = [];
    const a = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 20, onError: e => errors.push(e) });
    await a.tick();
    expect(a.isLeader()).toBe(true);
    server.down = true;
    await a.tick();
    expect(a.isLeader()).toBe(false);
    expect(errors).toHaveLength(1);
    server.holder = null; // the server released the lock with the dead connection
    server.down = false;
    await a.tick();
    expect(a.isLeader()).toBe(true);
    await a.stop();
  });

  it("forgets leadership at once when the driver reports a connection error", async () => {
    const server = new FakeServer();
    const a = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 20 });
    await a.tick();
    server.clients[0]!.emit("error", new Error("terminated"));
    expect(a.isLeader()).toBe(false);
    await a.stop();
  });

  it("treats a database that stops answering as lost", async () => {
    const server = new FakeServer();
    const a = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 25 });
    await a.tick();
    server.hang = true;
    await a.tick();
    expect(a.isLeader()).toBe(false);
    await a.stop();
  });

  it("is never leader after stop, and rounds do not overlap", async () => {
    const server = new FakeServer();
    const a = new LeaderElector({ pool: server.pool, key: 1, intervalMs: 20 });
    const first = a.tick(); const second = a.tick();
    expect(second).toBe(first);
    await first;
    await a.stop();
    await a.tick();
    expect(a.isLeader()).toBe(false);
    expect(server.clients).toHaveLength(1);
  });

  it("refuses a bad key or interval", () => {
    const server = new FakeServer();
    expect(() => new LeaderElector({ pool: server.pool, key: 0 })).toThrow(/key/);
    expect(() => new LeaderElector({ pool: server.pool, key: 1, intervalMs: 1 })).toThrow(/interval/);
  });
});

const URL_UNDER_TEST = process.env.ZERO_TEST_POSTGRES_URL;

describe.skipIf(!URL_UNDER_TEST)("LeaderElector on PostgreSQL (needs ZERO_TEST_POSTGRES_URL)", () => {
  const config = URL_UNDER_TEST ? parseHaDatabaseConfig({ [HA_DATABASE_URL_ENV]: URL_UNDER_TEST })! : (null as never);
  const pools: Pool[] = [];
  const replica = () => { const pool = createHaPool(config, { max: 3 }); pools.push(pool); return pool; };
  afterAll(async () => { await Promise.all(pools.map(pool => pool.end().catch(() => undefined))); });
  // Advisory locks are server-wide, so each test takes its own key.
  const key = () => 800_000_000 + randomInt(1_000_000_000);

  it("elects exactly one of five replicas, and another takes over when the leader's connection is killed", async () => {
    const k = key();
    const electors = Array.from({ length: 5 }, () => new LeaderElector({ pool: replica(), key: k, intervalMs: 50 }));
    await Promise.all(electors.map(e => e.tick()));
    expect(electors.filter(e => e.isLeader())).toHaveLength(1);
    const leader = electors.find(e => e.isLeader())!;
    // The server ends the leader's session, as it would when a replica or the network dies.
    const admin = replica();
    await admin.query("SELECT pg_terminate_backend(l.pid) FROM pg_locks l WHERE l.locktype = 'advisory' AND l.objid = $1::bigint::oid AND l.granted", [k]);
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && (leader.isLeader() || electors.filter(e => e.isLeader()).length !== 1)) {
      await Promise.all(electors.map(e => e.tick()));
      await new Promise(r => setTimeout(r, 30));
    }
    expect(electors.filter(e => e.isLeader())).toHaveLength(1);
    await Promise.all(electors.map(e => e.stop()));
  });

  it("frees the lock on stop so the next replica leads at once", async () => {
    const k = key();
    const a = new LeaderElector({ pool: replica(), key: k, intervalMs: 50 });
    const b = new LeaderElector({ pool: replica(), key: k, intervalMs: 50 });
    await a.tick(); await b.tick();
    expect([a.isLeader(), b.isLeader()]).toEqual([true, false]);
    await a.stop();
    await b.tick();
    expect(b.isLeader()).toBe(true);
    await b.stop();
  });
});
