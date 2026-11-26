// One behaviour suite, run against SQLite always and against a real PostgreSQL server when
// ZERO_TEST_POSTGRES_URL names one. The Postgres run needs a throwaway `ha` license, made in the test.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { SqliteSessionStore } from "@0/engine/storage";
import { dropTestSchema, openHaSessionStore } from "./ha-bridge.js";
import { applyTestLicense } from "./web/__fixtures__/test-license.js";
import { sessionStoreContract, type SessionStoreHarness } from "./web/__fixtures__/session-store-contract.js";

const dirs: string[] = [];
afterAll(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

sessionStoreContract("SQLite", async () => {
  const dir = mkdtempSync(join(tmpdir(), "zero-session-store-"));
  dirs.push(dir);
  const path = join(dir, "0.db");
  return { open: async () => new SqliteSessionStore(path) };
});

describe("SQLite session store", () => {
  it("keeps sessions across a reopen and stores only a hash of the cookie value", async () => {
    const dir = mkdtempSync(join(tmpdir(), "zero-session-store-"));
    dirs.push(dir);
    const path = join(dir, "0.db");
    const secret = `cookie-${randomBytes(12).toString("hex")}`;
    const first = new SqliteSessionStore(path);
    await first.create({ id: secret, userId: "alex", expiresAt: Date.now() + 60_000 }, Date.now());
    await first.close();
    expect(readFileSync(path).includes(Buffer.from(secret))).toBe(false);
    const second = new SqliteSessionStore(path);
    expect((await second.get(secret, Date.now()))?.userId).toBe("alex");
    await second.close();
  });
});

const POSTGRES_URL = process.env.ZERO_TEST_POSTGRES_URL;

describe.skipIf(!POSTGRES_URL)("Postgres session store (needs ZERO_TEST_POSTGRES_URL)", () => {
  const schemas: string[] = [];
  const restores: Array<() => void> = [];
  const env = () => ({ ...process.env, ZERO_HA_DATABASE_URL: POSTGRES_URL! });
  afterAll(async () => {
    for (const schema of schemas.splice(0)) await dropTestSchema(env(), schema);
    for (const restore of restores.splice(0)) restore();
  });

  // The licensed store is opened through the bridge, as the server would open it.
  const harness = async (): Promise<SessionStoreHarness> => {
    restores.push(applyTestLicense(["ha"]));
    const schema = `t_${randomBytes(6).toString("hex")}`;
    schemas.push(schema);
    return { open: async () => (await openHaSessionStore(env(), { schema }))!.store };
  };
  sessionStoreContract("Postgres", harness, !POSTGRES_URL);
});

describe("shared database gate", () => {
  const restores: Array<() => void> = [];
  afterEach(() => { for (const restore of restores.splice(0)) restore(); });
  const url = "postgres://user:pw@127.0.0.1:1/zero";

  it("names no database, so the single-node store stays in use", async () => {
    expect(await openHaSessionStore({})).toBeNull();
  });

  it("refuses a named database without a license", async () => {
    const before = { l: process.env.ZERO_LICENSE, f: process.env.ZERO_LICENSE_FILE };
    delete process.env.ZERO_LICENSE; delete process.env.ZERO_LICENSE_FILE;
    try {
      await expect(openHaSessionStore({ ZERO_HA_DATABASE_URL: url })).rejects.toThrow(/enterprise license/i);
    } finally {
      if (before.l !== undefined) process.env.ZERO_LICENSE = before.l;
      if (before.f !== undefined) process.env.ZERO_LICENSE_FILE = before.f;
    }
  });

  it("refuses a license that lacks the feature", async () => {
    restores.push(applyTestLicense(["rbac"]));
    await expect(openHaSessionStore({ ...process.env, ZERO_HA_DATABASE_URL: url })).rejects.toThrow(/high availability/i);
  });

  it("refuses an expired license past its grace period", async () => {
    const past = new Date(Date.now() - 90 * 86_400_000).toISOString().replace(/\.\d+Z$/, "Z");
    const issued = new Date(Date.now() - 400 * 86_400_000).toISOString().replace(/\.\d+Z$/, "Z");
    restores.push(applyTestLicense(["ha"], { expires: past, issuedAt: issued }));
    await expect(openHaSessionStore({ ...process.env, ZERO_HA_DATABASE_URL: url })).rejects.toThrow(/expired/i);
  });

  it("with a license, fails on an unreachable database instead of falling back to SQLite", async () => {
    restores.push(applyTestLicense(["ha"]));
    await expect(openHaSessionStore({ ...process.env, ZERO_HA_DATABASE_URL: url })).rejects.toThrow();
  });
});
