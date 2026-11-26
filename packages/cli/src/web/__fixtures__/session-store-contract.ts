import { describe, expect, it } from "vitest";
import type { SessionStore } from "@0/engine/storage";

export interface SessionStoreHarness {
  /** A store on the shared storage. Calling it twice gives two handles on the same data, like two replicas. */
  open(): Promise<SessionStore>;
}

const NOW = 1_800_000_000_000;
const HOUR = 3_600_000;

/** One behaviour suite for every SessionStore. Add a backend by passing a harness. */
export function sessionStoreContract(name: string, harness: () => Promise<SessionStoreHarness>, skip = false): void {
  const suite = skip ? describe.skip : describe;
  suite(`SessionStore contract: ${name}`, () => {
    const opened: SessionStore[] = [];
    const open = async (h: SessionStoreHarness) => { const store = await h.open(); opened.push(store); return store; };
    const fresh = async () => { const h = await harness(); return { h, a: await open(h) }; };

    it("returns what it stored", async () => {
      const { a } = await fresh();
      await a.create({ id: "cookie-1", userId: "alex", expiresAt: NOW + HOUR }, NOW);
      expect(await a.get("cookie-1", NOW + 1)).toEqual({ id: "cookie-1", userId: "alex", createdAt: NOW, expiresAt: NOW + HOUR });
    });

    it("keeps a role fixed at sign-in", async () => {
      const { a } = await fresh();
      await a.create({ id: "cookie-r", userId: "sam", role: "viewer", expiresAt: NOW + HOUR }, NOW);
      expect((await a.get("cookie-r", NOW))?.role).toBe("viewer");
    });

    it("returns null for an unknown id", async () => {
      const { a } = await fresh();
      expect(await a.get("nobody", NOW)).toBeNull();
    });

    it("treats a session as expired at its expiry time and removes it", async () => {
      const { a } = await fresh();
      await a.create({ id: "short", userId: "alex", expiresAt: NOW + 1000 }, NOW);
      expect(await a.get("short", NOW + 999)).not.toBeNull();
      expect(await a.get("short", NOW + 1000)).toBeNull();
      expect(await a.deleteExpired(NOW + HOUR)).toBe(0);
    });

    it("refuses a second session with the same id and keeps the first", async () => {
      const { a } = await fresh();
      await a.create({ id: "dup", userId: "alex", expiresAt: NOW + HOUR }, NOW);
      await expect(a.create({ id: "dup", userId: "mallory", expiresAt: NOW + HOUR }, NOW)).rejects.toMatchObject({ name: "SessionConflictError" });
      expect((await a.get("dup", NOW))?.userId).toBe("alex");
    });

    it("deletes one session and reports whether it existed", async () => {
      const { a } = await fresh();
      await a.create({ id: "gone", userId: "alex", expiresAt: NOW + HOUR }, NOW);
      expect(await a.delete("gone")).toBe(true);
      expect(await a.delete("gone")).toBe(false);
      expect(await a.get("gone", NOW)).toBeNull();
    });

    it("deletes every session of one account only", async () => {
      const { a } = await fresh();
      for (const id of ["a1", "a2"]) await a.create({ id, userId: "alex", expiresAt: NOW + HOUR }, NOW);
      await a.create({ id: "b1", userId: "sam", expiresAt: NOW + HOUR }, NOW);
      expect(await a.deleteForUser("alex")).toBe(2);
      expect(await a.get("a1", NOW)).toBeNull();
      expect(await a.get("b1", NOW)).not.toBeNull();
      expect(await a.deleteForUser("alex")).toBe(0);
    });

    it("drops a fixed role but keeps the session", async () => {
      const { a } = await fresh();
      await a.create({ id: "s1", userId: "alex", role: "owner", expiresAt: NOW + HOUR }, NOW);
      await a.create({ id: "s2", userId: "alex", expiresAt: NOW + HOUR }, NOW);
      await a.create({ id: "s3", userId: "sam", role: "editor", expiresAt: NOW + HOUR }, NOW);
      expect(await a.clearRoleForUser("alex")).toBe(1);
      expect((await a.get("s1", NOW))).toMatchObject({ userId: "alex" });
      expect((await a.get("s1", NOW))?.role).toBeUndefined();
      expect((await a.get("s3", NOW))?.role).toBe("editor");
    });

    it("counts live sessions and removes expired ones in bulk", async () => {
      const { a } = await fresh();
      await a.create({ id: "old1", userId: "alex", expiresAt: NOW + 10 }, NOW);
      await a.create({ id: "old2", userId: "alex", expiresAt: NOW + 20 }, NOW);
      await a.create({ id: "live", userId: "alex", expiresAt: NOW + HOUR }, NOW);
      expect(await a.count(NOW + 30)).toBe(1);
      expect(await a.deleteExpired(NOW + 30)).toBe(2);
      expect(await a.count(NOW + 30)).toBe(1);
    });

    it("shares sessions between two handles, like two replicas", async () => {
      const { h, a } = await fresh();
      const b = await open(h);
      await a.create({ id: "shared", userId: "alex", expiresAt: NOW + HOUR }, NOW);
      expect((await b.get("shared", NOW))?.userId).toBe("alex");
      expect(await b.delete("shared")).toBe(true);
      expect(await a.get("shared", NOW)).toBeNull();
    });

    it("lets exactly one of two racing handles create the same id", async () => {
      const { h, a } = await fresh();
      const b = await open(h);
      const results = await Promise.allSettled([
        a.create({ id: "race", userId: "alex", expiresAt: NOW + HOUR }, NOW),
        b.create({ id: "race", userId: "sam", expiresAt: NOW + HOUR }, NOW),
      ]);
      expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
      expect(results.filter(result => result.status === "rejected")).toHaveLength(1);
    });
  });
}
