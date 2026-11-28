import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { osecDB } from "./database.js";
import { createShimmedDatabase } from "./wasm-shim.js";

describe("ordinary database open preserves existing storage", () => {
  it.each([false, true])("rejects unsupported WAL without modifying header or sidecars (readOnly=%s)", readOnly => {
    const dir = mkdtempSync(join(tmpdir(), "0-wal-preserve-"));
    const path = join(dir, "test.db");
    try {
      const db = createShimmedDatabase(path);
      db.exec("CREATE TABLE retained (value TEXT)");
      db.close();
      const header = readFileSync(path);
      header[18] = header[19] = 2;
      writeFileSync(path, header);
      writeFileSync(`${path}-wal`, "committed WAL evidence");
      writeFileSync(`${path}-shm`, "shared memory evidence");
      const before = [path, `${path}-wal`, `${path}-shm`].map(file => readFileSync(file));
      expect(() => new osecDB(path, { readOnly })).toThrow(/native SQLite connection to checkpoint/);
      expect([path, `${path}-wal`, `${path}-shm`].map(file => readFileSync(file))).toEqual(before);
      expect(readdirSync(dir).sort()).toEqual(["test.db", "test.db-shm", "test.db-wal"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("does not remove an old lock held by a live transaction", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-live-lock-"));
    const path = join(dir, "test.db");
    const writer = createShimmedDatabase(path);
    try {
      writer.exec("CREATE TABLE retained (value TEXT); BEGIN IMMEDIATE; INSERT INTO retained VALUES ('pending')");
      const old = new Date(Date.now() - 60_000);
      utimesSync(`${path}.lock`, old, old);
      expect(() => new osecDB(path)).toThrow(/locked/);
      expect(existsSync(`${path}.lock`)).toBe(true);
      writer.exec("COMMIT");
      expect(writer.prepare("SELECT value FROM retained").all()).toEqual([{ value: "pending" }]);
    } finally { writer.close(); rmSync(dir, { recursive: true, force: true }); }
  });

  it("reports malformed storage without backing it up and recreating an empty database", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-malformed-preserve-"));
    const path = join(dir, "test.db");
    try {
      const bytes = Buffer.from("malformed but valuable operator evidence");
      writeFileSync(path, bytes);
      expect(() => new osecDB(path)).toThrow();
      expect(readFileSync(path)).toEqual(bytes);
      expect(readdirSync(dir)).toEqual(["test.db"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("names the stale lock of a killed process and says to keep the journal", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-stale-lock-"));
    const path = join(dir, "test.db");
    try {
      createShimmedDatabase(path).close();
      // What a kill -9 during a write leaves: the lock directory of the VFS and a journal.
      mkdirSync(`${path}.lock`);
      writeFileSync(`${path}-journal`, "interrupted write");
      let message = "";
      try { new osecDB(path); } catch (error) { message = (error as Error).message; }
      expect(message).toMatch(/database is locked/);
      expect(message).toContain(`${path}.lock`);
      expect(message).toMatch(/keep .*-journal/);
      expect(message).toMatch(/own HOME/);
      expect(existsSync(`${path}.lock`)).toBe(true);
      expect(readFileSync(`${path}-journal`, "utf8")).toBe("interrupted write");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("explains a damaged database and leaves it in place", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-damaged-hint-"));
    const path = join(dir, "test.db");
    try {
      const writer = createShimmedDatabase(path);
      writer.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)");
      writer.transaction(() => { for (let i = 0; i < 400; i++) writer.prepare("INSERT INTO t (v) VALUES (?)").run("x".repeat(500)); })();
      writer.close();
      // A copy taken while another process was writing: pages from two moments.
      const bytes = readFileSync(path);
      bytes.fill(0xff, 4096 * 5, 4096 * 6);
      writeFileSync(path, bytes);
      let message = "";
      try { new osecDB(path); } catch (error) { message = (error as Error).message; }
      expect(message).toContain(path);
      expect(message).toMatch(/copied while a 0 process was using it/);
      expect(message).toMatch(/move .* aside together/);
      expect(readFileSync(path)).toEqual(bytes);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
