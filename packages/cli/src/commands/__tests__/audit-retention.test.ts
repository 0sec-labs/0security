import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeAuditLog, recordAudit, verifyAuditLog } from "@0/engine/storage";
import { runAuditExport, runAuditPrune, runAuditVerify, type AuditLicenseDeps } from "../audit-log.js";

const dirs: string[] = [];
afterEach(() => { closeAuditLog(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const day = (n: number) => `2026-01-${String(n).padStart(2, "0")}T10:00:00.000Z`;
function setup(count = 8) {
  const dir = mkdtempSync(join(tmpdir(), "zero-audit-ret-")); dirs.push(dir);
  const dbPath = join(dir, "audit.db");
  for (let i = 1; i <= count; i++) recordAudit({ actor: "cli", action: `a.${i}`, ts: day(i) }, { dbPath });
  return { dir, dbPath };
}
const full: AuditLicenseDeps["license"] = { proofRefusal: () => null, pruneRefusal: () => null };
// An expired license past grace: reads and exports keep working, writes stop.
const readOnly: AuditLicenseDeps["license"] = { proofRefusal: () => null, pruneRefusal: () => "Your 0security enterprise license expired on 2026-01-01. Retention policies is read-only until you renew." };
const none: AuditLicenseDeps["license"] = { proofRefusal: () => "The tamper-evident audit log needs an enterprise license.", pruneRefusal: () => "Retention policies needs an enterprise license." };

const io = () => { const out: string[] = []; const err: string[] = []; let code = -1; return { out, err, get code() { return code; }, deps: { out: (l: string) => out.push(l), err: (l: string) => err.push(l), setExitCode: (v: number) => { code = v; } } }; };
const now = () => new Date("2026-02-10T00:00:00.000Z");

describe("0 config audit-export --with-proof", () => {
  it("writes a chain file that audit-verify --file accepts", async () => {
    const { dir, dbPath } = setup();
    const file = join(dir, "proof.ndjson");
    const a = io();
    await runAuditExport({ withProof: true, output: file }, { dbPath, ...a.deps, license: full, now });
    expect(a.code).toBe(0);
    expect(a.err.join(" ")).toMatch(/Wrote 8 chained events with proof/);
    const b = io();
    runAuditVerify({ file }, { dbPath, ...b.deps });
    expect(b.code).toBe(0);
    expect(b.out[0]).toBe("Chain file intact: 8 chained events, ids 1 to 8.");
  });

  it("is refused without a license, and still works with an expired one", async () => {
    const { dbPath } = setup(3);
    const a = io();
    await runAuditExport({ withProof: true }, { dbPath, ...a.deps, license: none, now });
    expect(a.code).toBe(2);
    expect(a.err.join(" ")).toContain("needs an enterprise license");
    const b = io();
    await runAuditExport({ withProof: true }, { dbPath, ...b.deps, license: readOnly, now });
    expect(b.code).toBe(0);
    expect(b.out.join("\n").split("\n")).toHaveLength(4); // 3 rows and the trailer
  });

  it("refuses formats and filters that cannot carry a proof", async () => {
    const { dbPath } = setup(3);
    for (const options of [{ format: "cef" }, { type: ["a"] }, { follow: true }]) {
      const a = io();
      await runAuditExport({ withProof: true, ...options }, { dbPath, ...a.deps, license: full, now });
      expect(a.code).toBe(2);
    }
  });

  it("free exports are unchanged without a license", async () => {
    const { dbPath } = setup(3);
    const a = io();
    await runAuditExport({}, { dbPath, ...a.deps, license: none, now });
    expect(a.code).toBe(0);
    expect(a.out).toHaveLength(3);
  });
});

describe("0 config audit-verify --file", () => {
  it("names the first break of a tampered file and exits 1", async () => {
    const { dir, dbPath } = setup(4);
    const file = join(dir, "proof.ndjson");
    await runAuditExport({ withProof: true, output: file }, { dbPath, ...io().deps, license: full, now });
    writeFileSync(file, readFileSync(file, "utf8").replace('"actor":"cli"', '"actor":"mallory"'));
    const a = io();
    runAuditVerify({ file }, { dbPath, ...a.deps });
    expect(a.code).toBe(1);
    expect(a.out[0]).toBe("Chain file BROKEN at event 1: row content does not match its hash.");
  });

  it("exits 2 for a file that cannot be read", () => {
    const { dbPath } = setup(1);
    const a = io();
    runAuditVerify({ file: "/nonexistent/x.ndjson" }, { dbPath, ...a.deps });
    expect(a.code).toBe(2);
  });
});

describe("0 config audit-prune", () => {
  it("reports without --yes and changes nothing", () => {
    const { dir, dbPath } = setup();
    const a = io();
    runAuditPrune({ olderThan: "2026-01-05", archive: join(dir, "a.ndjson") }, { dbPath, ...a.deps, license: full, now });
    expect(a.code).toBe(0);
    expect(a.out[0]).toMatch(/^Would write 4 events \(ids 1 to 4\)/);
    expect(existsSync(join(dir, "a.ndjson"))).toBe(false);
    expect(verifyAuditLog({ dbPath }).rows).toBe(8);
  });

  it("archives, removes, and leaves a log and an archive that both verify", () => {
    const { dir, dbPath } = setup();
    const archive = join(dir, "a.ndjson");
    const a = io();
    runAuditPrune({ olderThan: "2026-01-05", archive, yes: true }, { dbPath, ...a.deps, license: full, now });
    expect(a.code).toBe(0);
    expect(a.out[0]).toBe(`Archived 4 events to ${archive} and removed them from the log.`);
    expect(verifyAuditLog({ dbPath })).toMatchObject({ ok: true, rows: 4, checkpoints: 1 });
    const b = io();
    runAuditVerify({ file: archive }, { dbPath, ...b.deps });
    expect(b.code).toBe(0);
    expect(b.out.join("\n")).toContain("the live log continues from this file");
  });

  it("never overwrites an archive and removes nothing in that case", () => {
    const { dir, dbPath } = setup();
    const archive = join(dir, "a.ndjson");
    writeFileSync(archive, "precious");
    const a = io();
    runAuditPrune({ olderThan: "2026-01-05", archive, yes: true }, { dbPath, ...a.deps, license: full, now });
    expect(a.code).toBe(2);
    expect(readFileSync(archive, "utf8")).toBe("precious");
    expect(verifyAuditLog({ dbPath }).rows).toBe(8);
  });

  it("is refused after the license expired (read-only) and without a license; the log is untouched", () => {
    const { dir, dbPath } = setup();
    for (const license of [readOnly, none]) {
      const a = io();
      runAuditPrune({ olderThan: "2026-01-05", archive: join(dir, "a.ndjson"), yes: true }, { dbPath, ...a.deps, license, now });
      expect(a.code).toBe(2);
    }
    expect(verifyAuditLog({ dbPath }).rows).toBe(8);
  });

  it("requires --older-than and --archive", () => {
    const { dbPath } = setup(2);
    const a = io();
    runAuditPrune({ archive: "x" }, { dbPath, ...a.deps, license: full, now });
    expect(a.code).toBe(2);
    const b = io();
    runAuditPrune({ olderThan: "1d" }, { dbPath, ...b.deps, license: full, now });
    expect(b.code).toBe(2);
  });
});
