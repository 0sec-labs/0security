import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CoverageLedger, coverageSentence, summarizeCoverage, type LedgerUnit } from "./coverage-ledger.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const open = () => { const dir = mkdtempSync(join(tmpdir(), "ledger-test-")); dirs.push(dir); return new CoverageLedger(join(dir, "db.sqlite")); };

const units = [
  { id: "a", kind: "http-route", path: "a.js", startLine: 3, name: "GET /a", batch: 0 },
  { id: "b", kind: "http-route", path: "b.js", startLine: 1, batch: 0 },
  { id: "c", kind: "exec", path: "c.js", startLine: 9, batch: 1 },
  { id: "o", kind: "other", path: "lib", name: "2 files", files: ["lib/x.js", "lib/y.js"], batch: 2 },
];

describe("CoverageLedger", () => {
  it("stores units, marks them, and survives a reopen", () => {
    const ledger = open();
    const scan = ledger.createScan({ folder: "/repo", label: "/repo", gitHead: "abc", batchSize: 8, budgetUsd: 5 }, units);
    expect(scan.id).toMatch(/^scan-[0-9a-f]{8}$/);
    expect(ledger.units(scan.id).map(unit => unit.status)).toEqual(["pending", "pending", "pending", "pending"]);
    ledger.mark(scan.id, ["a", "b"], { status: "reviewed", threadId: "t1" });
    ledger.mark(scan.id, ["c"], { status: "pending", reason: "budget" });
    ledger.addSpend(scan.id, 0.25);
    ledger.addThread(scan.id, "t1");
    ledger.addThread(scan.id, "t2");
    ledger.addThread(scan.id, "t1");
    expect(ledger.getScan(scan.id)?.threadIds).toEqual(["t1", "t2"]);
    expect(ledger.units(scan.id, "reviewed").map(unit => [unit.unitId, unit.threadId])).toEqual([["a", "t1"], ["b", "t1"]]);
    expect(ledger.units(scan.id).find(unit => unit.unitId === "o")?.files).toEqual(["lib/x.js", "lib/y.js"]);
    expect(ledger.getScan(scan.id)).toMatchObject({ gitHead: "abc", spentUsd: 0.25, budgetUsd: 5 });
    expect(ledger.latestScan("/repo")?.id).toBe(scan.id);
    expect(ledger.latestScan("/other")).toBeUndefined();
    ledger.close();
  });

  it("returns the newest scan of a folder", () => {
    const ledger = open();
    ledger.createScan({ folder: "/repo", label: "r", batchSize: 8, budgetUsd: 1 }, units, new Date("2026-01-01"));
    const second = ledger.createScan({ folder: "/repo", label: "r", batchSize: 8, budgetUsd: 1 }, units, new Date("2026-01-02"));
    expect(ledger.latestScan("/repo")?.id).toBe(second.id);
    expect(ledger.latestScan()?.id).toBe(second.id);
    ledger.close();
  });
});

describe("coverage summary", () => {
  const row = (unitId: string, kind: string, status: LedgerUnit["status"], reason?: string): LedgerUnit => ({ unitId, kind, path: unitId, batch: 0, status, updatedAt: "", ...(reason ? { reason } : {}) });
  it("says plainly how much was reviewed and why the rest was not", () => {
    const all = [...Array.from({ length: 41 }, (_, i) => row(`r${i}`, "http-route", "reviewed")), ...Array.from({ length: 16 }, (_, i) => row(`p${i}`, "exec", "pending", "budget"))];
    const summary = summarizeCoverage("s", all);
    expect(coverageSentence(summary)).toBe("reviewed 41 of 57 entry points; 16 not reached (budget)");
    expect(summary.complete).toBe(false);
    expect(summary.byKind["exec"]).toMatchObject({ total: 16, pending: 16 });
  });
  it("lists mixed reasons and unreached groups of other files, and is complete only with nothing pending", () => {
    const summary = summarizeCoverage("s", [row("a", "http-route", "reviewed"), row("b", "http-route", "pending", "budget"), row("c", "http-route", "pending", "thread failed"), row("d", "other", "pending", "budget")]);
    expect(coverageSentence(summary)).toBe("reviewed 1 of 3 entry points; 2 not reached (budget: 1, thread failed: 1); 0 of 1 groups of other files reviewed; 1 not reached");
    const done = summarizeCoverage("s", [row("a", "http-route", "reviewed"), row("o", "other", "reviewed")]);
    expect(done.complete).toBe(true);
    expect(coverageSentence(done)).toBe("reviewed 1 of 1 entry point; 1 of 1 groups of other files reviewed");
  });
});
