import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { auditCheckpointHashAt, closeAuditLog, planAuditPrune, pruneAuditLog, queryAuditChainRows, recordAudit, verifyAuditLog } from "./audit-log.js";
import { checkAuditChainFile, formatAuditChainFile } from "./audit-chain-file.js";

const dirs: string[] = [];
const fresh = () => { const dir = mkdtempSync(join(tmpdir(), "zero-audit-file-")); dirs.push(dir); return { dbPath: join(dir, "audit.db") }; };
afterEach(() => { closeAuditLog(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const day = (n: number) => `2026-01-${String(n).padStart(2, "0")}T10:00:00.000Z`;
const fill = (target: { dbPath: string }, n: number) => { for (let i = 1; i <= n; i++) recordAudit({ actor: "cli", action: `a.${i}`, ts: day(i) }, target); };
const mutate = (text: string, fn: (lines: Array<Record<string, unknown>>) => void) => {
  const lines = text.trim().split("\n").map(line => JSON.parse(line) as Record<string, unknown>);
  fn(lines);
  return `${lines.map(line => JSON.stringify(line)).join("\n")}\n`;
};

describe("chain file", () => {
  it("verifies an export and finds an edited, removed, reordered or cut-off row", () => {
    const target = fresh(); fill(target, 6);
    const text = formatAuditChainFile(queryAuditChainRows({}, target), "2026-02-01T00:00:00.000Z");
    expect(checkAuditChainFile(text)).toMatchObject({ ok: true, rows: 6, firstId: 1, lastId: 6 });

    expect(checkAuditChainFile(mutate(text, l => { l[2]!.actor = "someone else"; })).firstBreak).toMatchObject({ id: 3, reason: "row content does not match its hash" });
    expect(checkAuditChainFile(mutate(text, l => { l.splice(2, 1); })).firstBreak).toMatchObject({ id: 4 });
    expect(checkAuditChainFile(mutate(text, l => { [l[1], l[2]] = [l[2]!, l[1]!]; })).ok).toBe(false);
    expect(checkAuditChainFile(mutate(text, l => { l.splice(4, 2); })).firstBreak?.reason).toMatch(/trailer does not match/);
    expect(checkAuditChainFile(text.split("\n").slice(0, 3).join("\n")).firstBreak?.reason).toMatch(/trailer line is missing/);
    expect(checkAuditChainFile("").ok).toBe(false);
    expect(checkAuditChainFile("not json\n").ok).toBe(false);
  });

  it("verifies a time-range slice from the middle of the log", () => {
    const target = fresh(); fill(target, 6);
    const rows = queryAuditChainRows({ since: day(3), until: day(5) }, target);
    expect(rows.map(r => r.id)).toEqual([3, 4]);
    expect(checkAuditChainFile(formatAuditChainFile(rows, "x"))).toMatchObject({ ok: true, rows: 2, firstId: 3 });
  });
});

describe("retention", () => {
  it("archives old rows, removes them, and keeps both the live log and the archive verifiable", () => {
    const target = fresh(); fill(target, 8);
    let archived = "";
    const result = pruneAuditLog(day(5), rows => { archived = formatAuditChainFile(rows, "x"); }, target);
    expect(result).toMatchObject({ pruned: 4, throughId: 4 });
    expect(verifyAuditLog(target)).toMatchObject({ ok: true, rows: 4, firstId: 5, checkpoints: 1, rotatedRows: 4 });
    const report = checkAuditChainFile(archived);
    expect(report).toMatchObject({ ok: true, rows: 4, lastId: 4 });
    expect(auditCheckpointHashAt(4, target)).toBe(report.headHash);
    // new events keep chaining after the prune
    recordAudit({ actor: "cli", action: "after", ts: day(20) }, target);
    expect(verifyAuditLog(target).ok).toBe(true);
  });

  it("removes nothing when the archive step fails", () => {
    const target = fresh(); fill(target, 6);
    expect(() => pruneAuditLog(day(4), () => { throw new Error("disk full"); }, target)).toThrow("disk full");
    expect(verifyAuditLog(target)).toMatchObject({ ok: true, rows: 6, checkpoints: 0 });
  });

  it("always keeps the newest row and stops at the first row that is not old enough", () => {
    const target = fresh(); fill(target, 5);
    expect(planAuditPrune("2099-01-01T00:00:00.000Z", target).map(r => r.id)).toEqual([1, 2, 3, 4]);
    expect(planAuditPrune("2000-01-01T00:00:00.000Z", target)).toEqual([]);
  });

  it("two prunes chain their checkpoints", () => {
    const target = fresh(); fill(target, 9);
    pruneAuditLog(day(3), () => undefined, target);
    pruneAuditLog(day(7), () => undefined, target);
    expect(verifyAuditLog(target)).toMatchObject({ ok: true, rows: 3, checkpoints: 2, rotatedRows: 6 });
  });
});
