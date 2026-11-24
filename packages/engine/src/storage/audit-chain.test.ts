import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeAuditLog, listAudit, recordAudit, verifyAuditLog } from "./audit-log.js";
import { createShimmedDatabase } from "./wasm-shim.js";

const dirs: string[] = [];
const fresh = () => { const dir = mkdtempSync(join(tmpdir(), "zero-audit-chain-")); dirs.push(dir); return { dbPath: join(dir, "audit.db") }; };
afterEach(() => { closeAuditLog(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const rawDb = (target: { dbPath: string }) => { closeAuditLog(); return createShimmedDatabase(target.dbPath); };
const fill = (target: { dbPath: string; maxRows?: number }, n: number) => {
  for (let i = 0; i < n; i++) recordAudit({ actor: "system", action: `a.${i}`, subject: `s${i}`, detail: { count: i } }, target);
};

describe("audit hash chain", () => {
  it("verifies an empty and an untouched log", () => {
    const target = fresh();
    expect(verifyAuditLog(target)).toMatchObject({ ok: true, rows: 0, headHash: null });
    fill(target, 5);
    const report = verifyAuditLog(target);
    expect(report).toMatchObject({ ok: true, rows: 5, unchainedRows: 0, firstId: 1, lastId: 5, firstBreak: null });
    expect(report.headHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("finds an edited row even if the attacker drops the update trigger", () => {
    const target = fresh();
    fill(target, 6);
    const db = rawDb(target);
    db.exec("DROP TRIGGER audit_events_no_update");
    db.prepare("UPDATE audit_events SET actor = 'someone else' WHERE id = 3").run();
    db.close();
    expect(verifyAuditLog(target)).toMatchObject({ ok: false, firstBreak: { id: 3, reason: "row content does not match its hash" } });
  });

  it("finds a removed middle row, a removed tail and a removed head", () => {
    const middle = fresh(); fill(middle, 6);
    let db = rawDb(middle); db.prepare("DELETE FROM audit_events WHERE id = 3").run(); db.close();
    expect(verifyAuditLog(middle).firstBreak).toMatchObject({ id: 4 });

    const tail = fresh(); fill(tail, 6);
    db = rawDb(tail); db.prepare("DELETE FROM audit_events WHERE id > 4").run(); db.close();
    expect(verifyAuditLog(tail)).toMatchObject({ ok: false, firstBreak: { reason: "rows after id 4 were removed" } });

    const head = fresh(); fill(head, 6);
    db = rawDb(head); db.prepare("DELETE FROM audit_events WHERE id < 3").run(); db.close();
    expect(verifyAuditLog(head)).toMatchObject({ ok: false, firstBreak: { id: 3 } });
  });

  it("finds a row appended without a valid link", () => {
    const target = fresh(); fill(target, 3);
    const db = rawDb(target);
    db.prepare("INSERT INTO audit_events (ts, actor, action, subject, outcome, detail_json, prev_hash, hash) VALUES ('2026-01-01T00:00:00.000Z','x','y','','ok','{}','00','11')").run();
    db.close();
    expect(verifyAuditLog(target)).toMatchObject({ ok: false, firstBreak: { id: 4 } });
  });

  it("keeps verifying across rotation and still finds tampering after it", () => {
    const target = { ...fresh(), maxRows: 5 };
    fill(target, 23);
    const report = verifyAuditLog(target);
    expect(report.ok).toBe(true);
    expect(report.checkpoints).toBeGreaterThan(0);
    expect(report.rotatedRows).toBeGreaterThan(0);
    expect(report.firstId).toBeGreaterThan(1);
    fill(target, 3);
    expect(verifyAuditLog(target).ok).toBe(true);
    const db = rawDb(target);
    db.exec("DROP TRIGGER audit_events_no_update");
    db.prepare("UPDATE audit_events SET subject = 'x' WHERE id = (SELECT MAX(id) - 1 FROM audit_events)").run();
    db.close();
    expect(verifyAuditLog(target).ok).toBe(false);
  });

  it("finds a forged rotation checkpoint", () => {
    const target = { ...fresh(), maxRows: 5 };
    fill(target, 12);
    const db = rawDb(target);
    db.exec("DROP TRIGGER audit_checkpoints_no_update");
    db.prepare("UPDATE audit_checkpoints SET through_hash = ?").run("ab".repeat(32));
    db.close();
    expect(verifyAuditLog(target).ok).toBe(false);
  });

  it("upgrades a log written before the chain and counts the old rows as unchained", () => {
    const target = fresh();
    const db = createShimmedDatabase(target.dbPath);
    db.exec("CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, outcome TEXT NOT NULL, detail_json TEXT NOT NULL)");
    db.prepare("INSERT INTO audit_events (ts, actor, action, subject, outcome, detail_json) VALUES ('2026-01-01T00:00:00.000Z','old','legacy','','ok','{}')").run();
    db.close();
    fill(target, 3);
    expect(verifyAuditLog(target)).toMatchObject({ ok: true, rows: 4, unchainedRows: 1 });
    expect(listAudit({}, target).events.map(e => e.action)).toContain("legacy");
  });
});
