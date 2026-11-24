import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeAuditLog, recordAudit } from "@0/engine/storage";
import { runAuditVerify } from "../audit-log.js";

const dirs: string[] = [];
afterEach(() => { closeAuditLog(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function setup(count: number) {
  const dir = mkdtempSync(join(tmpdir(), "zero-audit-verify-")); dirs.push(dir);
  const dbPath = join(dir, "audit.db");
  for (let i = 0; i < count; i++) recordAudit({ actor: "cli", action: `a.${i}` }, { dbPath });
  return dbPath;
}
function run(dbPath: string, json = false) {
  const out: string[] = []; const err: string[] = []; let code = -1;
  runAuditVerify({ json }, { dbPath, out: line => out.push(line), err: line => err.push(line), setExitCode: value => { code = value; } });
  return { out, err, code };
}

describe("0 config audit-verify", () => {
  it("reports an intact chain with exit 0", () => {
    const { out, code } = run(setup(4));
    expect(code).toBe(0);
    expect(out[0]).toBe("Audit log chain intact: 4 chained events, ids 1 to 4.");
    expect(out.join("\n")).toMatch(/Head hash: [0-9a-f]{64}/);
  });

  it("prints JSON", () => {
    const { out, code } = run(setup(2), true);
    expect(code).toBe(0);
    expect(JSON.parse(out.join("\n"))).toMatchObject({ ok: true, rows: 2 });
  });
});
