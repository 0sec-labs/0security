import { describe, expect, it, vi } from "vitest";

vi.mock("@0/engine/storage", async importOriginal => {
  const actual = await importOriginal<typeof import("@0/engine/storage")>();
  return {
    ...actual,
    verifyAuditLog: () => ({ ok: false, rows: 4, unchainedRows: 0, checkpoints: 0, rotatedRows: 0, firstId: 1, lastId: 5, headHash: null, firstBreak: { id: 3, reason: "rows between id 1 and id 3 are missing" } }),
  };
});

const { runAuditVerify } = await import("../audit-log.js");

describe("0 config audit-verify on a broken chain", () => {
  it("names the first break and exits 1", () => {
    const out: string[] = []; let code = -1;
    runAuditVerify({}, { dbPath: ":memory:", out: line => out.push(line), err: () => {}, setExitCode: value => { code = value; } });
    expect(code).toBe(1);
    expect(out[0]).toBe("Audit log chain BROKEN at event 3: rows between id 1 and id 3 are missing.");
  });
});
