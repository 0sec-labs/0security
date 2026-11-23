import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "../shared/index.js";
import { osecDB } from "./database.js";
import { parseFindingModelVerification } from "./finding-helpers.js";

const record = { verdict: "false-positive" as const, reasoning: "The query is parameterized at db.ts:12.", control: "db.ts:12", advisorySeverity: "info", model: "m", threadId: "t1", verifiedAt: "2026-11-22T00:00:00.000Z" };

describe("finding model verification", () => {
  it("is stored next to the finding and changes neither severity nor status", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-db-verify-"));
    const db = new osecDB(join(dir, "t.db"));
    try {
      const scanId = db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
      db.saveFinding(scanId, { id: "f-1", templateId: "t", title: "x", description: "d", severity: "high", category: "xss", status: "discovered", evidence: { request: "a", response: "b" }, timestamp: Date.now() } as Finding);
      expect(db.getFindingModelVerification("f-1")).toBeUndefined();
      db.setFindingModelVerification("f-1", record);
      expect(db.getFindingModelVerification("f-1")).toMatchObject(record);
      const row = db.listFindings({ limit: 10 })[0]!;
      expect(row.severity).toBe("high");
      expect(row.status).toBe("discovered");
      expect(row.triageStatus).toBe("new");
      expect(() => db.setFindingModelVerification("missing", record)).toThrow(/not found/);
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reads unusable stored text as absent", () => {
    expect(parseFindingModelVerification("not json")).toBeUndefined();
    expect(parseFindingModelVerification(JSON.stringify({ verdict: "maybe", reasoning: "r", verifiedAt: "x" }))).toBeUndefined();
    expect(parseFindingModelVerification(null)).toBeUndefined();
  });

  it("stores an acceptance with expiry and approver on the whole family, and does not carry a lapsed one onto a new scan", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-db-accept-"));
    const db = new osecDB(join(dir, "t.db"));
    try {
      const scanId = db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
      const make = (id: string): Finding => ({ id, templateId: "t", title: "x", description: "d", severity: "high", category: "xss", status: "discovered", fingerprint: "fp-1", evidence: { request: "a", response: "b" }, timestamp: Date.now() } as Finding);
      db.saveFinding(scanId, make("f-1"));
      db.updateFindingTriage("f-1", "accepted", "vendor patch due", { expiresAt: "2999-01-01T00:00:00.000Z", approver: "lead" });
      db.saveFinding(scanId, make("f-2"));
      expect(db.getFinding("f-2")).toMatchObject({ triageStatus: "accepted", triageNote: "vendor patch due", triageExpiresAt: "2999-01-01T00:00:00.000Z", triageApprover: "lead" });
      db.updateFindingTriage("f-1", "accepted", "old", { expiresAt: "2001-01-01T00:00:00.000Z", approver: "lead" });
      db.saveFinding(scanId, make("f-3"));
      expect(db.getFinding("f-3")).toMatchObject({ triageStatus: "new", triageNote: null, triageExpiresAt: null });
      db.updateFindingTriage("f-1", "new");
      expect(db.getFinding("f-1")).toMatchObject({ triageStatus: "new", triageExpiresAt: null, triageApprover: null });
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
