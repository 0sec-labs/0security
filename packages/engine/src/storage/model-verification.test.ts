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
});
