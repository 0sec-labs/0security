import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createShimmedDatabase } from "./wasm-shim.js";
import type { Finding } from "../shared/index.js";
import { osecDB } from "./database.js";

const make = (id: string): Finding => ({ id, templateId: "t", title: "x", description: "d", severity: "high", category: "denial-of-service", status: "discovered", evidence: { request: "a", response: "b" }, timestamp: Date.now() } as Finding);

describe("finding scope label", () => {
  it("is stored in nullable columns, leaves everything else alone, and starts out empty", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-db-scope-"));
    const db = new osecDB(join(dir, "t.db"));
    try {
      const scanId = db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
      db.saveFinding(scanId, make("f-1"));
      db.saveFinding(scanId, make("f-2"));
      expect(db.getFinding("f-1")).toMatchObject({ scope: null, scopeReason: null, scopeSource: null });
      db.setFindingScope("f-1", { scope: "out-of-scope", reason: "behind a gateway", source: "SECURITY.md" });
      expect(db.getFinding("f-1")).toMatchObject({ scope: "out-of-scope", scopeReason: "behind a gateway", scopeSource: "SECURITY.md", severity: "high", status: "discovered", triageStatus: "new" });
      expect(db.getFinding("f-2")).toMatchObject({ scope: null });
      // Saving the same finding again does not drop the label.
      db.saveFinding(scanId, make("f-1"));
      expect(db.getFinding("f-1")).toMatchObject({ scope: "out-of-scope" });
      // A finding that is not there is ignored.
      expect(() => db.setFindingScope("missing", { scope: "out-of-scope", reason: "r", source: "s" })).not.toThrow();
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("adds the columns to a database made before they existed", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-db-scope-old-"));
    const path = join(dir, "old.db");
    try {
      const first = new osecDB(path);
      first.close();
      const raw = createShimmedDatabase(path);
      for (const column of ["scope", "scopeReason", "scopeSource"]) raw.exec(`ALTER TABLE findings DROP COLUMN ${column}`);
      raw.close();
      const db = new osecDB(path);
      try {
        const scanId = db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
        db.saveFinding(scanId, make("f-1"));
        db.setFindingScope("f-1", { scope: "in-scope", reason: "r", source: "SECURITY.md" });
        expect(db.getFinding("f-1")).toMatchObject({ scope: "in-scope" });
      } finally { db.close(); }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
