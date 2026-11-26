import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { osecDB } from "./database.js";
import { createShimmedDatabase } from "./wasm-shim.js";
import type { Finding, FindingBusinessContext } from "../shared/index.js";
import { parseFindingBusinessContext } from "../shared/business-context.js";

const context: FindingBusinessContext = { provenance: "operator", repository: "shop", tags: ["payments"], notes: ["unverified"], shift: 2, score: 4, rationale: "ranked higher (+2): payments" };
const finding = (id: string, severity: Finding["severity"] = "high"): Finding => ({ id, templateId: "t", title: id, description: "d", severity, category: "xss", status: "discovered", evidence: { request: "a", response: "b" }, timestamp: 1 });

describe("operator business context persistence", () => {
  it("migrates a legacy database, preserves operator attribution on ordinary saves, and ranks before limit", () => {
    const dir = mkdtempSync(join(tmpdir(), "business-context-")), path = join(dir, "old.db");
    let db: osecDB | undefined;
    try {
      db = new osecDB(path); db.close(); db = undefined;
      const raw = createShimmedDatabase(path); raw.exec("ALTER TABLE findings DROP COLUMN businessContext"); raw.close();
      db = new osecDB(path);
      const scan = db.createScan({ target: "shop", depth: "default", format: "json" });
      db.saveFinding(scan, { ...finding("technical-high"), businessContext: context });
      expect(db.getFinding("technical-high")?.businessContext).toBeNull(); // model/ordinary save cannot assert operator provenance
      db.saveFinding(scan, finding("payments-medium", "medium"));
      db.setFindingBusinessContext("payments-medium", context);
      db.saveFinding(scan, finding("payments-medium", "medium"));
      expect(db.getFindingReviewFields("payments-medium").businessContext).toEqual(context);
      expect(db.getFinding("payments-medium")).toMatchObject({ severity: "medium", status: "discovered", triageStatus: "new" });
      expect(db.listFindingsBySeverity({ limit: 1 })[0]?.id).toBe("payments-medium");
      expect(db.listFindingFamiliesBySeverity({ limit: 1 })[0]?.latest.id).toBe("payments-medium");
      db.close(); db = new osecDB(path);
      expect(db.getFindingReviewFields("payments-medium").businessContext).toEqual(context);
      db.setFindingBusinessContext("payments-medium", undefined);
      expect(db.getFindingReviewFields("payments-medium").businessContext).toBeUndefined();
      expect(() => db.setFindingBusinessContext("payments-medium", { ...context, provenance: "model" } as never)).toThrow();
      expect(parseFindingBusinessContext('{"provenance":"operator"}')).toBeUndefined();
      expect(parseFindingBusinessContext("not json")).toBeUndefined();
    } finally { db?.close(); rmSync(dir, { recursive: true, force: true }); }
  });
});
