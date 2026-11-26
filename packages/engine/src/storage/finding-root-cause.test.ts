/**
 * The structured root cause and the `variantOf` link on findings: stored, read back, never erased by a re-save,
 * and a database created before the columns existed still opens and reads them as absent.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findingSchema, type Finding, type RootCause } from "../shared/index.js";
import { EXECUTED_POC_HARNESS, type ExecutedPoc } from "../shared/executed-poc.js";
import { osecDB } from "./database.js";
import { createShimmedDatabase } from "./wasm-shim.js";

const cause: RootCause = { bugClass: "SQL injection", unsafePattern: { sink: "db.query with a template literal", source: "the id parameter" }, missingGuard: "a bound parameter", designOrigin: "a shared query helper" };

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id, templateId: "test", title: id, description: "d", severity: "high", category: "sql-injection", status: "discovered",
  evidence: { request: id, response: "res" }, timestamp: 1, ...extra,
});

function withDb(use: (db: osecDB, scanId: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "0-root-cause-"));
  const db = new osecDB(join(dir, "test.db"));
  try { use(db, db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0])); }
  finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
}

describe("root cause and variantOf storage", () => {
  it("round-trips a root cause saved with the finding and one set afterwards", () => {
    withDb((db, scan) => {
      db.saveFinding(scan, finding("a", { rootCause: cause }));
      db.saveFinding(scan, finding("b"));
      expect(db.getFindingRootCause("a")).toEqual(cause);
      expect(db.getFindingRootCause("b")).toBeUndefined();
      db.setFindingRootCause("b", cause);
      expect(db.getFindingRootCause("b")).toEqual(cause);
      expect(() => db.setFindingRootCause("missing", cause)).toThrow(/not found/);
      expect(() => db.setFindingRootCause("a", { ...cause, missingGuard: "" })).toThrow(/usable/);
    });
  });

  it("keeps a recorded root cause and link when the finding is saved again without them", () => {
    withDb((db, scan) => {
      db.saveFinding(scan, finding("parent"));
      db.saveFinding(scan, finding("child", { rootCause: cause, variantOf: "parent" }));
      db.saveFinding(scan, finding("child", { title: "renamed" }));
      expect(db.getFindingRootCause("child")).toEqual(cause);
      expect(db.listVariantsOf("parent").map(row => [row.id, row.title])).toEqual([["child", "renamed"]]);
    });
  });

  it("lists variants of one finding and every link in the database", () => {
    withDb((db, scan) => {
      db.saveFinding(scan, finding("p"));
      db.saveFinding(scan, finding("v1", { variantOf: "p", timestamp: 2 }));
      db.saveFinding(scan, finding("v2", { variantOf: "p", timestamp: 3 }));
      db.saveFinding(scan, finding("other"));
      db.updateFindingStatus("v2", "fixed");
      expect(db.listVariantsOf("p").map(row => row.id)).toEqual(["v1", "v2"]);
      expect(db.listVariantLinks().sort((a, b) => a.id.localeCompare(b.id))).toEqual([{ id: "v1", variantOf: "p", status: "discovered" }, { id: "v2", variantOf: "p", status: "fixed" }]);
    });
  });

  const executedPoc: ExecutedPoc = { schemaVersion: 1, harness: EXECUTED_POC_HARNESS, outcome: "static-only", reason: "no-sandbox-image", stepIds: [], startedAt: "2026-11-25T00:00:00.000Z", finishedAt: "2026-11-25T00:00:01.000Z" };

  // A database written by an older version has either neither of the later nullable columns or only executedPoc.
  it.each([["neither executedPoc nor the root cause columns", ""], ["only the executedPoc column", ", executedPoc TEXT"]])("opens and migrates a database with %s", (_label, extraColumn) => {
    const dir = mkdtempSync(join(tmpdir(), "0-root-cause-legacy-"));
    try {
      const path = join(dir, "legacy.db");
      const legacy = createShimmedDatabase(path);
      legacy.exec(`
        CREATE TABLE scans (id TEXT PRIMARY KEY, target TEXT NOT NULL, depth TEXT NOT NULL, runtime TEXT NOT NULL DEFAULT 'api', mode TEXT NOT NULL DEFAULT 'probe', status TEXT NOT NULL DEFAULT 'running', startedAt TEXT NOT NULL, completedAt TEXT, durationMs INTEGER, summary TEXT);
        CREATE TABLE findings (id TEXT PRIMARY KEY, scanId TEXT NOT NULL REFERENCES scans(id), templateId TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'discovered', fingerprint TEXT, evidenceRequest TEXT NOT NULL, evidenceResponse TEXT NOT NULL, evidenceAnalysis TEXT, timestamp INTEGER NOT NULL${extraColumn});
        INSERT INTO scans (id, target, depth, startedAt) VALUES ('s', 'https://example.com', 'full', '2026-01-01T00:00:00.000Z');
        INSERT INTO findings (id, scanId, templateId, title, description, severity, category, evidenceRequest, evidenceResponse, timestamp) VALUES ('old', 's', 't', 'Old', 'd', 'high', 'xss', 'req', 'res', 1);
      `);
      legacy.close();
      // Opening twice proves the migration is idempotent: the second open finds every column already there.
      for (let round = 0; round < 2; round++) {
        const db = new osecDB(path);
        try {
          const columns = new Set((db as unknown as { sqlite: { prepare(q: string): { all(): Array<{ name: string }> } } }).sqlite.prepare("PRAGMA table_info(findings)").all().map(c => c.name));
          for (const column of ["executedPoc", "rootCause", "variantOf"]) expect(columns.has(column)).toBe(true);
          expect(db.listVariantsOf("old")).toEqual([]);
          if (round === 0) {
            expect(db.getFindingRootCause("old")).toBeUndefined();
            expect(db.getFindingExecutedPoc("old")).toBeUndefined();
            db.setFindingRootCause("old", cause);
            db.setFindingExecutedPoc("old", executedPoc);
          } else {
            expect(db.getFindingRootCause("old")).toEqual(cause);
            expect(db.getFindingExecutedPoc("old")?.outcome).toBe("static-only");
          }
        } finally { db.close(); }
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("findings import schema stays backward compatible", () => {
  const base = { id: "x", templateId: "t", title: "T", description: "d", severity: "high", category: "xss", status: "discovered", evidence: { request: "r", response: "s" }, timestamp: 1 };

  it("accepts a finding with no root cause or link", () => {
    const parsed = findingSchema.parse(base);
    expect(parsed.rootCause).toBeUndefined();
    expect(parsed.variantOf).toBeUndefined();
  });

  it("keeps a complete root cause and the link", () => {
    const parsed = findingSchema.parse({ ...base, rootCause: cause, variantOf: "y" });
    expect(parsed.rootCause).toEqual(cause);
    expect(parsed.variantOf).toBe("y");
  });

  it("drops a half-filled root cause instead of rejecting the finding", () => {
    const parsed = findingSchema.parse({ ...base, rootCause: { bugClass: "SQL injection" }, variantOf: 7 });
    expect(parsed.rootCause).toBeUndefined();
    expect(parsed.variantOf).toBeUndefined();
  });
});
