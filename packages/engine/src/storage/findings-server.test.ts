import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { osecDB } from "./database.js";
import type { Finding } from "../shared/index.js";

let dir: string;
let db: osecDB;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "fx-db-")); db = new osecDB(join(dir, "o.db")); });
afterEach(() => { db.close(); });

const finding = (n: number, fingerprint = `fx:${n}`): Finding => ({
  id: `up-${fingerprint}`, fingerprint, templateId: "rule/x", title: `Finding ${n}`, description: "d", category: "injection", severity: "high",
  evidence: { request: "a.ts:1", response: "", analysis: "" }, timestamp: Date.now(), status: "discovered", triageStatus: "new", workflowStatus: "backlog",
} as Finding);
const upload = (scanId: string, repo: string, findings: Finding[]) => db.ingestFindings({ scanId, digest: scanId, repo, source: "ci", actor: "key:ci", format: "sarif", findings });

describe("ingestFindings", () => {
  it("stores findings with repo and source, and an open history row", () => {
    expect(upload("fx-1", "acme/api", [finding(1), finding(2)])).toMatchObject({ created: 2, known: 0, alreadyImported: false });
    const rows = db.listOrgFindings();
    expect(rows.map(r => [r.repo, r.source])).toEqual([["acme/api", "ci"], ["acme/api", "ci"]]);
    expect(db.listFindingHistory("fx:1")).toEqual([expect.objectContaining({ action: "open", actor: "key:ci", repo: "acme/api" })]);
  });

  it("is idempotent: the same upload and the same fingerprints add nothing", () => {
    upload("fx-1", "acme/api", [finding(1)]);
    expect(upload("fx-1", "acme/api", [finding(1)])).toMatchObject({ alreadyImported: true, created: 0 });
    expect(upload("fx-2", "acme/api", [finding(1), finding(2)])).toMatchObject({ created: 1, known: 1 });
    expect(db.listOrgFindings()).toHaveLength(2);
    expect(db.listFindingHistory("fx:1")).toHaveLength(1);
  });

  it("keeps the same fingerprint in two repositories apart and filters by repository", () => {
    upload("fx-1", "acme/api", [finding(1)]);
    upload("fx-2", "acme/web", [finding(2)]);
    expect(db.listOrgFindings({ repo: "acme/web" }).map(r => r.repo)).toEqual(["acme/web"]);
    expect(db.listOrgFindings()).toHaveLength(2);
  });

  it("leaves findings that were not ingested out of the org view", () => {
    const scan = db.createScan({ target: "https://t.example", depth: "quick", format: "json" } as never);
    db.saveFinding(scan, finding(9, "local-9"));
    expect(db.listOrgFindings()).toEqual([]);
    expect(db.repoOfFingerprint("local-9")).toBeNull();
  });
});

describe("finding_history", () => {
  it("is append-only", () => {
    const id = db.appendFindingHistory({ fingerprint: "fx:1", actor: "u", action: "suppress", reason: "why not" });
    expect(db.listFindingHistory("fx:1")).toEqual([expect.objectContaining({ id, reason: "why not" })]);
    const sqlite = (db as unknown as { sqlite: { prepare(s: string): { run(...a: unknown[]): unknown } } }).sqlite;
    expect(() => sqlite.prepare("UPDATE finding_history SET actor = 'x'").run()).toThrow(/append-only/);
    expect(() => sqlite.prepare("DELETE FROM finding_history").run()).toThrow(/append-only/);
  });
});
