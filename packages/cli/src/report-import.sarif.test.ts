import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { osecDB } from "@0/engine/storage";
import { importSarif, prepareSarifImport } from "./report-import.js";

const sarif = (results: unknown[]) => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "foxguard", version: "0.14.0" } }, results }] });
const result = (ruleId: string, uri: string, line: number, level = "error") => ({ ruleId, level, message: { text: `${ruleId} at ${line}` }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } }] });

const directories: string[] = [];
afterEach(() => directories.splice(0).forEach(path => rmSync(path, { recursive: true, force: true })));
const database = () => { const dir = mkdtempSync(join(tmpdir(), "0-sarif-")); directories.push(dir); return join(dir, "0.db"); };

describe("SARIF import", () => {
  it("stores findings with the scanner, location and an unverified status", () => {
    const dbPath = database();
    const outcome = importSarif({ sarifJson: sarif([result("js/sqli", "src/db.ts", 10), result("js/xss", "src/ui.ts", 4, "warning")]), dbPath });
    expect(outcome).toMatchObject({ findings: 2, alreadyImported: false });
    const db = new osecDB(dbPath);
    try {
      const rows = db.getFindings(outcome.scanId);
      expect(rows.map(row => [row.tool, row.severity])).toEqual(expect.arrayContaining([["foxguard", "high"], ["foxguard", "medium"]]));
      expect(db.getFindingReviewFields(rows[0]!.id).reviewAnnotation?.path).toMatch(/^src\//);
      expect(rows.every(row => row.triageStatus === "new" && row.workflowStatus === "backlog")).toBe(true);
    } finally { db.close(); }
  });

  it("importing the same file twice leaves the same findings", () => {
    const dbPath = database();
    const text = sarif([result("r", "a.ts", 1), result("r", "a.ts", 2)]);
    const first = importSarif({ sarifJson: text, dbPath });
    const second = importSarif({ sarifJson: text, dbPath });
    expect(second.alreadyImported).toBe(true);
    expect(second.scanId).toBe(first.scanId);
    const db = new osecDB(dbPath);
    try { expect(db.getFindings(first.scanId)).toHaveLength(2); } finally { db.close(); }
  });

  it("keeps two results of the same rule at the same place apart, and takes a --tool label", () => {
    const prepared = prepareSarifImport(sarif([result("r", "a.ts", 1), result("r", "a.ts", 1)]), { tool: "ci-sast" });
    expect(prepared.findings).toHaveLength(2);
    expect(new Set(prepared.findings.map(finding => finding.id)).size).toBe(2);
    expect(prepared.findings.every(finding => finding.tool === "ci-sast")).toBe(true);
  });

  it("refuses a file that is not SARIF", () => {
    expect(() => prepareSarifImport(JSON.stringify({ findings: [] }))).toThrow("not a SARIF log");
  });

  it("strips a leading UTF-8 BOM in prepareSarifImport and produces the same scanId", () => {
    const text = sarif([result("js/sqli", "src/db.ts", 10)]);
    const plain = prepareSarifImport(text);
    const bom = prepareSarifImport(`\uFEFF${text}`);
    expect(bom.scanId).toBe(plain.scanId);
    expect(bom.findings).toHaveLength(1);
  });
});

describe("web scanner import", () => {
  const fixture = (name: string) => readFileSync(new URL(`../../engine/src/shared/__fixtures__/${name}`, import.meta.url), "utf8");
  for (const [name, expected] of [["strix.sarif", "GET http://127.0.0.1:18089/search"], ["zap.sarif", "GET http://127.0.0.1:18089/"], ["nuclei.jsonl", "GET http://127.0.0.1:18089/admin"]] as const) {
    it(`stores ${name} findings with the method and URL as their place and no file annotation`, () => {
      const dbPath = database();
      expect(prepareSarifImport(fixture(name), { roots: ["/work/repo"] }).findings.some(finding => finding.evidence.request === expected)).toBe(true);
      const outcome = importSarif({ sarifJson: fixture(name), dbPath, roots: ["/work/repo"] });
      expect(outcome.findings).toBeGreaterThan(0);
      const db = new osecDB(dbPath);
      try {
        const rows = db.getFindings(outcome.scanId);
        expect(rows.every(row => !db.getFindingReviewFields(row.id).reviewAnnotation)).toBe(true);
      } finally { db.close(); }
    });
  }
  it("imports the same Nuclei file once", () => {
    const dbPath = database();
    const first = importSarif({ sarifJson: fixture("nuclei.jsonl"), dbPath });
    expect(importSarif({ sarifJson: fixture("nuclei.jsonl"), dbPath })).toMatchObject({ scanId: first.scanId, alreadyImported: true });
  });
});
