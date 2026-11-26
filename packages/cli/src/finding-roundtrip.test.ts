/**
 * `findings export` carries a finding's root cause, its variantOf link and its executed-PoC record, in JSON and SARIF.
 * Re-importing 0's own JSON report restores the descriptive links (root cause, variant link inside the same file) and
 * never an executed result; reports written before these fields existed still import.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { osecDB } from "@0/engine/storage";
import type { Finding } from "@0/engine/shared";
import { runFindingsExport, type FindingsExportDeps } from "./commands/findings-export.js";
import { importCiReport } from "./report-import.js";

const directories: string[] = [];
afterEach(() => { for (const d of directories.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tempDb = () => { const d = mkdtempSync(join(tmpdir(), "0-roundtrip-")); directories.push(d); return join(d, "engine.db"); };

const ROOT_CAUSE = { bugClass: "SQL injection", unsafePattern: { sink: "db.query with a template literal", source: "the id parameter" }, missingGuard: "a bound parameter", designOrigin: "a shared query helper" };
const EXECUTED = {
  schemaVersion: 1 as const, harness: "0security-executed-poc/1" as const, outcome: "script-matched" as const, reason: "expectation-met", stepIds: ["p1"],
  run: { status: "pass" as const, reason: "ok", command: "sh app.sh", isolation: "container" as const, imageDigest: `sha256:${"a".repeat(64)}`, durationMs: 1200, logTail: "TOP-SECRET" },
  startedAt: "2026-01-01T00:00:00.000Z", finishedAt: "2026-01-01T00:00:02.000Z",
};

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id, templateId: "agent", title: `Finding ${id}`, description: `Description of ${id}`, severity: "high", category: "sql-injection", status: "discovered",
  evidence: { request: "src/a.ts:3", response: "db.query(`${id}`)" }, timestamp: 1_760_000_000_000, ...extra,
});

function seed(): string {
  const dbPath = tempDb();
  const db = new osecDB(dbPath);
  try {
    const scan = db.createScan({ target: "/repo", depth: "default", format: "json" });
    db.saveFinding(scan, finding("parent", { rootCause: ROOT_CAUSE }));
    db.saveFinding(scan, finding("variant", { rootCause: ROOT_CAUSE, variantOf: "parent" }));
    db.setFindingExecutedPoc("parent", EXECUTED);
  } finally { db.close(); }
  return dbPath;
}

async function exportAs(dbPath: string, format: "json" | "sarif"): Promise<any> {
  let body = "";
  const deps: FindingsExportDeps = { out: () => {}, err: () => {}, writeBytes: () => {}, writeStdout: bytes => { body = new TextDecoder().decode(bytes); }, contextLoad: { settings: { findingsContext: "" } } };
  await runFindingsExport([], { format, dbPath }, deps);
  return JSON.parse(body);
}

describe("findings export carries root cause, variantOf and the executed PoC", () => {
  it("JSON", async () => {
    const report = await exportAs(seed(), "json");
    const byId = new Map<string, Finding>(report.findings.map((f: Finding) => [f.id, f]));
    expect(byId.get("parent")).toMatchObject({ rootCause: ROOT_CAUSE, executedPoc: { outcome: "script-matched", run: { isolation: "container" } } });
    expect(byId.get("parent")!.variantOf).toBeUndefined();
    expect(byId.get("variant")).toMatchObject({ rootCause: ROOT_CAUSE, variantOf: "parent" });
  });

  it("SARIF, with the executed record complete enough to parse", async () => {
    const sarif = await exportAs(seed(), "sarif");
    const props = (title: string) => sarif.runs[0].results.find((r: { message: { text: string }; properties: unknown }) => r.message.text.includes(`Description of ${title}`)).properties;
    const parent = props("parent");
    expect(parent.rootCause).toEqual(ROOT_CAUSE);
    expect(parent.executedPoc).toMatchObject({ outcome: "script-matched", schemaVersion: 1, harness: "0security-executed-poc/1", stepIds: ["p1"], startedAt: EXECUTED.startedAt, run: { imageDigest: EXECUTED.run.imageDigest } });
    const variant = props("variant");
    expect(variant.variantOf).toBe("parent");
    expect(variant.executedPoc).toMatchObject({ outcome: "static-only", reason: "not-attempted" });
  });
});

describe("re-importing 0's own JSON report", () => {
  it("restores root cause and the variant link inside the file, and never an executed result", async () => {
    const report = await exportAs(seed(), "json");
    const target = tempDb();
    const result = importCiReport({ reportJson: JSON.stringify(report), dbPath: target });
    const db = new osecDB(target);
    try {
      const rows = db.getFindings(result.scanId);
      const parent = rows.find(r => r.title === "Finding parent")!;
      const variant = rows.find(r => r.title === "Finding variant")!;
      expect(db.getFindingRootCause(parent.id)).toEqual(ROOT_CAUSE);
      expect(db.getFindingRootCause(variant.id)).toEqual(ROOT_CAUSE);
      expect(variant.variantOf).toBe(parent.id);
      expect(parent.variantOf).toBeNull();
      expect(db.getFindingExecutedPoc(parent.id)).toBeUndefined();
    } finally { db.close(); }
  });

  it("drops a variant link whose parent is not in the file, and a malformed root cause, without failing", async () => {
    const report = await exportAs(seed(), "json");
    const only = { ...report, findings: report.findings.filter((f: Finding) => f.id === "variant").map((f: Finding) => ({ ...f, rootCause: { bugClass: "only this" } })) };
    const target = tempDb();
    const result = importCiReport({ reportJson: JSON.stringify(only), dbPath: target });
    const db = new osecDB(target);
    try {
      const row = db.getFindings(result.scanId)[0]!;
      expect(row.variantOf).toBeNull();
      expect(db.getFindingRootCause(row.id)).toBeUndefined();
    } finally { db.close(); }
  });

  it("still imports a report from before these fields existed", async () => {
    const report = await exportAs(seed(), "json");
    const older = { ...report, findings: report.findings.map(({ rootCause: _r, variantOf: _v, executedPoc: _e, ...rest }: Finding) => rest) };
    const target = tempDb();
    const result = importCiReport({ reportJson: JSON.stringify(older), dbPath: target });
    const db = new osecDB(target);
    try {
      const rows = db.getFindings(result.scanId);
      expect(rows).toHaveLength(2);
      expect(rows.every(r => r.variantOf === null && db.getFindingRootCause(r.id) === undefined)).toBe(true);
    } finally { db.close(); }
  });
});
