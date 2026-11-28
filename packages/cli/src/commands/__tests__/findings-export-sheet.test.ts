import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { osecDB } from "@0/engine/storage";
import type { Finding } from "@0/engine/shared";

let paths: string[] = [];
vi.mock("../../finding-focus.js", async importOriginal => ({ ...(await importOriginal<typeof import("../../finding-focus.js")>()), findingDatabasePaths: () => paths }));
const { runFindingsExport } = await import("../findings-export.js");

let directory: string;
const finding = (id: string, severity: string, path: string, line: number, extra: Partial<Finding> = {}): Finding => ({
  id, templateId: "source", title: `Finding ${id}`, description: "Issue", severity, category: "xss", status: "confirmed", timestamp: 1800000000000,
  evidence: { request: `${path}:${line}`, response: "evidence", analysis: "Reproduced" }, reviewAnnotation: { path, startLine: line, fixExplanation: `Fix ${id}` }, ...extra } as Finding);
beforeEach(() => {
  process.exitCode = 0;
  directory = mkdtempSync(join(tmpdir(), "0-cli-sheet-"));
  const path = join(directory, "run.db");
  const db = new osecDB(path);
  try {
    db.createScan({ target: "repo", depth: "deep", format: "json" }, "scan-a");
    db.saveFinding("scan-a", finding("aaa11111", "low", "src/z.ts", 4));
    db.saveFinding("scan-a", finding("bbb22222", "high", "src/a.ts", 9));
    db.completeScan("scan-a", { target: "repo" } as never);
  } finally { db.close(); }
  paths = [path];
});
afterEach(() => { process.exitCode = 0; rmSync(directory, { recursive: true, force: true }); });

function deps() {
  const err: string[] = [];
  return { err, deps: { out: () => {}, err: (t: string) => err.push(t), writeBytes: () => {}, writeStdout: () => {}, gitHead: () => "deadbeef", now: () => new Date("2026-02-03T04:05:06.000Z"), commandLine: () => "0security findings export --scan scan-a --format sheet -o out" } };
}

describe("findings export --format sheet", () => {
  it("writes the sheet from the stored findings, with the commit, in severity order", async () => {
    const h = deps();
    const out = join(directory, "sheet");
    await runFindingsExport([], { format: "sheet", scan: "scan-a", output: out, source: directory, dbPath: paths[0]! }, h.deps);
    expect(h.err).toEqual([expect.stringContaining("Wrote the evaluation sheet")]);
    expect(process.exitCode).toBe(0);
    expect(readdirSync(out).sort()).toEqual(["README.md", "findings.json", "review.csv", "run.json"]);
    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")).findings;
    expect(findings.map((f: { findingId: string }) => f.findingId)).toEqual(["bbb22222", "aaa11111"]);
    expect(findings[0].fixExplanation).toBe("Fix bbb22222");
    expect(findings[0].verdict).toBe("not verified");
    const run = JSON.parse(readFileSync(join(out, "run.json"), "utf8"));
    expect(run).toMatchObject({ source: "stored", repository: { commit: "deadbeef" }, scanId: "scan-a", command: "0security findings export --scan scan-a --format sheet -o out", model: null, costUsd: null });
    expect(h.err.join("\n")).toContain("not an accuracy result");
  });
  it("needs a folder, and refuses a non-empty one before reading anything", async () => {
    const needs = deps();
    await runFindingsExport([], { format: "sheet", scan: "scan-a" }, needs.deps);
    expect(process.exitCode).toBe(2);
    expect(needs.err.join("\n")).toContain("supply -o <folder>");
    process.exitCode = 0;
    const out = join(directory, "full");
    writeFileSync(directory + "/full", "a file");
    const refused = deps();
    await runFindingsExport([], { format: "sheet", scan: "scan-a", output: out }, refused.deps);
    expect(process.exitCode).toBe(2);
    expect(refused.err.join("\n")).toMatch(/not a folder/);
  });
  it("keeps --source and --overwrite-sheet to the sheet format", async () => {
    const h = deps();
    await runFindingsExport([], { format: "json", source: directory }, h.deps);
    expect(process.exitCode).toBe(2);
    expect(h.err.join("\n")).toContain("--format sheet");
  });
});
