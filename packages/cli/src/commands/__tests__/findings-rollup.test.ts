import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { osecDB } from "@0/engine/storage";
import type { Finding } from "@0/engine/shared";
import { applyOwners, buildExport, mergeRows, parseExport, renderHtml, renderText, summarise, type RollupRow } from "../findings-rollup-core.js";
import { runFindingsRollup, type FindingsRollupDeps } from "../findings-rollup.js";

const NOW = new Date("2026-06-01T00:00:00.000Z");
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const row = (over: Partial<RollupRow> = {}): RollupRow => ({
  repository: "api", fingerprint: "fp1", title: "Finding", severity: "high", category: "xss", status: "confirmed", triage: "new", owner: null, firstSeen: day(1), lastSeen: day(1), ...over,
});

describe("rollup counting", () => {
  it("counts a flaw once per repository but separately across repositories", () => {
    const merged = mergeRows([row({ firstSeen: day(40), lastSeen: day(40) }), row({ firstSeen: day(2), lastSeen: day(2), severity: "critical" }), row({ repository: "web" })]);
    expect(merged).toHaveLength(2);
    const api = merged.find(r => r.repository === "api")!;
    expect(api.severity).toBe("critical");
    expect(api.firstSeen).toBe(day(40));
    expect(api.lastSeen).toBe(day(2));
  });

  it("leaves fixed, false-positive, accepted and suppressed findings out of the open count", () => {
    const summary = summarise([
      row({ fingerprint: "a" }), row({ fingerprint: "b", status: "fixed" }), row({ fingerprint: "c", status: "false-positive" }),
      row({ fingerprint: "d", triage: "accepted" }), row({ fingerprint: "e", triage: "suppressed" }),
    ], NOW);
    expect(summary.total).toBe(5);
    expect(summary.open).toBe(1);
    expect(summary.excluded).toEqual({ fixed: 1, "false-positive": 1, accepted: 1, suppressed: 1 });
  });

  it("groups open findings by severity, category, age, owner and repository", () => {
    const summary = summarise([
      row({ fingerprint: "a", severity: "critical", firstSeen: day(3), owner: "payments" }),
      row({ fingerprint: "b", severity: "low", category: "ssrf", firstSeen: day(20) }),
      row({ fingerprint: "c", repository: "web", severity: "low", firstSeen: day(50), owner: "payments" }),
      row({ fingerprint: "d", repository: "web", severity: "weird", firstSeen: day(200) }),
    ], NOW);
    expect(summary.bySeverity.map(c => `${c.name}:${c.count}`)).toEqual(["critical:1", "high:0", "medium:0", "low:2", "info:0", "weird:1"]);
    expect(summary.byAge.map(c => c.count)).toEqual([1, 1, 1, 1]);
    expect(summary.byOwner).toEqual([{ name: "payments", count: 2 }, { name: "unassigned", count: 2 }]);
    expect(summary.byCategory[0]).toEqual({ name: "xss", count: 3 });
    expect(summary.byRepository).toEqual([{ name: "api", count: 2 }, { name: "web", count: 2 }]);
    expect(summary.repositories).toBe(2);
  });

  it("fills a missing owner from the owners map and keeps a finding's own owner", () => {
    const out = applyOwners([row({ owner: "alice" }), row({ fingerprint: "b" }), row({ fingerprint: "c", repository: "toString" })], { api: "payments" });
    expect(out.map(r => r.owner)).toEqual(["alice", "payments", null]);
  });

  it("renders text and html that escape hostile names", () => {
    const summary = summarise([row({ owner: "<script>alert(1)</script>\u001b[2J" })], NOW);
    const html = renderHtml(summary);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toMatch(/https?:\/\//);
    expect(renderText(summary)).not.toContain("\u001b");
    expect(renderText(summary)).toContain("1 open findings across 1 repository");
  });
});

describe("rollup export format", () => {
  it("round-trips", () => {
    const text = JSON.stringify(buildExport([row()], NOW));
    expect(parseExport(text, "x.json").findings).toEqual([row()]);
  });
  it("names the problem in a bad file", () => {
    expect(() => parseExport("nope", "a.json")).toThrow("a.json is not JSON.");
    expect(() => parseExport("{}", "a.json")).toThrow("not a 0.findings-rollup.v1 export");
    expect(() => parseExport(JSON.stringify({ ...buildExport([row()], NOW), findings: [{ ...row(), firstSeen: "yesterday" }] }), "a.json")).toThrow(/findings\.0\.firstSeen/);
  });
});

describe("findings rollup command", () => {
  let dir: string;
  const written: Record<string, string> = {};
  let out: string[]; let err: string[];
  const deps = (databases: string[] = []): FindingsRollupDeps => ({
    now: () => NOW, defaultDatabases: () => databases, out: t => out.push(t), err: t => err.push(t), writeFile: (p, t) => { written[p] = t; },
  });
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-rollup-")); out = []; err = []; for (const k of Object.keys(written)) delete written[k]; });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  const seed = (name: string, target: string, ids: Array<[string, string]>): string => {
    const path = join(dir, name);
    const db = new osecDB(path);
    try {
      db.createScan({ target, depth: "deep", format: "json" }, `scan-${name}`);
      for (const [id, severity] of ids) {
        db.saveFinding(`scan-${name}`, { id, templateId: "t", title: `Finding ${id}`, description: "d", severity, category: "xss", status: "confirmed", timestamp: NOW.getTime() - 10 * 86_400_000, evidence: { request: "SECRET-EVIDENCE", response: "r", analysis: "a" } } as Finding);
      }
    } finally { db.close(); }
    return path;
  };

  it("merges a database and an export file, naming repositories from the scan target", () => {
    const database = seed("a.db", "/home/someone/code/api", [["id-1", "high"], ["id-2", "low"]]);
    const file = join(dir, "web.json");
    writeFileSync(file, JSON.stringify(buildExport([row({ repository: "web", fingerprint: "w1", severity: "critical" })], NOW)));
    runFindingsRollup([database, file], { format: "json" }, deps());
    const summary = JSON.parse(out[0]!);
    expect(summary.open).toBe(3);
    expect(summary.byRepository).toEqual([{ name: "api", count: 2 }, { name: "web", count: 1 }]);
    expect(summary.bySeverity[0]).toEqual({ name: "critical", count: 1 });
  });

  it("writes an export without evidence or local paths, which a second rollup can read", () => {
    const database = seed("b.db", "/home/someone/code/api", [["id-1", "high"]]);
    runFindingsRollup([database], { export: join(dir, "api.json"), owners: undefined }, deps());
    const exported = written[join(dir, "api.json")]!;
    expect(exported).not.toContain("SECRET-EVIDENCE");
    expect(exported).not.toContain("someone");
    writeFileSync(join(dir, "api.json"), exported);
    out.length = 0;
    runFindingsRollup([join(dir, "api.json"), database], {}, deps());
    expect(out[0]).toContain("1 open findings across 1 repository");
  });

  it("reads local databases when no input is named, and applies an owners file", () => {
    const database = seed("c.db", "api", [["id-1", "high"]]);
    const owners = join(dir, "owners.json");
    writeFileSync(owners, JSON.stringify({ api: "payments" }));
    runFindingsRollup([], { owners, format: "json" }, deps([database]));
    expect(JSON.parse(out[0]!).byOwner).toEqual([{ name: "payments", count: 1 }]);
  });

  it("writes html to a file", () => {
    const database = seed("d.db", "api", [["id-1", "high"]]);
    runFindingsRollup([database], { format: "html", output: join(dir, "r.html") }, deps());
    expect(written[join(dir, "r.html")]).toContain("<!doctype html>");
    expect(out).toEqual([]);
  });

  it("rejects a missing file, a bad owners file and a bad format", () => {
    expect(() => runFindingsRollup([join(dir, "missing.json")], {}, deps())).toThrow("does not exist");
    writeFileSync(join(dir, "o.json"), "[1]");
    expect(() => runFindingsRollup([], { owners: join(dir, "o.json") }, deps())).toThrow("--owners");
    expect(() => runFindingsRollup([], { format: "pdf" }, deps())).toThrow("--format");
    writeFileSync(join(dir, "bad.json"), "{}");
    expect(() => runFindingsRollup([join(dir, "bad.json")], {}, deps())).toThrow("Could not read");
  });
});
