import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { osecDB } from "@0/engine/storage";
import type { Finding } from "@0/engine/shared";
import { applyLabels, applyOwners, buildExport, computeTrend, mergeRows, parseExport, renderHtml, renderText, summarise, type RollupRow } from "../findings-rollup-core.js";
import { readLabels, repositoryFromUri, runFindingsRollup, type FindingsRollupDeps } from "../findings-rollup.js";

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

describe("rollup trend", () => {
  const earlier = buildExport([
    row({ fingerprint: "stays" }), row({ fingerprint: "fixed", severity: "critical" }), row({ fingerprint: "accepted-now" }),
    row({ fingerprint: "was-accepted", triage: "accepted" }), row({ repository: "gone", fingerprint: "g1" }), row({ repository: "web", fingerprint: "w1", severity: "low" }),
  ], new Date("2026-05-01T00:00:00.000Z"));
  const current = [
    row({ fingerprint: "stays" }), row({ fingerprint: "fixed", severity: "critical", status: "fixed" }), row({ fingerprint: "accepted-now", triage: "accepted" }),
    row({ fingerprint: "was-accepted" }), row({ fingerprint: "new", severity: "medium" }), row({ repository: "web", fingerprint: "w1", severity: "low", status: "fixed" }),
    row({ repository: "fresh", fingerprint: "f1", severity: "high" }),
  ];

  it("counts opened, fixed and net per severity and repository", () => {
    const t = computeTrend(earlier, current);
    expect(t).toMatchObject({ since: "2026-05-01T00:00:00.000Z", opened: 3, fixed: 3, net: 0 });
    const sev = Object.fromEntries(t.bySeverity.map(c => [c.name, [c.opened, c.fixed, c.net]]));
    expect(sev).toMatchObject({ critical: [0, 1, -1], high: [2, 1, 1], medium: [1, 0, 1], low: [0, 1, -1], info: [0, 0, 0] });
    expect(t.bySeverity.map(c => c.name)).toEqual(["critical", "high", "medium", "low", "info"]);
    expect(t.byRepository).toEqual([
      { name: "api", opened: 2, fixed: 2, net: 0 }, { name: "fresh", opened: 1, fixed: 0, net: 1 }, { name: "web", opened: 0, fixed: 1, net: -1 },
    ]);
  });

  it("lists repositories on one side only instead of counting them as fixed", () => {
    const t = computeTrend(earlier, current);
    expect(t.missingRepositories).toEqual(["gone"]);
    expect(t.newRepositories).toEqual(["fresh"]);
  });

  it("shows the trend in text, html and json, and escapes names", () => {
    const hostile = buildExport([row({ repository: "<img src=x>", fingerprint: "z" })], NOW);
    const summary = summarise([row({ repository: "<b>x</b>", fingerprint: "n" })], NOW, hostile);
    expect(renderText(summary)).toContain("Trend since");
    const html = renderHtml(summary);
    expect(html).toContain("Trend by repository");
    expect(html).not.toContain("<b>x</b>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x&gt;");
    expect(JSON.parse(JSON.stringify(summary)).trend.opened).toBe(1);
  });
});

describe("rollup labels", () => {
  const rules = [
    { pattern: "pay-*", path: false, team: "payments", tier: "2" },
    { pattern: "pay-api", path: false, tier: "1" },
    { pattern: "src/vault/**", path: true, team: "security" },
  ];
  it("prefers a path rule, then an exact name, then the longest glob", () => {
    const out = applyLabels([
      row({ repository: "pay-api", fingerprint: "a" }), row({ repository: "pay-web", fingerprint: "b" }),
      { ...row({ repository: "pay-api", fingerprint: "c" }), path: "src/vault/keys.ts" }, row({ repository: "other", fingerprint: "d" }),
    ], rules);
    expect(out.map(r => [r.team, r.tier])).toEqual([["payments", "1"], ["payments", "2"], ["security", "1"], [null, null]]);
  });
  it("lets the labels file override a stored label and keeps stored labels when nothing matches", () => {
    const out = applyLabels([row({ repository: "pay-api", team: "old", tier: "9" }), row({ repository: "zzz", fingerprint: "b", team: "kept" })], rules);
    expect(out.map(r => [r.team, r.tier])).toEqual([["payments", "1"], ["kept", null]]);
  });
  it("counts open findings by team and tier, with unlabelled ones separate", () => {
    const summary = summarise(applyLabels([row({ repository: "pay-api" }), row({ repository: "o", fingerprint: "b" })], rules), NOW);
    expect(summary.byTeam).toEqual([{ name: "payments", count: 1 }, { name: "unlabelled", count: 1 }]);
    expect(renderText(summary)).toContain("By team");
    expect(renderText(summarise([row()], NOW))).not.toContain("By team");
  });
  it("does not let a glob key behave as a regular expression", () => {
    expect(applyLabels([row({ repository: "apiX" })], [{ pattern: "api.", path: false, team: "t" }])[0]!.team).toBeNull();
    expect(applyLabels([row({ repository: "a(b" })], [{ pattern: "a(b", path: false, team: "t" }])[0]!.team).toBe("t");
  });
  it("keeps team and tier in an export that reads back, and reads old exports without them", () => {
    const labelled = applyLabels([row({ repository: "pay-api" })], rules);
    expect(parseExport(JSON.stringify(buildExport(labelled, NOW)), "x").findings[0]).toMatchObject({ team: "payments", tier: "1" });
    const old = JSON.stringify({ schema: "0.findings-rollup.v1", exportedAt: NOW.toISOString(), findings: [row()] });
    expect(parseExport(old, "old.json").findings[0]!.team).toBeUndefined();
  });
});

describe("rollup command: labels, trend and SARIF input", () => {
  let dir: string; let out: string[]; let err: string[]; const written: Record<string, string> = {};
  const deps = (): FindingsRollupDeps => ({ now: () => NOW, defaultDatabases: () => [], out: t => out.push(t), err: t => err.push(t), writeFile: (p, t) => { written[p] = t; } });
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-rollup-")); out = []; err = []; for (const k of Object.keys(written)) delete written[k]; });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });
  const sarif = (results: unknown[], extra: Record<string, unknown> = {}) => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "scanner", rules: [{ id: "r1", shortDescription: { text: "Rule one" } }] } }, results, ...extra }] });
  const result = (file: string, line: number, level = "error") => ({ ruleId: "r1", level, message: { text: `bad at ${file}` }, locations: [{ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: line } } }] });

  it("reads a SARIF file directly and names the repository from the flag or the provenance", () => {
    const file = join(dir, "scan.sarif");
    writeFileSync(file, sarif([result("src/a.ts", 3), result("src/b.ts", 4, "warning")], { versionControlProvenance: [{ repositoryUri: "https://user:hunter2@git.example.com/org/api.git?x=1" }] }));
    runFindingsRollup([file], { format: "json" }, deps());
    const summary = JSON.parse(out[0]!);
    expect(summary.open).toBe(2);
    expect(summary.byRepository).toEqual([{ name: "git.example.com/org/api", count: 2 }]);
    expect(JSON.stringify(summary)).not.toContain("hunter2");
    out.length = 0;
    runFindingsRollup([file], { format: "json", repository: "billing" }, deps());
    expect(JSON.parse(out[0]!).byRepository).toEqual([{ name: "billing", count: 2 }]);
  });

  it("falls back to the file name and never writes the SARIF path into an export", () => {
    const file = join(dir, "svc.sarif");
    writeFileSync(file, sarif([result("src/vault/k.ts", 1)]));
    runFindingsRollup([file], { export: join(dir, "e.json"), format: "json" }, deps());
    expect(JSON.parse(out[0]!).byRepository).toEqual([{ name: "svc", count: 1 }]);
    expect(written[join(dir, "e.json")]).not.toContain("vault");
  });

  it("applies path labels to SARIF findings from a YAML labels file", () => {
    const file = join(dir, "x.sarif"); const labels = join(dir, "labels.yaml");
    writeFileSync(file, sarif([result("src/vault/k.ts", 1), result("src/other.ts", 2)]));
    writeFileSync(labels, 'x:\n  team: platform\n  tier: 3\n"path:src/vault/**":\n  team: security\n');
    runFindingsRollup([file], { format: "json", labels }, deps());
    const summary = JSON.parse(out[0]!);
    expect(summary.byTeam).toEqual([{ name: "platform", count: 1 }, { name: "security", count: 1 }]);
    expect(summary.byTier).toEqual([{ name: "3", count: 2 }]);
  });

  it("scrubs credentials and neutralises hostile SARIF text", () => {
    const file = join(dir, "h.sarif");
    const hostile = { ruleId: "<script>alert(1)</script>", level: "error", message: { text: "see https://u:pw@h.example/p?token=abc123 \u001b[2J" }, locations: [{ physicalLocation: { artifactLocation: { uri: "../../etc/passwd" } } }] };
    writeFileSync(file, sarif([hostile], { versionControlProvenance: [{ repositoryUri: "<img src=x onerror=alert(1)>\u0000" }] }));
    runFindingsRollup([file], { format: "html" }, deps());
    expect(out[0]).not.toMatch(/<img|<script/);
    expect(out[0]).not.toContain("pw@");
  });

  it("rejects too many results, a bad SARIF version and a bad labels file", () => {
    const many = join(dir, "many.sarif");
    writeFileSync(many, sarif(Array.from({ length: 5001 }, (_, i) => result(`f${i}.ts`, 1))));
    expect(() => runFindingsRollup([many], {}, deps())).toThrow("more than 5000 results");
    const old = join(dir, "old.sarif");
    writeFileSync(old, JSON.stringify({ version: "1.0", runs: [] }));
    expect(() => runFindingsRollup([old], {}, deps())).toThrow("Unsupported SARIF version");
    for (const bad of ["[1]", "x: 1", "x: {team: 1, extra: 2}", "x: {}", "a: [", ""]) { const p = join(dir, "bad.yaml"); writeFileSync(p, bad); expect(() => readLabels(p)).toThrow("--labels"); }
    expect(() => readLabels(join(dir, "missing.yaml"))).toThrow("--labels");
  });

  it("compares with an earlier export through --since", () => {
    const first = join(dir, "first.json"); const second = join(dir, "second.json");
    writeFileSync(first, JSON.stringify(buildExport([row({ fingerprint: "a" }), row({ fingerprint: "b", severity: "low" })], new Date("2026-05-01T00:00:00.000Z"))));
    writeFileSync(second, JSON.stringify(buildExport([row({ fingerprint: "a" }), row({ fingerprint: "c", severity: "critical" })], NOW)));
    runFindingsRollup([second], { since: first, format: "json" }, deps());
    const trend = JSON.parse(out[0]!).trend;
    expect(trend).toMatchObject({ opened: 1, fixed: 1, net: 0 });
    out.length = 0;
    runFindingsRollup([second], { since: first }, deps());
    expect(out[0]).toContain("Trend since 2026-05-01T00:00:00.000Z: 1 opened, 1 fixed, net 0");
    expect(() => runFindingsRollup([second], { since: join(dir, "nope.json") }, deps())).toThrow("--since");
    writeFileSync(join(dir, "junk.json"), "{}");
    expect(() => runFindingsRollup([second], { since: join(dir, "junk.json") }, deps())).toThrow("--since");
  });

  it("derives a repository name from a URI without credentials", () => {
    expect(repositoryFromUri("ssh://git@host.example/org/repo.git")).toBe("host.example/org/repo");
    expect(repositoryFromUri("git@host.example:org/repo.git")).toBe("host.example:org/repo");
  });
});
