import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { compareFindingsByBusinessContext, type Finding } from "@0/engine/shared";
import { exportReport } from "@0/engine";
import { osecDB } from "@0/engine/storage";
import { adjustmentFor, applicableEntries, globMatch, parseBusinessContext, repositoryNames } from "../../business-context.js";
import { contextPath, labelFor, loadContextFor, type LoadedContext } from "../../business-context-load.js";
import { runBurndown, selectCandidates, renderReport, type BurndownDeps, type BurndownOptions, type Candidate } from "../burndown.js";
import { checkContext, renderCheck, runContextCheck } from "../findings-context.js";
import { runFindingsExport, type FindingsExportDeps } from "../findings-export.js";
import { buildFixReport, renderFixReportMarkdown, type ExportFixesDeps } from "../findings-export-fixes.js";
import { runFindingsRollup, type FindingsRollupDeps } from "../findings-rollup.js";
import { buildExport, priorityOf, summarise, renderText, renderHtml, type WorkRow } from "../findings-rollup-core.js";
import { runReportDraft, type ReportDraftDeps } from "../findings-report-draft.js";
import { scanExitCode, scanJson, toScanReport, type ScanOutcome } from "../../scan-report.js";
import { isOperatorSetting } from "../../state/settings.js";
import { Command } from "commander";
import { registerFindingsCommand } from "../findings.js";
import { registerFindingsExportCommand } from "../findings-export.js";
import { registerFindingsRollupCommand } from "../findings-rollup.js";
import { registerFindingsContextCommand } from "../findings-context.js";
import { registerReportsCommand } from "../reports.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const tmp = () => { const dir = mkdtempSync(join(tmpdir(), "0-ctx-")); dirs.push(dir); return dir; };
const parse = (value: unknown) => parseBusinessContext(JSON.stringify(value), "ctx.json");
/** What the context says about a finding, or undefined when it says nothing. */
const rankingFor = (context: ReturnType<typeof parse>, path: string | undefined, repository?: string) => { const a = adjustmentFor(context, path, repository); return a.tags.length ? { shift: a.shift, tags: a.tags, notes: a.notes } : undefined; };
const loaded = (value: unknown, repository?: string): LoadedContext => ({ context: parse(value), source: "ctx.json", fromConfig: false, ...(repository ? { repository } : {}) });

/** A shop: payments code and personal data matter, the demo folder does not. */
const SHOP = { entries: [{ match: "src/payments/**", tags: ["payments", "personal-data"], note: "card data" }, { match: "examples/**", tags: ["non-production"] }] };
/** An internal tool: only the admin panel matters. */
const INTERNAL = { entries: [{ match: "services/admin/**", tags: ["operationally-critical"] }] };

describe("ranking math and precedence", () => {
  it("moves by at most two steps either way and never changes the severity", () => {
    const up = rankingFor(parse({ entries: [{ tags: ["internet-facing", "payments", "personal-data", "operationally-critical"] }] }), "a.ts")!;
    expect(up.shift).toBe(2);
    const down = rankingFor(parse({ entries: [{ tags: ["non-production", "internal-only"] }] }), "a.ts")!;
    expect(down.shift).toBe(-2);
    const ctx = loaded({ entries: [{ match: "up/**", tags: ["internet-facing", "payments", "personal-data", "operationally-critical"] }, { match: "down/**", tags: ["non-production", "internal-only"] }] });
    const rows = [["m", "medium", "up/a.ts"], ["c", "critical", "a.ts"], ["h", "high", "down/a.ts"], ["l", "low", "a.ts"], ["i", "info", "up/b.ts"]].map(([id, severity, path]) => ({ id: id!, severity: severity!, businessContext: labelFor(ctx, { severity: severity!, path }) }));
    // medium + 2 ties critical, and the more severe one wins the tie; info + 2 sits between; high - 2 ties low, and high wins that tie.
    expect([...rows].sort(compareFindingsByBusinessContext).map(row => row.id)).toEqual(["c", "m", "i", "h", "l"]);
    expect(rows.map(row => row.severity)).toEqual(["medium", "critical", "high", "low", "info"]);
  });

  it("adds opposite tags up and respects custom weights inside the cap", () => {
    expect(rankingFor(parse({ entries: [{ tags: ["payments", "internal-only"] }] }), "a.ts")!.shift).toBe(0);
    expect(rankingFor(parse({ entries: [{ tags: ["payments"] }], weights: { payments: 2 } }), "a.ts")!.shift).toBe(2);
    expect(rankingFor(parse({ entries: [{ tags: ["payments"] }, { tags: ["payments"] }] }), "a.ts")!.shift).toBe(1);
  });

  it("applies rules for every repository and the ones under a matching repository name, and none for an unknown repository", () => {
    const context = parse({ entries: [{ tags: ["internet-facing"] }], repositories: { "acme/api": [{ match: "src/**", tags: ["payments"] }], "acme/web-*": [{ tags: ["internal-only"] }] } });
    expect(rankingFor(context, "src/a.ts", "https://github.com/Acme/API.git")!.tags).toEqual(["internet-facing", "payments"]);
    expect(rankingFor(context, "src/a.ts", "git@github.com:acme/api.git")!.tags).toEqual(["internet-facing", "payments"]);
    expect(rankingFor(context, "src/a.ts", "acme/web-shop")!.tags).toEqual(["internet-facing", "internal-only"]);
    expect(rankingFor(context, "src/a.ts", "acme/other")!.tags).toEqual(["internet-facing"]);
    expect(rankingFor(context, "src/a.ts", undefined)!.tags).toEqual(["internet-facing"]);
    expect(applicableEntries(context, "acme/api").map(entry => entry.ref)).toEqual(["entries[0]", 'repositories["acme/api"][0]']);
  });

  it("names a repository from a bare name, owner/name or a remote", () => {
    expect(repositoryNames("Acme/API")).toEqual(["acme/api", "api"]);
    expect(repositoryNames("https://host.example/acme/api.git?x=1")).toEqual(["acme/api", "api"]);
    expect(repositoryNames("api")).toEqual(["api"]);
    expect(repositoryNames("")).toEqual([]);
  });

  it("takes --context over the configured file, and the configured file when there is no flag", () => {
    expect(contextPath({ context: "flag.json" }, { findingsContext: "/cfg.json" })).toEqual({ path: "flag.json", fromConfig: false });
    expect(contextPath({}, { findingsContext: "/cfg.json" })).toEqual({ path: "/cfg.json", fromConfig: true });
    expect(contextPath({}, { findingsContext: "" })).toBeUndefined();
    expect(() => contextPath({ context: " " }, {})).toThrow("--context needs a file path");
  });

  it("detects the repository from the remote only when the file has per-repository rules, and prefers --repository", async () => {
    const dir = tmp();
    const file = join(dir, "c.json");
    writeFileSync(file, JSON.stringify({ repositories: { "acme/api": [{ tags: ["payments"] }] } }));
    const asked: string[] = [];
    const detect = async (folder: string) => { asked.push(folder); return "acme/api"; };
    expect((await loadContextFor({ context: file }, { detect, folder: "/work" }))!.repository).toBe("acme/api");
    expect(asked).toEqual(["/work"]);
    expect((await loadContextFor({ context: file, repository: "acme/web" }, { detect, folder: "/work" }))!.repository).toBe("acme/web");
    expect(asked).toHaveLength(1);
    const plain = join(dir, "p.json");
    writeFileSync(plain, JSON.stringify({ entries: [{ tags: ["payments"] }] }));
    await loadContextFor({ context: plain }, { detect, folder: "/work" });
    expect(asked).toHaveLength(1);
    await expect(loadContextFor({ repository: "acme/api" }, { settings: {} })).rejects.toThrow("--repository needs a business context");
  });

  it("names the setting when the configured file is bad", async () => {
    const dir = tmp();
    const bad = join(dir, "bad.json"); writeFileSync(bad, "{}");
    await expect(loadContextFor({}, { settings: { findingsContext: bad } })).rejects.toThrow("findingsContext");
    await expect(loadContextFor({}, { settings: { findingsContext: join(dir, "missing.json") } })).rejects.toThrow("findingsContext");
  });

  it("keeps findingsContext out of a project's reach", () => {
    expect(isOperatorSetting("findingsContext")).toBe(true);
  });
});

describe("a hostile context file", () => {
  it("refuses unknown keys, including a prototype key, and huge lists", () => {
    expect(() => parseBusinessContext('{"__proto__": {"x": 1}, "entries": []}', "c.json")).toThrow("not a setting");
    expect(() => parse({ entries: [{ tags: ["payments"], __proto__: 1, constructor: 2 }] })).toThrow("not a setting");
    expect(() => parse({ entries: Array.from({ length: 501 }, () => ({ tags: ["payments"] })) })).toThrow("at most 500");
    expect(() => parse({ repositories: Object.fromEntries(Array.from({ length: 201 }, (_, i) => [`r${i}`, [{ tags: ["payments"] }]])) })).toThrow("at most 200");
    expect(() => parse({ entries: Array.from({ length: 300 }, () => ({ tags: ["payments"] })), repositories: { a: Array.from({ length: 300 }, () => ({ tags: ["payments"] })) } })).toThrow("at most 500 entries in total");
    expect(() => parse({ entries: [{ tags: ["payments"], match: "a".repeat(201) }] })).toThrow("200 characters");
    expect(() => parse({ entries: [{ tags: ["payments"], note: "n".repeat(201) }] })).toThrow("200 characters");
    expect(() => parse({ repositories: { "": [{ tags: ["payments"] }] } })).toThrow("repository name");
    expect(() => parse({ repositories: { a: { tags: ["payments"] } } })).toThrow("list of entries");
    expect(() => parse({})).toThrow("entries");
  });

  it("treats a prototype-looking repository name as an ordinary name", () => {
    const context = parseBusinessContext('{"repositories": {"__proto__": [{"tags": ["payments"]}]}}', "c.json");
    expect(context.repositories.map(rules => rules.pattern)).toEqual(["__proto__"]);
    expect(({} as Record<string, unknown>).tags).toBeUndefined();
    expect(rankingFor(context, "a.ts", "acme/api")).toBeUndefined();
  });

  it("survives deeply nested JSON", () => {
    expect(() => parseBusinessContext(`{"entries":${"[".repeat(50_000)}`, "c.json")).toThrow("not valid JSON");
  });

  it("matches globs in linear time, so a pattern built to blow up a regular expression does not", () => {
    const path = `${"a/".repeat(240)}b.ts`;
    const nasty = ["**/".repeat(40) + "x", "*a*a*a*a*a*a*a*a*a*a*a*a*b", "a*".repeat(60) + "c", "(a+)+$", "(.*)*x", "[a-z]*[a-z]*[a-z]*!"];
    const started = performance.now();
    for (const pattern of nasty) expect(globMatch(pattern, path)).toBe(false);
    expect(globMatch(`${"**/".repeat(40)}b.ts`, path)).toBe(true);
    expect(performance.now() - started).toBeLessThan(1000);
    // A whole context of such patterns against many findings stays fast too.
    const context = parse({ entries: Array.from({ length: 400 }, () => ({ match: "**/".repeat(30) + "nomatch.ts", tags: ["payments"] })) });
    const t0 = performance.now();
    for (let i = 0; i < 200; i++) rankingFor(context, path);
    expect(performance.now() - t0).toBeLessThan(5000);
  });

  it("matches regular-expression characters literally", () => {
    expect(globMatch("src/(a|b)/x.ts", "src/(a|b)/x.ts")).toBe(true);
    expect(globMatch("src/(a|b)/x.ts", "src/a/x.ts")).toBe(false);
    expect(globMatch("a.b", "aXb")).toBe(false);
    expect(globMatch("src/[ab]/x.ts", "src/a/x.ts")).toBe(false);
  });

  it("gives a hostile finding path no way to reach a rule it should not", () => {
    const context = parse({ entries: [{ match: "src/payments/**", tags: ["payments"] }] });
    expect(rankingFor(context, "src/../etc/passwd")).toBeUndefined();
    expect(rankingFor(context, `src/payments/${"x".repeat(100_000)}`)?.tags).toEqual(["payments"]);
    expect(rankingFor(context, undefined)).toBeUndefined();
    expect(rankingFor(context, "SRC/PAYMENTS/a.ts")).toBeUndefined();
  });
});

describe("rules and findings", () => {
  const finding = (id: string, severity: string, path: string) => ({ id, severity, title: id, path });
  it("lists which rule matches which finding and flags a rule that matches nothing", () => {
    const context = parse({ entries: [{ match: "src/payments/**", tags: ["payments"] }, { match: "nothing/**", tags: ["internal-only"] }], repositories: { "acme/other": [{ tags: ["payments"] }] } });
    const check = checkContext(context, [finding("a", "high", "src/payments/x.ts"), finding("b", "low", "src/y.ts")], "acme/api", "ctx.json");
    expect(check).toMatchObject({ findings: 2, touched: 1, unused: 1 });
    expect(check.rules.map(rule => [rule.ref, rule.status, rule.matches])).toEqual([["entries[0]", "matched", 1], ["entries[1]", "unused", 0], ['repositories["acme/other"][0]', "other-repository", 0]]);
    const text = renderCheck(check);
    expect(text).toContain("matches nothing");
    expect(text).toContain("1 rule match nothing.");
    expect(text).toContain("src/payments/x.ts");
    expect(checkContext(context, [], undefined, "c").rules.at(-1)!.status).toBe("repository-unknown");
  });

  it("exits 0 when every rule matches, 1 when one matches nothing and 2 for a bad file", async () => {
    const dir = tmp();
    const dbPath = join(dir, "h.db");
    const db = new osecDB(dbPath);
    const scan = db.createScan({ target: "https://example.test", depth: "default", format: "json" });
    db.saveFinding(scan, { id: "f1", templateId: "t", title: "SQLi", description: "d", severity: "high", category: "sql-injection", status: "confirmed", evidence: { request: "r", response: "s" }, timestamp: 1, fingerprint: "fp1", reviewAnnotation: { path: "src/payments/a.ts", startLine: 1 } } as unknown as Finding);
    db.close();
    const good = join(dir, "good.json"); writeFileSync(good, JSON.stringify({ entries: [{ match: "src/payments/**", tags: ["payments"] }] }));
    const unused = join(dir, "unused.json"); writeFileSync(unused, JSON.stringify(SHOP));
    const bad = join(dir, "bad.json"); writeFileSync(bad, "{}");
    const out: string[] = [], err: string[] = [];
    const run = async (file: string, extra: { json?: boolean } = {}) => { process.exitCode = undefined; await runContextCheck(file, { dbPath, ...extra }, { out: t => out.push(t), err: t => err.push(t) }); const code = process.exitCode; process.exitCode = undefined; return code; };
    expect(await run(good)).toBeUndefined();
    expect(out.at(-1)).toContain("Every rule that applies matches");
    expect(await run(unused)).toBe(1);
    expect(out.at(-1)).toContain("examples/**");
    expect(JSON.parse((await run(unused, { json: true }), out.at(-1)!)).unused).toBe(1);
    expect(await run(bad)).toBe(2);
    expect(err.at(-1)).toContain("entries");
    expect(await run(join(dir, "missing.json"))).toBe(2);
  });
});

function savedDatabase() {
  const dir = tmp();
  const dbPath = join(dir, "h.db");
  const db = new osecDB(dbPath);
  const scan = db.createScan({ target: "https://example.test", depth: "default", format: "json" });
  const add = (id: string, severity: string, path: string) => db.saveFinding(scan, { id, templateId: "t", title: `Finding ${id}`, description: "d", severity, category: "xss", status: "confirmed", evidence: { request: "r", response: "s" }, timestamp: 100, fingerprint: `fp-${id}`, reviewAnnotation: { path, startLine: 1 } } as unknown as Finding);
  add("admin-high", "high", "services/admin/panel.ts");
  add("checkout-medium", "medium", "src/payments/checkout.ts");
  add("demo-critical", "critical", "examples/demo.ts");
  db.close();
  return { dir, dbPath };
}
const orderIn = (text: string) => ["admin-high", "checkout-medium", "demo-critical"].map(id => [id, text.indexOf(`Finding ${id}`)] as const).filter(([, at]) => at >= 0).sort((a, b) => a[1] - b[1]).map(([id]) => id);

describe("findings export", () => {
  async function exported(format: string, extra: { context?: string; repository?: string } = {}, contextLoad: FindingsExportDeps["contextLoad"] = {}) {
    const { dbPath } = savedDatabase();
    const chunks: Uint8Array[] = [];
    const errs: string[] = [];
    process.exitCode = undefined;
    await runFindingsExport([], { format, dbPath, ...extra }, { out: () => {}, err: t => errs.push(t), writeBytes: () => {}, writeStdout: bytes => chunks.push(bytes), contextLoad });
    const code = process.exitCode; process.exitCode = undefined;
    return { text: Buffer.concat(chunks).toString("utf8"), errs, code };
  }
  const write = (value: unknown) => { const file = join(tmp(), "c.json"); writeFileSync(file, JSON.stringify(value)); return file; };

  it("orders json, markdown and sarif by the context and says why, with two contexts giving two orders", async () => {
    const shop = write(SHOP), internal = write(INTERNAL);
    const plain = await exported("md", {}, { settings: {} });
    expect(orderIn(plain.text)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    expect(plain.text).not.toContain("Business priority");
    const first = await exported("md", { context: shop });
    expect(orderIn(first.text)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(first.text).toContain("**Business priority:**");
    expect(first.text).toContain("payments, personal-data. card data");
    expect(first.text).toContain("**Technical severity:** critical");
    const second = await exported("md", { context: internal });
    expect(orderIn(second.text)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    expect(second.text).toContain("operationally-critical");
    const json = JSON.parse((await exported("json", { context: shop })).text) as { findings: Array<{ id: string; severity: string; businessContext?: { shift: number } }> };
    expect(json.findings.map(f => f.id)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(json.findings.map(f => f.severity)).toEqual(["medium", "high", "critical"]);
    expect(json.findings[0]!.businessContext!.shift).toBe(2);
    const sarif = JSON.parse((await exported("sarif", { context: shop })).text) as { runs: Array<{ results: Array<{ level: string; properties: { businessContext?: { rationale: string } } }> }> };
    expect(sarif.runs[0]!.results[0]!.properties.businessContext!.rationale).toContain("payments");
    expect(sarif.runs[0]!.results[0]!.level).toBe("warning");
  });

  it("uses the configured file when no flag is given, and --context wins over it", async () => {
    const shop = write(SHOP), internal = write(INTERNAL);
    expect(orderIn((await exported("md", {}, { settings: { findingsContext: shop } })).text)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(orderIn((await exported("md", { context: internal }, { settings: { findingsContext: shop } })).text)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
  });

  it("stops on a bad file before reading anything, and applies repository rules by --repository", async () => {
    const bad = write({ nope: 1 });
    expect((await exported("md", { context: bad })).code).toBe(2);
    const perRepo = write({ repositories: { "acme/shop": SHOP.entries, "acme/internal": INTERNAL.entries } });
    expect(orderIn((await exported("md", { context: perRepo, repository: "acme/shop" })).text)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(orderIn((await exported("md", { context: perRepo, repository: "acme/internal" })).text)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    expect(orderIn((await exported("md", { context: perRepo, repository: "acme/unrelated" })).text)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
  });
});

describe("burndown", () => {
  const candidate = (id: string, severity: string, path: string): Candidate => ({ id, fingerprint: `fp-${id}`, title: id, severity, category: "xss", tool: null, scanId: "s", status: "confirmed", triage: "new", timestamp: 1, path, startLine: 1 });
  const all = [candidate("admin-high", "high", "services/admin/panel.ts"), candidate("checkout-medium", "medium", "src/payments/checkout.ts"), candidate("demo-critical", "critical", "examples/demo.ts")];
  const rank = (value: unknown, repository?: string) => all.map(c => ({ ...c, businessContext: labelFor(loaded(value, repository), c) }));

  it("orders the fixes by the context and keeps the severity", () => {
    expect(selectCandidates(all, {}).map(c => c.id)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    const shop = selectCandidates(rank(SHOP), {});
    expect(shop.map(c => c.id)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(shop.map(c => c.severity)).toEqual(["medium", "high", "critical"]);
    expect(selectCandidates(rank(INTERNAL), {}).map(c => c.id)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
  });

  it("fixes in that order, and the plan says why", async () => {
    const dir = tmp();
    const file = join(dir, "c.json"); writeFileSync(file, JSON.stringify(SHOP));
    const calls: string[] = [];
    const deps: BurndownDeps = { listCandidates: () => all, repoRoot: async () => "/repo", fix: async id => { calls.push(id); return undefined; }, store: { load: () => ({ version: 1, findings: {}, runs: [] }), save: () => {} }, now: () => 1, err: () => {}, contextLoad: { settings: {} } };
    const options: BurndownOptions = { pr: true, timeout: "60", concurrency: "1", budget: "10", perFix: "3", maxConsecutiveFailures: "9", maxFailureRate: "1", context: file };
    const plan = await runBurndown({ ...options, dryRun: true }, deps);
    expect(plan.items.map(item => item.finding)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(renderReport(plan)).toContain("Operator business context (unverified): ranked higher (+2): payments, personal-data. card data");
    expect(plan.items[0]!.severity).toBe("medium");
    await runBurndown(options, deps);
    expect(calls).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    const bad = join(dir, "bad.json"); writeFileSync(bad, "[]");
    await expect(runBurndown({ ...options, context: bad }, deps)).rejects.toThrow("entries");
    expect(calls).toHaveLength(3);
  });

  it("matches repository rules against the repository being fixed", async () => {
    const dir = tmp();
    const file = join(dir, "c.json"); writeFileSync(file, JSON.stringify({ repositories: { "acme/shop": SHOP.entries } }));
    const options: BurndownOptions = { pr: true, timeout: "60", concurrency: "1", budget: "10", perFix: "3", maxConsecutiveFailures: "9", maxFailureRate: "1", context: file, dryRun: true };
    const deps = (): BurndownDeps => ({ listCandidates: () => all, repoRoot: async () => "/repo", fix: async () => undefined, store: { load: () => ({ version: 1, findings: {}, runs: [] }), save: () => {} }, now: () => 1, err: () => {}, contextLoad: { detect: async () => "acme/shop" } });
    expect((await runBurndown(options, deps())).items[0]!.finding).toBe("checkout-medium");
    expect((await runBurndown({ ...options, repository: "acme/elsewhere" }, deps())).items[0]!.finding).toBe("demo-critical");
  });
});

describe("export-fixes", () => {
  it("orders the fix outcomes by the context and adds the reason", async () => {
    const key = (fp: string) => `/repo\u0000${fp}`;
    const record = (finding: string, at: string) => ({ finding, branch: `0/fix-${finding}`, result: "pr-opened" as const, runId: "r", updatedAt: at });
    const state = { version: 1 as const, runs: [], findings: { [key("a")]: record("f-aaaaaaaaaaaa", "2026-01-01T00:00:00Z"), [key("b")]: record("f-bbbbbbbbbbbb", "2026-01-02T00:00:00Z") } };
    const deps: ExportFixesDeps = {
      store: { load: () => state, save: () => {} },
      lookup: () => new Map([["f-aaaaaaaaaaaa", { title: "Demo", severity: "critical", category: "xss", path: "examples/demo.ts" }], ["f-bbbbbbbbbbbb", { title: "Checkout", severity: "medium", category: "xss", path: "src/payments/checkout.ts" }]]),
      host: () => { throw new Error("no host"); }, repoRoot: async dir => dir, now: () => new Date("2026-06-01T00:00:00Z"), out: () => {}, err: () => {}, writeReport: () => {},
    };
    const plain = await buildFixReport({}, deps);
    expect(plain.fixes.map(row => row.title)).toEqual(["Demo", "Checkout"]);
    expect(plain.fixes[0]!.businessContext).toBeUndefined();
    const ranked = await buildFixReport({ ranking: loaded(SHOP) }, deps);
    expect(ranked.fixes.map(row => row.title)).toEqual(["Checkout", "Demo"]);
    expect(ranked.fixes[0]).toMatchObject({ severity: "medium", businessContext: { shift: 2 } });
    expect(renderFixReportMarkdown(ranked)).toContain("Why ranked");
    expect(renderFixReportMarkdown(plain)).not.toContain("Why ranked");
  });
});

describe("rollup", () => {
  const row = (fingerprint: string, repository: string, severity: string, path: string): WorkRow => ({ repository, fingerprint, title: fingerprint, severity, category: "xss", status: "confirmed", triage: "new", owner: null, path, firstSeen: "2026-01-01T00:00:00Z", lastSeen: "2026-01-02T00:00:00Z" });
  const rows = [row("demo", "acme/shop", "critical", "examples/demo.ts"), row("checkout", "acme/shop", "medium", "src/payments/checkout.ts"), row("admin", "acme/internal", "high", "services/admin/panel.ts")];
  const now = new Date("2026-02-01T00:00:00Z");
  const ranker = (value: unknown) => { const ctx = loaded(value); return (r: { repository: string; severity: string; path?: string }) => labelFor(ctx, r, r.repository); };

  it("lists what to look at first, ordered by the context, and leaves the counts by real severity", () => {
    const shop = { ...summarise(rows, now), priority: priorityOf(rows, ranker({ repositories: { "acme/shop": SHOP.entries, "acme/internal": INTERNAL.entries } })) };
    // admin (high, +1) and checkout (medium, +2) tie at the top; the real severity breaks the tie.
    expect(shop.priority!.map(p => p.title)).toEqual(["admin", "checkout", "demo"]);
    expect(shop.priority![1]!.why).toContain("payments");
    expect(shop.bySeverity.find(c => c.name === "critical")!.count).toBe(1);
    const internal = { ...summarise(rows, now), priority: priorityOf(rows, ranker({ repositories: { "acme/internal": INTERNAL.entries } })) };
    expect(internal.priority!.map(p => p.title)).toEqual(["demo", "admin", "checkout"]);
    expect(summarise(rows, now).priority).toBeUndefined();
    expect(renderText(shop)).toContain("Look at first");
    expect(renderHtml(shop)).toContain("Look at first");
    expect(renderText(summarise(rows, now))).not.toContain("Look at first");
  });

  it("never writes the path into an export, and an export has no path to match, so only rules without a match apply to it", () => {
    const written = buildExport(rows, now);
    expect(JSON.stringify(written)).not.toContain("examples/demo.ts");
    const dir = tmp();
    const file = join(dir, "r.json");
    writeFileSync(file, JSON.stringify(written));
    const out: string[] = [];
    const deps: FindingsRollupDeps = { now: () => now, defaultDatabases: () => [], out: text => out.push(text), err: () => {}, writeFile: () => {} };
    runFindingsRollup([file], { format: "json", ranking: loaded({ entries: [{ tags: ["payments"] }] }) }, deps);
    expect((JSON.parse(out[0]!) as { priority: unknown[] }).priority).toHaveLength(3);
  });
});

describe("report draft", () => {
  it("adds why the finding ranks where it does, and nothing without a context", () => {
    const finding = { id: "f-1", templateId: "t", title: "Checkout flaw", description: "d", severity: "medium", category: "xss", status: "confirmed", evidence: { request: "", response: "" }, timestamp: Date.UTC(2026, 0, 1), reviewAnnotation: { path: "src/payments/checkout.ts", startLine: 3 } } as unknown as Finding;
    const deps = (): ReportDraftDeps => ({ out: () => {}, err: () => {}, write: () => {}, load: () => ({ finding: { ...finding } }), now: () => new Date("2026-02-01T00:00:00Z"), version: "1" });
    const text = (options: Parameters<typeof runReportDraft>[1]) => { let out = ""; const d = deps(); d.out = t => { out += t; }; runReportDraft("f-1", { stage: "early-warning", ...options }, d); return out; };
    expect(text({})).not.toContain("Operator business context");
    const draft = text({ ranking: loaded(SHOP) });
    expect(draft).toContain("Operator business context");
    expect(draft).toContain("ranked higher (+2): payments, personal-data. card data");
    expect(draft).toContain("medium (as recorded by the scanner");
  });
});

describe("scan report", () => {
  const stored = (id: string, severity: string, path: string): Finding => ({ id, templateId: "manual", title: `Finding ${id}`, description: "", severity, category: "xss", status: "discovered", timestamp: 1, fingerprint: id, evidence: { request: "", response: "", analysis: "" }, reviewAnnotation: { path, startLine: 1 } }) as Finding;
  const base: ScanOutcome = { target: "repo", threadId: "t", startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:01:00.000Z", budgetUsd: 5, budgetExhausted: false, failed: false, summary: "" };
  const findings = [stored("admin-high", "high", "services/admin/panel.ts"), stored("checkout-medium", "medium", "src/payments/checkout.ts"), stored("demo-critical", "critical", "examples/demo.ts")];
  const report = (outcome: ScanOutcome) => ({ target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings, warnings: [] }) as never;

  it("orders the JSON and every export by the context and keeps real severity in the counts", async () => {
    const shop = { ...base, businessContext: parse(SHOP) };
    const json = scanJson(shop, findings) as { counts: Record<string, number>; findings: Array<{ id: string; severity: string; businessContext?: { shift: number; tags: string[] } }> };
    expect(json.findings.map(f => f.id)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(json.findings.map(f => f.severity)).toEqual(["medium", "high", "critical"]);
    expect(json.findings[0]!.businessContext).toMatchObject({ shift: 2, tags: ["payments", "personal-data"] });
    expect(json.counts).toMatchObject({ critical: 1, high: 1, medium: 1 });
    expect((scanJson(base, findings) as { findings: Array<{ id: string }> }).findings.map(f => f.id)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    expect(JSON.stringify(scanJson(base, findings))).not.toContain("businessContext");
    const md = new TextDecoder().decode((await exportReport(toScanReport(shop, report(shop)), "markdown", "x")).body);
    expect(md.indexOf("Finding checkout-medium")).toBeLessThan(md.indexOf("Finding demo-critical"));
    expect(md).toContain("Business priority");
    const second = { ...base, businessContext: parse(INTERNAL) };
    expect((scanJson(second, findings) as { findings: Array<{ id: string }> }).findings.map(f => f.id)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
  });

  it("decides --fail-on by the real severity, whatever the context says", () => {
    const lowering = { ...base, businessContext: parse({ entries: [{ match: "examples/**", tags: ["non-production"] }, { match: "services/**", tags: ["internal-only"] }] }) };
    // The critical demo finding drops two steps in the order; it still fails --fail-on critical.
    expect(scanExitCode(lowering, findings, "critical")).toBe(1);
    expect(scanExitCode(lowering, [stored("m", "medium", "src/payments/checkout.ts")], "high")).toBe(0);
    // Raising a medium finding to the top of the list does not make it fail --fail-on high.
    const raising = { ...base, businessContext: parse(SHOP) };
    expect(scanExitCode(raising, [stored("m", "medium", "src/payments/checkout.ts")], "high")).toBe(0);
    expect(scanExitCode(raising, [stored("m", "medium", "src/payments/checkout.ts")], "medium")).toBe(1);
    expect(scanExitCode(raising, findings, undefined)).toBe(0);
  });
});

describe("flags typed after the subcommand", () => {
  it("reach export, rollup and context check even though findings declares them too", async () => {
    const { dir, dbPath } = savedDatabase();
    const shop = join(dir, "shop.json"); writeFileSync(shop, JSON.stringify(SHOP));
    const out: string[] = [], chunks: Uint8Array[] = [];
    const program = new Command().exitOverride();
    registerFindingsCommand(program);
    const findings = program.commands.find(command => command.name() === "findings")!;
    registerFindingsExportCommand(findings, { out: () => {}, err: () => {}, writeBytes: () => {}, writeStdout: bytes => chunks.push(bytes), contextLoad: { settings: {} } });
    registerFindingsRollupCommand(findings, { now: () => new Date("2026-02-01T00:00:00Z"), defaultDatabases: () => [], out: text => out.push(text), err: () => {}, writeFile: () => {} });
    registerFindingsContextCommand(findings, { out: text => out.push(text), err: () => {} });
    await program.parseAsync(["findings", "export", "--format", "md", "--db-path", dbPath, "--context", shop], { from: "user" });
    expect(orderIn(Buffer.concat(chunks).toString("utf8"))).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    await program.parseAsync(["findings", "rollup", dbPath, "--format", "json", "--context", shop, "--repository", "acme/shop"], { from: "user" });
    const rollup = JSON.parse(out.at(-1)!) as { priority: Array<{ repository: string; title: string }> };
    expect(rollup.priority.map(row => row.repository)).toEqual(["acme/shop", "acme/shop", "acme/shop"]);
    expect(rollup.priority[0]!.title).toBe("Finding checkout-medium");
    await program.parseAsync(["findings", "context", "check", shop, "--db-path", dbPath, "--json"], { from: "user" });
    expect((JSON.parse(out.at(-1)!) as { findings: number }).findings).toBe(3);
    process.exitCode = undefined;
  });
});

describe("reports export", () => {
  it("orders a share-safe copy by the context and keeps the reasons and severities out of the change", async () => {
    const dir = tmp();
    const finding = (id: string, severity: string, path: string) => ({ id, templateId: "t", title: id, description: "d", severity, category: "xss", status: "discovered", evidence: { request: "", response: "" }, timestamp: 1, location: { path, startLine: 1 } });
    const report = join(dir, "report.json");
    writeFileSync(report, JSON.stringify({ target: "repo", scanDepth: "default", startedAt: "a", completedAt: "b", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 3, critical: 1, high: 1, medium: 1, low: 0, info: 0 }, warnings: [], findings: [finding("demo-critical", "critical", "examples/demo.ts"), finding("admin-high", "high", "services/admin/panel.ts"), finding("checkout-medium", "medium", "src/payments/checkout.ts")] }));
    const context = join(dir, "c.json"); writeFileSync(context, JSON.stringify(SHOP));
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const run = async (...extra: string[]) => { log.mockClear(); const program = new Command().exitOverride(); registerReportsCommand(program); await program.parseAsync(["reports", "export", report, ...extra], { from: "user" }); return String(log.mock.calls[0]![0]); };
    const plain = JSON.parse(await run()) as { findings: Array<{ id: string }> };
    expect(plain.findings.map(f => f.id)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    const ranked = await run("--context", context);
    const parsed = JSON.parse(ranked) as { findings: Array<{ id: string; severity: string }> };
    expect(parsed.findings.map(f => f.id)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    expect(parsed.findings.map(f => f.severity)).toEqual(["medium", "high", "critical"]);
    expect(ranked).not.toContain("card data");
    expect(ranked).not.toContain("payments");
    expect(ranked).not.toContain("businessContext");
    log.mockRestore();
  });
});
