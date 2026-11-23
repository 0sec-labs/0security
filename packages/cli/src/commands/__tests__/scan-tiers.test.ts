import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ImportedFinding } from "@0/engine/shared";
import { runScan, type ScanDeps } from "../scan.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "scan-tiers-run-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

const options = (extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "60", skill: "scan", passes: "1", batches: "auto", ...extra }) as never;
const snapshot = { session: { id: "t1", status: "ready" }, usage: { costUsd: 0.1 }, messages: [{ role: "assistant", content: [{ type: "text", text: "Covered." }] }] };
const finding = (over: Record<string, unknown> = {}) => ({ id: "f1", templateId: "manual", title: "SQL injection in owner filter", description: "d", severity: "high", category: "sql-injection", status: "discovered", timestamp: 1, evidence: { request: "r", response: "s", analysis: "The owner query parameter is concatenated into the SQL string passed to db.query." }, reviewAnnotation: { path: "server.js", startLine: 22 }, ...over });
const stored = (findings: unknown[]) => ({ target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings, warnings: [] });
const lead = (over: Partial<ImportedFinding> = {}): ImportedFinding => ({ tool: "foxguard", ruleId: "js/sqli", title: "SQL injection", description: "tainted query", severity: "high", category: "sql-injection", path: "server.js", startLine: 22, fingerprint: "sarif:abc", cwe: ["CWE-89"], ...over });

function fakes(findings: unknown[] = [], extra: Partial<ScanDeps> = {}) {
  const requests: Array<[string, string, unknown]> = [];
  const out: string[] = [];
  const err: string[] = [];
  const client = { request: vi.fn(async (method: string, path: string, body?: unknown) => { requests.push([method, path, body]); return method === "GET" ? { snapshot } : { session: { id: "t1" } }; }), dispose: vi.fn() };
  const deps: ScanDeps = {
    open: vi.fn(async () => client as never), out: bytes => out.push(typeof bytes === "string" ? bytes : Buffer.from(bytes).toString("utf8")), err: text => err.push(text), sleep: async () => {}, now: () => new Date("2026-01-01T00:00:00Z"),
    writeBytes: vi.fn(), loadReport: vi.fn(async () => stored(findings) as never), startConsole: vi.fn(async () => () => {}), changedFiles: vi.fn(async () => undefined),
    prePass: vi.fn(async () => undefined), diffFiles: vi.fn(async () => []), clone: vi.fn(), gitRemote: vi.fn(async () => "git@github.com:acme/payments.git"), ...extra,
  };
  return { deps, requests, out, err, client };
}
const tierFile = (text: string) => { const path = join(temp(), "tiers.yaml"); writeFileSync(path, text); return path; };
const TIERS = `
default: standard
tiers:
  critical: { budget: 12, batches: off, reason: card data }
  light: { prepassOnly: true }
  skip: { reason: archived }
repositories:
  - repo: acme/payments
    tier: critical
  - repo: acme/archive
    tier: skip
  - repo: acme/quick
    tier: light
    reason: low risk
`;
const json = (out: string[]) => JSON.parse(out.join(""));

describe("scan tiers", () => {
  it("applies the tier's budget and says which tier applied and why", async () => {
    const { deps, requests, err, out } = fakes([finding()]);
    await runScan(temp(), options({ tiers: tierFile(TIERS) }), deps);
    const created = requests.find(([method, path]) => method === "POST" && path === "/api/console/sessions")!;
    expect((created[2] as { costCeilingUsd: number }).costCeilingUsd).toBe(12);
    expect(err.join("\n")).toContain("tier critical (repository acme/payments matched exactly; reason: card data): budget $12, batches off, skill scan");
    expect(json(out).tier).toMatchObject({ name: "critical", source: "exact-repo", match: "acme/payments", reason: "card data" });
  });
  it("lets a typed flag win over the tier", async () => {
    const { deps, requests, err } = fakes([finding()]);
    await runScan(temp(), options({ tiers: tierFile(TIERS), budget: "2", explicit: ["budget"] }), deps);
    const created = requests.find(([method, path]) => method === "POST" && path === "/api/console/sessions")!;
    expect((created[2] as { costCeilingUsd: number }).costCeilingUsd).toBe(2);
    expect(err.join("\n")).toContain("--budget 2 overrides the tier budget $12");
  });
  it("skips explicitly: status skipped, exit 0, no console, no model", async () => {
    const { deps, out, err } = fakes([], { gitRemote: vi.fn(async () => "https://github.com/acme/archive.git") });
    await runScan(temp(), options({ tiers: tierFile(TIERS) }), deps);
    expect(deps.open).not.toHaveBeenCalled();
    expect(deps.prePass).not.toHaveBeenCalled();
    expect(err.join("\n")).toContain("skipped by tier skip: archived");
    const report = json(out);
    expect(report).toMatchObject({ status: "skipped", summary: "skipped by tier skip: archived", tier: { name: "skip", skipped: true }, counts: { total: 0 } });
    expect(process.exitCode).toBeUndefined();
  });
  it("exits 1 for a skipped scan with --fail-on-skip", async () => {
    const { deps } = fakes([], { gitRemote: vi.fn(async () => "git@github.com:acme/archive.git") });
    await runScan(temp(), options({ tiers: tierFile(TIERS), failOnSkip: true }), deps);
    expect(process.exitCode).toBe(1);
  });
  it("says 'skipped' in the markdown and SARIF reports, never 'no vulnerabilities found'", async () => {
    for (const format of ["md", "sarif"]) {
      const { deps, out } = fakes([], { gitRemote: vi.fn(async () => "git@github.com:acme/archive.git") });
      await runScan(temp(), options({ tiers: tierFile(TIERS), format }), deps);
      const text = out.join("");
      expect(text).not.toMatch(/No Findings|passed all tests/);
      if (format === "md") expect(text).toContain("Skipped by tier skip: archived");
      else expect(JSON.parse(text).runs[0].properties.tier).toMatchObject({ name: "skip", skipped: true });
    }
  });
  it("runs the scanners only for a pre-pass-only tier and labels every finding", async () => {
    const { deps, out, err } = fakes([], { gitRemote: vi.fn(async () => "git@github.com:acme/quick.git"), prePass: vi.fn(async () => ({ tools: ["foxguard"], leads: [lead()], total: 1 })) });
    await runScan(temp(), options({ tiers: tierFile(TIERS) }), deps);
    expect(deps.open).not.toHaveBeenCalled();
    expect(deps.prePass).toHaveBeenCalled();
    const report = json(out);
    expect(report.status).toBe("prepass_only");
    expect(report.tier).toMatchObject({ name: "light", prepassOnly: true, reason: "low risk" });
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].description).toContain("Pre-pass only, not reviewed by a model.");
    expect(report.findings[0].location).toMatchObject({ path: "server.js", startLine: 22 });
    expect(err.join("\n")).toContain("not reviewed by a model");
  });
  it("fails a pre-pass-only scan when no scanner could run, instead of reporting a clean result", async () => {
    const { deps, out } = fakes([], { gitRemote: vi.fn(async () => "git@github.com:acme/quick.git") });
    await runScan(temp(), options({ tiers: tierFile(TIERS) }), deps);
    expect(json(out)).toMatchObject({ status: "failed" });
    expect(process.exitCode).toBe(1);
  });
  it("refuses --prepass off for a pre-pass-only tier", async () => {
    const { deps, err } = fakes([], { gitRemote: vi.fn(async () => "git@github.com:acme/quick.git") });
    await runScan(temp(), options({ tiers: tierFile(TIERS), prepass: "off" }), deps);
    expect(err.join("\n")).toContain("drop --prepass off");
    expect(process.exitCode).toBe(2);
  });
  it("shows the tier in --plan", async () => {
    const { deps, out } = fakes();
    await runScan(temp(), options({ tiers: tierFile(TIERS), plan: true, format: "md" }), deps);
    expect(out.join("")).toContain("Tier: critical (card data)");
    const second = fakes();
    await runScan(temp(), options({ tiers: tierFile(TIERS), plan: true, format: "json" }), second.deps);
    expect(json(second.out).tier).toMatchObject({ name: "critical", source: "exact-repo" });
  });
  it("uses the default tier for a folder with no remote and no matching path", async () => {
    const { deps, err } = fakes([finding()], { gitRemote: vi.fn(async () => undefined) });
    await runScan(temp(), options({ tiers: tierFile(TIERS) }), deps);
    expect(err.join("\n")).toContain("no entry matched, so the default applies");
  });
  it("reports a bad tier file as a usage error that names the entry", async () => {
    const { deps, err } = fakes();
    await runScan(temp(), options({ tiers: tierFile("repositories:\n  - repo: acme/x\n    tier: gold\n") }), deps);
    expect(err.join("\n")).toContain("repositories[0]: tier must be one of");
    expect(process.exitCode).toBe(2);
  });
  it("warns when the named tier file sits inside the scanned folder", async () => {
    const repo = temp();
    const path = join(repo, "tiers.yaml");
    writeFileSync(path, TIERS);
    const { deps, err } = fakes([finding()]);
    await runScan(repo, options({ tiers: path }), deps);
    expect(err.join("\n")).toContain("is inside the folder being scanned");
  });
  it("does not read a tier file from the scanned folder", async () => {
    const repo = temp();
    writeFileSync(join(repo, "scan-tiers.yaml"), "default: skip\n");
    const { deps, out } = fakes([finding()]);
    await runScan(repo, options(), deps);
    expect(json(out).status).toBe("complete");
    expect(json(out).tier).toBeUndefined();
  });
});

describe("scan --known", () => {
  const sarif = (path: string) => { const file = join(temp(), "known.sarif"); writeFileSync(file, JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "semgrep" } }, results: [{ ruleId: "js.sqli", level: "error", message: { text: "Possible SQL injection" }, locations: [{ physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 22 } } }] }] }] })); return file; };
  const authz = finding({ id: "f2", title: "Missing ownership check on order", category: "missing-authorization", reviewAnnotation: { path: "routes.js", startLine: 8 }, evidence: { request: "", response: "", analysis: "GET /orders/:id returns any order without comparing the owner to the caller." } });

  it("tells the thread what is known, in a delimited block", async () => {
    const { deps, requests, err } = fakes([authz]);
    await runScan(temp(), options({ known: [sarif("server.js")] }), deps);
    const message = requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string };
    expect(message.text).toContain("<known-findings>");
    expect(message.text).toContain("- semgrep server.js:22 js.sqli: Possible SQL injection");
    expect(err.join("\n")).toContain("known: 1 item from semgrep");
  });
  it("separates new and already-known in JSON, marks confirmedIndependently, and --only-new hides the matched ones", async () => {
    const rediscovered = finding();
    const shallow = finding({ id: "f3", evidence: { request: "", response: "", analysis: "" }, reviewAnnotation: { path: "server.js", startLine: 24 } });
    const all = fakes([authz, rediscovered, shallow]);
    await runScan(temp(), options({ known: [sarif("server.js")] }), all.deps);
    const report = json(all.out);
    const byId = Object.fromEntries(report.findings.map((item: { id: string; knownStatus: string }) => [item.id, item.knownStatus]));
    expect(byId).toEqual({ f2: "new", f1: "already-known", f3: "already-known" });
    expect(report.findings.find((item: { id: string }) => item.id === "f1").confirmedIndependently).toBe(true);
    expect(report.findings.find((item: { id: string }) => item.id === "f3").confirmedIndependently).toBeUndefined();
    expect(report.known).toMatchObject({ tools: ["semgrep"], total: 1, findings: { new: 1, alreadyKnown: 2, confirmedIndependently: 1 } });
    expect(report.findings.find((item: { id: string }) => item.id === "f1").knownBy).toMatchObject({ tool: "semgrep", ruleId: "js.sqli" });

    const only = fakes([authz, rediscovered, shallow]);
    await runScan(temp(), options({ known: [sarif("server.js")], onlyNew: true }), only.deps);
    const filtered = json(only.out);
    expect(filtered.findings.map((item: { id: string }) => item.id)).toEqual(["f2"]);
    expect(filtered.counts.total).toBe(1);
    expect(filtered.known.hidden).toBe(2);
  });
  it("carries knownStatus in the SARIF properties and the markdown", async () => {
    const sarifRun = fakes([authz, finding()]);
    await runScan(temp(), options({ known: [sarif("server.js")], format: "sarif" }), sarifRun.deps);
    const parsed = JSON.parse(sarifRun.out.join(""));
    expect(parsed.runs[0].results.map((result: { properties: { knownStatus: string } }) => result.properties.knownStatus).sort()).toEqual(["already-known", "new"]);
    expect(parsed.runs[0].results.some((result: { properties: { confirmedIndependently?: boolean } }) => result.properties.confirmedIndependently === true)).toBe(true);
    expect(parsed.runs[0].properties.known.findings).toEqual({ new: 1, alreadyKnown: 1, confirmedIndependently: 1 });
    const md = fakes([authz, finding()]);
    await runScan(temp(), options({ known: [sarif("server.js")], format: "md" }), md.deps);
    expect(md.out.join("")).toContain("**Known status:** already-known, confirmed independently");
    expect(md.out.join("")).toContain("1 new and 1 already known findings; 1 of the known ones were confirmed independently");
  });
  it("does not fail --fail-on for a known finding under --only-new", async () => {
    const { deps } = fakes([finding()]);
    await runScan(temp(), options({ known: [sarif("server.js")], onlyNew: true, failOn: "high" }), deps);
    expect(process.exitCode).toBeUndefined();
    const second = fakes([finding()]);
    await runScan(temp(), options({ known: [sarif("server.js")], failOn: "high" }), second.deps);
    expect(process.exitCode).toBe(1);
  });
  it("refuses a missing file, a file that is not SARIF, and --only-new without --known", async () => {
    for (const [extra, message] of [[{ known: ["/nonexistent.sarif"] }, "--known /nonexistent.sarif is not a file"], [{ onlyNew: true }, "--only-new needs --known"]] as const) {
      const { deps, err } = fakes();
      await runScan(temp(), options(extra), deps);
      expect(err.join("\n")).toContain(message);
      expect(process.exitCode).toBe(2);
      process.exitCode = undefined;
    }
    const notSarif = join(temp(), "x.sarif");
    writeFileSync(notSarif, "{\"hello\":1}");
    const { deps, err } = fakes();
    await runScan(temp(), options({ known: [notSarif] }), deps);
    expect(err.join("\n")).toContain("not a SARIF log");
    expect(process.exitCode).toBe(2);
  });
});

describe("scan tiers with the rest of the scan", () => {

  const sessionBudget = (requests: Array<[string, string, unknown]>) => (requests.find(([m, p]) => m === "POST" && p === "/api/console/sessions")![2] as { costCeilingUsd: number }).costCeilingUsd;
  let tierMap = "";
  beforeEach(() => { tierMap = tierFile(TIERS); });
  it("ranks a typed flag above the tier, the tier above the workflow default, and the workflow default above the built-in default", async () => {
    // The action puts the workflow default into options.budget and lists only typed flags in `explicit`.
    const workflow = fakes([finding()]);
    await runScan(temp(), options({ tiers: tierMap, budget: "7", explicit: [] }), workflow.deps);
    expect(sessionBudget(workflow.requests)).toBe(12);
    const typed = fakes([finding()]);
    await runScan(temp(), options({ tiers: tierMap, budget: "7", explicit: ["budget"] }), typed.deps);
    expect(sessionBudget(typed.requests)).toBe(7);
    // No tier file: the workflow default stands.
    const none = fakes([finding()]);
    await runScan(temp(), options({ budget: "7", explicit: [] }), none.deps);
    expect(sessionBudget(none.requests)).toBe(7);
  });
  it("sees a flag typed on the command line through the registered command", async () => {
    const { Command } = await import("commander");
    const { registerScanCommand } = await import("../scan.js");
    const run = async (args: string[]) => {
      const { deps, requests } = fakes([finding()]);
      const program = new Command().exitOverride();
      registerScanCommand(program, deps);
      await program.parseAsync(["node", "0", "scan", temp(), "--tiers", tierMap, "--format", "json", "--batches", "off", ...args]);
      return sessionBudget(requests);
    };
    expect(await run([])).toBe(12);
    expect(await run(["--budget", "3"])).toBe(3);
  });
  it("resolves a tier's skill name like --skill", async () => {
    const resolveSkill = vi.fn((skill: string) => `ext/pack/${skill}`);
    const { deps, requests } = fakes([finding()], { resolveSkill });
    await runScan(temp(), options({ tiers: tierFile("tiers:\n  standard: { skill: my-review }\n") }), deps);
    expect(resolveSkill).toHaveBeenCalledWith("my-review");
    expect(JSON.stringify(requests)).toContain("ext/pack/my-review");
  });
  it("writes a metrics line for a tier skip and for a pre-pass-only run", async () => {
    const skipped = fakes([], { metrics: vi.fn(), gitRemote: vi.fn(async () => "https://github.com/acme/archive.git") });
    await runScan(temp(), options({ tiers: tierMap }), skipped.deps);
    expect(skipped.deps.metrics).toHaveBeenCalledWith(expect.objectContaining({ command: "scan", status: "skipped", costUsd: null }));
    const pre = fakes([], { metrics: vi.fn(), gitRemote: vi.fn(async () => "https://github.com/acme/quick.git"), prePass: vi.fn(async () => ({ tools: ["foxguard"], leads: [lead()], total: 1 })) });
    await runScan(temp(), options({ tiers: tierMap }), pre.deps);
    expect(pre.deps.metrics).toHaveBeenCalledWith(expect.objectContaining({ command: "scan", status: "prepass_only", findingsProposed: 1 }));
  });
  it("runs a pre-pass-only tier through the same pre-pass call as a scan, with --repo-ignores and its warning", async () => {
    const prePass = vi.fn(async () => ({ tools: ["foxguard"], leads: [lead()], total: 1 }));
    const { deps, err } = fakes([], { gitRemote: vi.fn(async () => "https://github.com/acme/quick.git"), prePass });
    await runScan(temp(), options({ tiers: tierMap, repoIgnores: true }), deps);
    expect(prePass).toHaveBeenCalledWith(expect.any(String), expect.any(Array), expect.any(Array), { repoIgnores: true });
    expect(err.join("\n")).toContain("--repo-ignores makes the pre-pass scanners read");
    const plain = fakes([], { gitRemote: vi.fn(async () => "https://github.com/acme/quick.git"), prePass: vi.fn(async () => ({ tools: ["foxguard"], leads: [lead()], total: 1 })) });
    await runScan(temp(), options({ tiers: tierMap }), plain.deps);
    expect(plain.deps.prePass).toHaveBeenCalledWith(expect.any(String), expect.any(Array));
  });
});
