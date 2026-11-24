#!/usr/bin/env node
// Second-opinion benchmark: does `0 scan --known <sarif>` find planted bugs that a baseline scanner misses?
//   node scripts/bench/second-opinion.mjs --baseline-only                 run only the baseline tools (free) and show what they miss
//   node scripts/bench/second-opinion.mjs --dry-run                       no model, no cost: check the plan
//   node scripts/bench/second-opinion.mjs --run [--tools foxguard,semgrep] [--repeat 2] [--budget 0.5] [--max-cost 3]
// For each fixture with planted items it runs the baseline tool, scores the tool's own SARIF against the answer key, then
// scans the fixture with and without `--known <tool sarif>` (fresh HOME per run) and reports, for the items the tool missed,
// how often the scan found them, and what share of the reported findings are new. See docs/design/benchmark.md.
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadFixtures } from "./run.mjs";
import { scoreFindings } from "./match.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");

export function parseArgs(argv) {
  const o = { run: false, dryRun: false, repeat: 2, budget: 0.5, maxCost: 3, tools: ["foxguard", "semgrep"], fixtures: undefined, model: undefined, timeout: 900, cli: join(repoRoot, "packages/cli/dist/index.js"), out: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--baseline-only") o.baselineOnly = true;
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--budget") o.budget = Number(next());
    else if (a === "--max-cost") o.maxCost = Number(next());
    else if (a === "--tools") o.tools = next().split(",");
    else if (a === "--fixtures") o.fixtures = next().split(",");
    else if (a === "--model") o.model = next();
    else if (a === "--timeout") o.timeout = Number(next());
    else if (a === "--out") o.out = resolve(next());
    else throw new Error(`unknown option ${a}`);
  }
  if (o.run === o.dryRun && !o.baselineOnly) throw new Error("pass exactly one of --run (spends model money) or --dry-run (free)");
  for (const t of o.tools) if (!["foxguard", "semgrep"].includes(t)) throw new Error(`unknown tool ${t} (foxguard, semgrep)`);
  return o;
}

/** A SARIF log's results as findings the matcher can score: the rule id and message stand in for the category and title. */
export function sarifFindings(sarif) {
  const out = [];
  for (const run of sarif.runs ?? []) {
    const rules = new Map((run.tool?.driver?.rules ?? []).map((r) => [r.id, r]));
    for (const res of run.results ?? []) {
      const loc = res.locations?.[0]?.physicalLocation;
      const region = loc?.region ?? {};
      const rule = rules.get(res.ruleId);
      const cwe = [...(rule?.properties?.tags ?? []), ...(res.properties?.tags ?? [])].join(" ");
      if (!loc?.artifactLocation?.uri) continue;
      out.push({ id: res.ruleId, title: `${res.ruleId} ${res.message?.text ?? ""} ${cwe}`, category: "other", description: "", location: { path: loc.artifactLocation.uri.replace(/^file:\/\//, ""), startLine: region.startLine, endLine: region.endLine } });
    }
  }
  return out;
}

function findFoxguard() {
  const candidates = [process.env.ZERO_FOXGUARD_PATH, join(homedir(), ".0", "bin", "foxguard")].filter(Boolean);
  return candidates.find((c) => existsSync(c)) ?? "foxguard";
}

/** The tool's SARIF for a folder, as text. Paths in it are relative to the folder when the tool allows it. */
function runTool(tool, folder) {
  if (tool === "foxguard") {
    const p = spawnSync(findFoxguard(), ["--format", "sarif", folder], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 120000 });
    return p.stdout;
  }
  const p = spawnSync(process.env.ZERO_SEMGREP_PATH || "semgrep", ["scan", "--sarif", "--quiet", "--metrics", "off", "--config", "p/default", folder], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 300000 });
  return p.stdout;
}

/** Make SARIF paths relative to the folder so the scan's findings and the known items name files the same way. */
export function relativize(sarifText, folder) {
  const log = JSON.parse(sarifText);
  const base = folder.replace(/\/+$/, "");
  for (const run of log.runs ?? []) for (const res of run.results ?? []) for (const loc of res.locations ?? []) {
    const art = loc.physicalLocation?.artifactLocation;
    if (!art?.uri) continue;
    art.uri = art.uri.replace(/^file:\/\//, "");
    if (art.uri.startsWith(`${base}/`)) art.uri = art.uri.slice(base.length + 1);
    // macOS temp folders are symlinks: also accept the real path.
    const real = base.replace(/^\/var\//, "/private/var/");
    if (art.uri.startsWith(`${real}/`)) art.uri = art.uri.slice(real.length + 1);
  }
  return JSON.stringify(log);
}

function scan(fixture, knownFile, o, label) {
  const root = mkdtempSync(join(tmpdir(), "0-so-"));
  const home = join(root, "home");
  const folder = join(root, "app");
  mkdirSync(home, { recursive: true });
  cpSync(fixture.dir, folder, { recursive: true, filter: (src) => !src.endsWith("answer.json") });
  const outFile = join(root, "report.json");
  const env = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, "config"), XDG_DATA_HOME: join(home, "data"), XDG_CACHE_HOME: join(home, "cache") };
  const args = ["scan", folder, "--budget", String(o.budget), "--format", "json", "-o", outFile, "--timeout", String(o.timeout), "--prepass", "off", ...(knownFile ? ["--known", knownFile] : []), ...(o.model ? ["--model", o.model] : [])];
  const proc = spawnSync(process.execPath, [o.cli, ...args], { env, encoding: "utf8", timeout: (o.timeout + 120) * 1000, cwd: repoRoot });
  let report;
  try { report = JSON.parse(readFileSync(outFile, "utf8")); } catch { /* no report */ }
  return { label, report, status: report?.status ?? `no-report (exit ${proc.status})`, costUsd: report?.costUsd ?? 0, stderr: report ? "" : (proc.stderr ?? "").slice(-300) };
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  const fixtures = loadFixtures(o.fixtures).filter((fx) => fx.answer.items.length > 0);
  if (o.dryRun && !o.baselineOnly) {
    const scans = fixtures.length * (o.repeat + o.tools.length * o.repeat);
    console.log(`${fixtures.length} fixtures with planted items; ${scans} scans (${o.repeat} generic + ${o.tools.length} x ${o.repeat} with --known per fixture); worst case $${(scans * o.budget).toFixed(2)} at --budget ${o.budget}, capped at --max-cost ${o.maxCost}`);
    return;
  }
  if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build the engine and the CLI first`);
  const { classifyKnown } = await import(join(repoRoot, "packages/engine/dist/shared/index.js"));
  const { parseSarif } = await import(join(repoRoot, "packages/engine/dist/shared/index.js"));
  let spent = 0;
  const rows = [];
  const results = [];
  for (const fx of fixtures) {
    const staging = mkdtempSync(join(tmpdir(), "0-so-stage-"));
    cpSync(fx.dir, join(staging, "app"), { recursive: true, filter: (src) => !src.endsWith("answer.json") });
    const toolInfo = {};
    for (const tool of o.tools) {
      const text = runTool(tool, join(staging, "app"));
      let sarif;
      try { sarif = relativize(text, join(staging, "app")); JSON.parse(sarif); } catch { console.log(`${fx.name}: ${tool} produced no SARIF; skipped`); continue; }
      const file = join(staging, `${tool}.sarif`);
      writeFileSync(file, sarif);
      const score = scoreFindings(fx.answer, sarifFindings(JSON.parse(sarif)));
      toolInfo[tool] = { file, score, missed: score.missedIds, known: parseSarif(sarif).findings };
      console.log(`${fx.name}: ${tool} reports ${score.findings} item(s), finds ${score.found}/${score.planted} planted; missed: ${score.missedIds.join(", ") || "none"}`);
    }
    if (o.baselineOnly) continue;
    const configs = [{ name: "generic", file: undefined }, ...Object.entries(toolInfo).map(([tool, info]) => ({ name: `known-${tool}`, file: info.file, tool }))];
    for (let rep = 1; rep <= o.repeat; rep++) for (const cfg of configs) {
      if (spent >= o.maxCost) { console.log(`stopped: spent $${spent.toFixed(3)} reached --max-cost ${o.maxCost}`); break; }
      const r = scan(fx, cfg.file, o, cfg.name);
      spent += r.costUsd;
      const findings = r.report?.findings ?? [];
      const score = scoreFindings(fx.answer, findings);
      // Against each tool's known set: how many of the reported findings are new, and which missed items were found.
      for (const [tool, info] of Object.entries(toolInfo)) {
        if (cfg.name !== "generic" && cfg.tool !== tool) continue;
        const located = findings.filter((f) => f.location?.path).map((f) => ({ ...f, reviewAnnotation: { path: f.location.path, startLine: f.location.startLine, endLine: f.location.endLine } }));
        const classified = classifyKnown(located, info.known);
        const fresh = classified.filter((f) => f.knownStatus === "new").length + (findings.length - located.length);
        const missedFound = info.missed.filter((id) => score.foundIds.includes(id));
        results.push({ fixture: fx.name, config: cfg.name, against: tool, repeat: rep, status: r.status, costUsd: r.costUsd, findings: findings.length, newFindings: fresh, missedByTool: info.missed.length, missedFound: missedFound.length, plantedFound: score.found, planted: score.planted, falsePositives: score.falsePositives });
      }
      console.log(`  ${fx.name} / ${cfg.name} / repeat ${rep}: ${r.status}, ${score.found}/${score.planted} planted found, ${findings.length} findings, $${r.costUsd.toFixed(4)} (total $${spent.toFixed(3)})${r.stderr ? `\n    ${r.stderr}` : ""}`);
    }
  }
  const lines = ["fixture,against,config,repeat,status,cost,findings,new,missedByTool,missedFound,plantedFound,planted,falsePositives", ...results.map((r) => [r.fixture, r.against, r.config, r.repeat, r.status, r.costUsd.toFixed(4), r.findings, r.newFindings, r.missedByTool, r.missedFound, r.plantedFound, r.planted, r.falsePositives].join(","))];
  console.log(`\n${lines.join("\n")}\n\ntotal cost $${spent.toFixed(3)}`);
  if (o.out) writeFileSync(o.out, `${lines.join("\n")}\n`);
  // Summary per tool: recall of the items the tool missed, generic against --known, and the share of new findings.
  for (const tool of o.tools) {
    const sum = (cfg, key) => results.filter((r) => r.against === tool && (cfg === "generic" ? r.config === "generic" : r.config === `known-${tool}`)).reduce((a, r) => a + r[key], 0);
    const gen = { missed: sum("generic", "missedByTool"), found: sum("generic", "missedFound"), findings: sum("generic", "findings"), fresh: sum("generic", "newFindings") };
    const kn = { missed: sum("known", "missedByTool"), found: sum("known", "missedFound"), findings: sum("known", "findings"), fresh: sum("known", "newFindings") };
    const pct = (a, b) => (b ? `${((a / b) * 100).toFixed(0)}%` : "n/a");
    console.log(`${tool}: items missed by the tool found: generic ${gen.found}/${gen.missed} (${pct(gen.found, gen.missed)}), --known ${kn.found}/${kn.missed} (${pct(kn.found, kn.missed)}); findings new: generic ${gen.fresh}/${gen.findings} (${pct(gen.fresh, gen.findings)}), --known ${kn.fresh}/${kn.findings} (${pct(kn.fresh, kn.findings)})`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
