#!/usr/bin/env node
// Planted-bug benchmark runner. See docs/design/benchmark.md.
//   node scripts/bench/run.mjs --dry-run                 validate fixtures and the matcher, no model, no cost
//   node scripts/bench/run.mjs --run [--repeat 2] ...     really scan; spends model money up to the printed estimate
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mean, scoreFindings, spread, validateAnswer } from "./match.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const FIXTURES = join(here, "fixtures");
export const CONFIGS = ["generic", "skill", "foxguard", "checkov", "checkov-prepass", "single", "batched"];
const DEFAULT_CONFIGS = ["generic", "skill"];

export function parseArgs(argv) {
  const o = { run: false, dryRun: false, repeat: 1, budget: 0.2, configs: DEFAULT_CONFIGS, fixtures: undefined, model: undefined, out: join(here, "results"), cli: join(repoRoot, "packages/cli/dist/index.js"), timeout: 900, batchSize: 8, concurrency: 1, fixturesDir: FIXTURES };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--budget") o.budget = Number(next());
    else if (a === "--configs") o.configs = next().split(",");
    else if (a === "--fixtures") o.fixtures = next().split(",");
    else if (a === "--model") o.model = next();
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--cli") o.cli = resolve(next());
    else if (a === "--timeout") o.timeout = Number(next());
    else if (a === "--batch-size") o.batchSize = Number(next());
    else if (a === "--concurrency") o.concurrency = Number(next());
    else if (a === "--fixtures-dir") o.fixturesDir = resolve(next());
    else throw new Error(`unknown option ${a}`);
  }
  if (o.run === o.dryRun) throw new Error("pass exactly one of --run (spends model money) or --dry-run (free)");
  if (!Number.isInteger(o.repeat) || o.repeat < 1) throw new Error("--repeat must be a positive integer");
  if (!(o.budget > 0)) throw new Error("--budget must be a positive number of USD");
  for (const c of o.configs) if (!CONFIGS.includes(c)) throw new Error(`unknown config ${c} (known: ${CONFIGS.join(", ")})`);
  return o;
}

export function loadFixtures(only, root = FIXTURES) {
  const names = readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory() && existsSync(join(root, d.name, "answer.json"))).map((d) => d.name).sort();
  const picked = only ?? names;
  for (const n of picked) if (!names.includes(n)) throw new Error(`unknown fixture ${n} (known: ${names.join(", ")})`);
  return picked.map((name) => {
    const dir = join(root, name);
    const answer = JSON.parse(readFileSync(join(dir, "answer.json"), "utf8"));
    return { name, dir, answer };
  });
}

/** Line counts by path relative to the fixture, including files in sub-folders and dot folders. */
function fileLines(dir, prefix = "") {
  const out = {};
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (!prefix && e.name === "answer.json") continue;
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) { Object.assign(out, fileLines(join(dir, e.name), rel)); continue; }
    const text = readFileSync(join(dir, e.name), "utf8");
    out[rel] = text.split("\n").length - (text.endsWith("\n") ? 1 : 0);
  }
  return out;
}

/** The (fixture, config) runs that apply: the skill config only exists for fixtures that name a skill, the checkov configs only for the infrastructure fixture. */
export function planRuns(fixtures, configs) {
  const plan = [];
  for (const fx of fixtures) for (const config of configs) {
    if (config === "skill" && !fx.answer.skill) continue;
    if (config.startsWith("checkov") && fx.answer.skill !== "iac-review") continue;
    plan.push({ fixture: fx, config });
  }
  return plan;
}

export function scanArgs({ fixture, config }, folder, outFile, o) {
  const args = ["scan", folder, "--budget", String(o.budget), "--format", "json", "-o", outFile, "--timeout", String(o.timeout)];
  if (o.model) args.push("--model", o.model);
  if (config === "foxguard") args.push("--prepass", "auto", "--scanner", "foxguard");
  else if (config === "checkov-prepass") args.push("--prepass", "auto", "--scanner", "checkov");
  else args.push("--prepass", "off");
  if (config === "single") args.push("--batches", "off");
  if (config === "batched") args.push("--batches", "on", "--batch-size", String(o.batchSize), "--concurrency", String(o.concurrency));
  if (config === "skill") args.push("--skill", fixture.answer.skill);
  return args;
}

function findFoxguard() {
  const candidates = [process.env.ZERO_FOXGUARD_PATH, join(homedir(), ".0", "bin", "foxguard")].filter(Boolean);
  const hit = candidates.find((c) => existsSync(c));
  if (hit) return hit;
  const which = spawnSync("which", ["foxguard"], { encoding: "utf8" });
  return which.status === 0 ? which.stdout.trim() : undefined;
}

/** Checkov findings from its SARIF, shaped like scan findings so the matcher can score them. */
export function checkovFindings(sarif) {
  const out = [];
  for (const r of sarif.runs ?? []) for (const res of r.results ?? []) {
    const loc = res.locations?.[0]?.physicalLocation;
    const region = loc?.region ?? {};
    out.push({ id: res.ruleId, title: `${res.ruleId} ${res.message?.text ?? ""}`, category: "other", description: "", location: loc ? { path: loc.artifactLocation?.uri ?? "", startLine: region.startLine, endLine: region.endLine } : undefined });
  }
  return out;
}

/** Checkov on its own: no model, so no cost. Its report is a file, so it is read from a scratch folder. */
function runCheckov(run, repeatIndex, o, folder, root) {
  const out = join(root, "checkov-out");
  mkdirSync(out, { recursive: true });
  const started = Date.now();
  const proc = spawnSync(process.env.ZERO_CHECKOV_PATH || "checkov", ["-d", folder, "-o", "sarif", "--output-file-path", out, "--quiet", "--skip-download"], { encoding: "utf8", timeout: o.timeout * 1000, cwd: root });
  let findings = []; let status = "complete"; let error;
  try { findings = checkovFindings(JSON.parse(readFileSync(join(out, "results_sarif.sarif"), "utf8"))); } catch { status = `no-report (exit ${proc.status})`; error = (proc.stderr ?? "").slice(-300); }
  return { fixture: run.fixture.name, config: run.config, repeat: repeatIndex + 1, seconds: (Date.now() - started) / 1000, costUsd: 0, status, error, score: scoreFindings(run.fixture.answer, findings), workdir: root };
}

function runOne(run, repeatIndex, o, foxguard) {
  const root = mkdtempSync(join(tmpdir(), "0-bench-"));
  const home = join(root, "home");
  const folder = join(root, "app");
  mkdirSync(home, { recursive: true });
  // The model must not be able to read the answer key: copy the fixture without it.
  cpSync(run.fixture.dir, folder, { recursive: true, filter: (src) => !src.endsWith("answer.json") });
  if (run.config === "checkov") return runCheckov(run, repeatIndex, o, folder, root);
  const outFile = join(root, "report.json");
  const env = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, "config"), XDG_DATA_HOME: join(home, "data"), XDG_CACHE_HOME: join(home, "cache") };
  if (foxguard) env.ZERO_FOXGUARD_PATH = foxguard;
  const started = Date.now();
  const proc = spawnSync(process.execPath, [o.cli, ...scanArgs(run, folder, outFile, o)], { env, encoding: "utf8", timeout: (o.timeout + 120) * 1000, cwd: repoRoot });
  const seconds = (Date.now() - started) / 1000;
  let report;
  try { report = JSON.parse(readFileSync(outFile, "utf8")); } catch { /* no report: the scan failed before writing one */ }
  const findings = report?.findings ?? [];
  const score = scoreFindings(run.fixture.answer, findings);
  return {
    fixture: run.fixture.name, config: run.config, repeat: repeatIndex + 1, seconds,
    costUsd: report?.costUsd ?? null, status: report?.status ?? `no-report (exit ${proc.status})`,
    error: report ? report.error : (proc.stderr ?? "").slice(-300),
    // Batched scans only: the plain statement of what was reviewed, and how many threads it took.
    coverage: report?.coverage?.statement ?? null, threads: report?.threadIds?.length ?? (report ? 1 : null),
    score, workdir: root,
  };
}

const pct = (x) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(0)}%`);
const usd = (x) => (x === null || x === undefined ? "n/a" : `$${x.toFixed(4)}`);
const range = (r, f) => (r ? (r[0] === r[1] ? f(r[0]) : `${f(r[0])}-${f(r[1])}`) : "n/a");

/** Group raw runs into one row per fixture and config with mean and spread over the repeats. */
export function summarize(runs) {
  const groups = new Map();
  for (const r of runs) {
    const key = `${r.fixture}|${r.config}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  return [...groups.values()].map((rs) => {
    const recalls = rs.map((r) => r.score.recall).filter((x) => x !== null);
    const costs = rs.map((r) => r.costUsd).filter((x) => x !== null);
    return {
      fixture: rs[0].fixture, config: rs[0].config, repeats: rs.length,
      planted: rs[0].score.planted,
      recallMean: mean(recalls), recallSpread: spread(recalls),
      foundMean: mean(rs.map((r) => r.score.found)),
      falsePositivesMean: mean(rs.map((r) => r.score.falsePositives)), falsePositivesSpread: spread(rs.map((r) => r.score.falsePositives)),
      unmatchedMean: mean(rs.map((r) => r.score.unmatched.length)),
      findingsMean: mean(rs.map((r) => r.score.findings)),
      costMean: mean(costs), costSpread: spread(costs), costTotal: costs.reduce((a, b) => a + b, 0),
      secondsMean: mean(rs.map((r) => r.seconds)), secondsSpread: spread(rs.map((r) => r.seconds)),
      failed: rs.filter((r) => r.status !== "complete").map((r) => r.status),
      coverage: rs.map((r) => r.coverage).filter(Boolean)[0] ?? null,
      threadsMean: mean(rs.map((r) => r.threads).filter((x) => x !== null && x !== undefined)),
    };
  });
}

export function renderMarkdown(rows, meta) {
  const lines = [
    `# Planted-bug benchmark${meta.synthetic ? " (dry run, synthetic findings)" : ""}`,
    "",
    `- Date: ${meta.date}`,
    `- Model: ${meta.model}`,
    `- Repeats: ${meta.repeat}`,
    `- Per-run budget: $${meta.budget}`,
    `- Total cost: ${usd(rows.reduce((a, r) => a + r.costTotal, 0))}`,
    "",
    "Recall is planted bugs found / planted bugs. False positives are findings on a decoy, or any finding in the clean app. Unmatched are findings that are neither (real extra issues or noise; read them). Cells show mean, with the min-max range over repeats in brackets.",
    "",
    "| fixture | config | recall | found/planted | false pos. | unmatched | cost | time (s) | threads | coverage reported | not complete |",
    "|---|---|---|---|---|---|---|---|---|---|---|",
  ];
  for (const r of rows) {
    lines.push(`| ${r.fixture} | ${r.config} | ${pct(r.recallMean)} (${range(r.recallSpread, pct)}) | ${r.foundMean.toFixed(1)}/${r.planted} | ${r.falsePositivesMean.toFixed(1)} (${range(r.falsePositivesSpread, (x) => String(x))}) | ${r.unmatchedMean.toFixed(1)} | ${usd(r.costMean)} (${range(r.costSpread, usd)}) | ${r.secondsMean.toFixed(0)} (${range(r.secondsSpread, (x) => x.toFixed(0))}) | ${r.threadsMean === null || r.threadsMean === undefined ? "-" : r.threadsMean.toFixed(1)} | ${r.coverage ?? "-"} | ${r.failed.length ? r.failed.join("; ") : "-"} |`);
  }
  const byConfig = new Map();
  for (const r of rows) if (r.recallMean !== null) { const l = byConfig.get(r.config) ?? []; l.push(r); byConfig.set(r.config, l); }
  lines.push("", "Recall by configuration over the fixtures it ran on (mean of fixture means, so it is not weighted by planted count):", "");
  for (const [config, rs] of byConfig) lines.push(`- ${config}: ${pct(mean(rs.map((r) => r.recallMean)))} over ${rs.length} fixtures`);
  lines.push("", "What this does not show: see docs/design/benchmark.md. Few tiny fixtures and few repeats; differences smaller than the spread are noise.", "");
  return lines.join("\n");
}

function dryRun(o) {
  const fixtures = loadFixtures(o.fixtures, o.fixturesDir);
  let bad = 0;
  const runs = [];
  for (const fx of fixtures) {
    const problems = validateAnswer(fx.answer, { fileLines: fileLines(fx.dir) });
    if (fx.answer.fixture !== fx.name) problems.push(`answer.fixture ${fx.answer.fixture} does not match the folder`);
    const lines = Object.values(fileLines(fx.dir)).reduce((a, b) => a + b, 0);
    console.log(`${problems.length ? "FAIL" : "ok  "} ${fx.name}: ${fx.answer.items.length} planted, ${fx.answer.decoys.length} decoys, ${lines} source lines${fx.answer.skill ? `, skill ${fx.answer.skill}` : ""}`);
    for (const p of problems) console.log(`     ${p}`);
    bad += problems.length;
    // Synthetic findings: one correct finding per planted item (offset by 3 lines), one on the first decoy.
    const mk = (entry, category, offset, i) => ({ id: `s${i}`, title: `synthetic ${category}`, category, location: { path: entry.path, startLine: entry.startLine + offset } });
    const findings = fx.answer.items.map((it, i) => mk(it, categoryLabel(it.category), 3, i));
    const decoy = fx.answer.decoys[0];
    if (decoy) findings.push({ id: "decoy", title: "synthetic noise", category: "other", location: { path: decoy.path, startLine: decoy.startLine } });
    const score = scoreFindings(fx.answer, findings);
    const expectFp = decoy ? 1 : 0;
    if (score.found !== fx.answer.items.length || score.falsePositives !== expectFp) {
      console.log(`FAIL ${fx.name}: synthetic findings scored found=${score.found}/${fx.answer.items.length}, false positives=${score.falsePositives} (expected ${expectFp})`);
      bad++;
    }
    runs.push({ fixture: fx.name, config: "synthetic", repeat: 1, seconds: 0, costUsd: 0, status: "complete", score });
  }
  const plan = planRuns(fixtures, o.configs);
  console.log(`\n${plan.length} fixture/config pairs x ${o.repeat} repeat(s) = ${plan.length * o.repeat} scans; estimated worst-case cost $${(plan.length * o.repeat * o.budget).toFixed(2)} at --budget ${o.budget}`);
  console.log(`first scan command: node ${relative(scanArgs(plan[0], "<copy-of-fixture>", "<out.json>", o))}`);
  if (bad) { console.error(`\n${bad} problem(s)`); process.exit(1); }
  console.log("\ndry run passed: fixtures and matcher are consistent. No model was called.");
  return runs;
}
const relative = (args) => ["packages/cli/dist/index.js", ...args].join(" ");
// Answer categories are family keys; a real scan labels them with the engine's category names.
const categoryLabel = (family) => ({ sqli: "sql-injection", secret: "information-disclosure", "weak-crypto": "weak-crypto", deserialization: "unsafe-deserialization", "output-handling": "output-manipulation", "iac-network": "network exposure: security group", "iac-iam": "iam privilege escalation", "iac-privilege": "privileged container", "iac-supply": "unpinned install script", "ci-injection": "workflow script injection" })[family] ?? family;

function realRun(o) {
  const fixtures = loadFixtures(o.fixtures, o.fixturesDir);
  const problems = fixtures.flatMap((fx) => validateAnswer(fx.answer, { fileLines: fileLines(fx.dir) }));
  if (problems.length) throw new Error(`fixtures are invalid, run --dry-run:\n${problems.join("\n")}`);
  if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build it with pnpm --filter @0/engine build && pnpm --filter @0/cli build`);
  const plan = planRuns(fixtures, o.configs);
  const foxguard = o.configs.includes("foxguard") ? findFoxguard() : undefined;
  if (o.configs.includes("foxguard") && !foxguard) throw new Error("the foxguard config needs foxguard installed (ZERO_FOXGUARD_PATH, ~/.0/bin/foxguard or PATH)");
  console.log(`${plan.length} fixture/config pairs x ${o.repeat} repeat(s) = ${plan.length * o.repeat} scans`);
  console.log(`estimated worst-case cost: $${(plan.length * o.repeat * o.budget).toFixed(2)} (each scan stops at --budget ${o.budget}; real cost is usually far lower)`);
  const runs = [];
  for (let rep = 0; rep < o.repeat; rep++) for (const run of plan) {
    process.stdout.write(`scan ${run.fixture.name} / ${run.config} / repeat ${rep + 1} ... `);
    const r = runOne(run, rep, o, foxguard);
    runs.push(r);
    console.log(`${r.status}, ${r.score.found}/${r.score.planted} found, ${r.score.falsePositives} false pos., ${usd(r.costUsd)}, ${r.seconds.toFixed(0)}s${r.coverage ? `, ${r.coverage}` : ""}`);
  }
  return runs;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/run.mjs (--run | --dry-run) [--repeat N] [--budget USD] [--configs generic,skill,foxguard,checkov,checkov-prepass] [--fixtures a,b] [--fixtures-dir dir] [--model id] [--out dir]`); process.exit(2); }
  try {
    const runs = o.dryRun ? dryRun(o) : realRun(o);
    const rows = summarize(runs);
    const meta = { date: new Date().toISOString().slice(0, 10), model: o.model ?? "default (gpt-6-luna)", repeat: o.repeat, budget: o.budget, synthetic: o.dryRun };
    if (o.run) {
      mkdirSync(o.out, { recursive: true });
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      writeFileSync(join(o.out, `${stamp}.json`), `${JSON.stringify({ meta, rows, runs: runs.map(({ workdir, ...r }) => r) }, null, 2)}\n`);
      writeFileSync(join(o.out, `${stamp}.md`), renderMarkdown(rows, meta));
      console.log(`\n${renderMarkdown(rows, meta)}\nwrote ${join(o.out, stamp)}.{md,json}`);
    }
  } catch (e) { console.error(e.message); process.exit(1); }
}
