#!/usr/bin/env node
// Score `0 findings verify` against the planted-bug fixtures.
//
//   node scripts/bench/verify-score.mjs --run [--fixtures clean-app,python-flask] [--repeat 2] [--scan-budget 0.5] [--verify-budget 1]
//   node scripts/bench/verify-score.mjs --score-file run.json       re-score saved runs (no model calls)
//
// Per run: scan a copy of the fixture with a fresh HOME, run `0 findings verify --apply` on what it found, then
// classify every finding with the benchmark matcher: a true positive matches a planted bug, a false positive is on a
// decoy or anywhere in a clean fixture, "other" is neither. The numbers that matter are printed first: real bugs
// that verification called false-positive, and real bugs that `--apply` would have suppressed.
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { scoreFindings } from "./match.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const DEFAULT_FIXTURES = ["clean-app", "clean-python", "python-flask", "go-http", "node-express", "llm-app"];

/** One finding's class against the answer key: "tp" (matches a planted bug), "fp" (decoy, or any finding in a clean fixture) or "other". */
export function classify(answer, finding) {
  const score = scoreFindings(answer, [finding]);
  if (answer.clean) return "fp";
  if (score.found > 0) return "tp";
  return score.falsePositives > 0 ? "fp" : "other";
}

/** Fold per-finding rows ({ cls, verdict, applied, severity }) into the counts the report needs. */
export function tally(rows) {
  const t = { tp: { total: 0, byVerdict: {} }, fp: { total: 0, byVerdict: {} }, other: { total: 0, byVerdict: {} }, wronglySuppressed: 0, wronglySuppressedHighOrCritical: 0, suppressedFalsePositives: 0 };
  for (const r of rows) {
    const bucket = t[r.cls];
    bucket.total++;
    bucket.byVerdict[r.verdict] = (bucket.byVerdict[r.verdict] ?? 0) + 1;
    if (r.applied) {
      if (r.cls === "tp") { t.wronglySuppressed++; if (["high", "critical"].includes(r.severity)) t.wronglySuppressedHighOrCritical++; }
      if (r.cls === "fp") t.suppressedFalsePositives++;
    }
  }
  return t;
}

function parseArgs(argv) {
  const o = { run: false, repeat: 1, scanBudget: 0.5, verifyBudget: 1, fixtures: DEFAULT_FIXTURES, cli: join(repoRoot, "packages/cli/dist/index.js"), out: join(tmpdir(), "verify-score"), model: undefined, timeout: 900, scoreFile: undefined };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]; const next = () => argv[++i];
    if (a === "--run") o.run = true;
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--scan-budget") o.scanBudget = Number(next());
    else if (a === "--verify-budget") o.verifyBudget = Number(next());
    else if (a === "--fixtures") o.fixtures = next().split(",");
    else if (a === "--cli") o.cli = resolve(next());
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--model") o.model = next();
    else if (a === "--score-file") o.scoreFile = resolve(next());
    else throw new Error(`unknown option ${a}`);
  }
  return o;
}

function runOnce(o, name, repeat) {
  const answer = JSON.parse(readFileSync(join(repoRoot, "scripts/bench/fixtures", name, "answer.json"), "utf8"));
  const root = mkdtempSync(join(tmpdir(), `verify-${name}-`));
  const folder = join(root, "app");
  const home = join(root, "home");
  mkdirSync(home, { recursive: true });
  cpSync(join(repoRoot, "scripts/bench/fixtures", name), folder, { recursive: true, filter: src => !src.endsWith("answer.json") });
  const env = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, "config"), XDG_DATA_HOME: join(home, "data"), XDG_CACHE_HOME: join(home, "cache") };
  const model = o.model ? ["--model", o.model] : [];
  const scanFile = join(root, "scan.json");
  const scan = spawnSync(process.execPath, [o.cli, "scan", folder, "--budget", String(o.scanBudget), "--format", "json", "-o", scanFile, "--timeout", String(o.timeout), ...model], { env, encoding: "utf8", timeout: (o.timeout + 120) * 1000, cwd: repoRoot });
  let report; try { report = JSON.parse(readFileSync(scanFile, "utf8")); } catch { /* no report */ }
  const findings = report?.findings ?? [];
  const row = { fixture: name, repeat, root, scanStatus: scan.status, findings: findings.length, rows: [], scanCostUsd: report?.usage?.costUsd ?? report?.costUsd };
  if (!findings.length) return row;
  const verify = spawnSync(process.execPath, [o.cli, "findings", "verify", "--folder", folder, "--apply", "--budget", String(o.verifyBudget), "--format", "json", "--timeout", "600", ...model], { env, encoding: "utf8", timeout: 1800 * 1000, cwd: repoRoot });
  let verified; try { verified = JSON.parse(verify.stdout); } catch { row.verifyError = (verify.stderr || verify.stdout).slice(-400); return row; }
  row.verifyCostUsd = verified.costUsd;
  row.stoppedReason = verified.stoppedReason;
  const byId = new Map(findings.map(f => [f.id, f]));
  for (const item of verified.items) {
    const finding = byId.get(item.finding);
    if (!finding) { row.rows.push({ id: item.finding, cls: "other", verdict: item.verdict ?? item.result, unmatchedId: true }); continue; }
    row.rows.push({ id: item.finding, title: finding.title, severity: item.severity, cls: classify(answer, finding), verdict: item.verdict ?? item.result, advisorySeverity: item.advisorySeverity, applied: Boolean(item.applied), applyRefused: item.applyRefused, reasoning: item.reasoning });
  }
  return row;
}

const pct = (n, d) => (d ? `${n}/${d}` : "0/0");
export function render(runs) {
  const all = runs.flatMap(r => r.rows);
  const t = tally(all);
  const v = (b, key) => b.byVerdict[key] ?? 0;
  const lines = [
    `Real bugs (planted, matched) called false-positive: ${pct(v(t.tp, "false-positive"), t.tp.total)}`,
    `Real bugs that --apply suppressed: ${t.wronglySuppressed} (high or critical: ${t.wronglySuppressedHighOrCritical})`,
    "",
    "| Group | Findings | true-positive | false-positive | uncertain | fixed | duplicate | other |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...[["Planted bugs", t.tp], ["False positives (decoy or clean app)", t.fp], ["Other (neither)", t.other]].map(([label, b]) => `| ${label} | ${b.total} | ${v(b, "true-positive")} | ${v(b, "false-positive")} | ${v(b, "uncertain")} | ${v(b, "fixed")} | ${v(b, "duplicate")} | ${Object.entries(b.byVerdict).filter(([k]) => !["true-positive", "false-positive", "uncertain", "fixed", "duplicate"].includes(k)).map(([k, n]) => `${k} ${n}`).join(", ")} |`),
    "",
    `False positives called false-positive: ${pct(v(t.fp, "false-positive"), t.fp.total)}; of them suppressed by --apply: ${t.suppressedFalsePositives}`,
    "",
    "| Fixture | Run | Findings | tp: true / false / uncertain | fp: false / uncertain / true | scan $ | verify $ |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...runs.map(r => {
      const t1 = tally(r.rows); const c = (b, k) => b.byVerdict[k] ?? 0;
      return `| ${r.fixture} | ${r.repeat} | ${r.findings}${r.verifyError ? " (verify failed)" : ""} | ${c(t1.tp, "true-positive")} / ${c(t1.tp, "false-positive")} / ${c(t1.tp, "uncertain")} | ${c(t1.fp, "false-positive")} / ${c(t1.fp, "uncertain")} / ${c(t1.fp, "true-positive")} | ${r.scanCostUsd ?? "?"} | ${r.verifyCostUsd ?? "?"} |`;
    }),
  ];
  return lines.join("\n");
}

const direct = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
const o = direct ? parseArgs(process.argv) : { scoreFile: undefined, run: false };
if (!direct) {
  // Imported for its helpers (classify, tally, render): nothing to run.
} else if (o.scoreFile) {
  console.log(render(JSON.parse(readFileSync(o.scoreFile, "utf8")).runs));
} else if (o.run) {
  if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build the engine and then the CLI first`);
  mkdirSync(o.out, { recursive: true });
  const runs = [];
  for (let rep = 1; rep <= o.repeat; rep++) for (const name of o.fixtures) {
    process.stdout.write(`${name} run ${rep} ... `);
    const run = runOnce(o, name, rep);
    console.log(`${run.findings} findings, ${run.rows.length} verified${run.verifyError ? `, verify failed: ${run.verifyError}` : ""}`);
    runs.push(run);
    writeFileSync(join(o.out, "runs.json"), `${JSON.stringify({ runs }, null, 2)}\n`);
  }
  console.log(`\n${render(runs)}`);
} else {
  console.log("Pass --run to spend model money, or --score-file <runs.json> to re-score saved runs.");
}
