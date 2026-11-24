#!/usr/bin/env node
// Agent-triage measurement harness: how well does `0 findings verify` separate real bugs from noise?
//   node scripts/bench/triage-score.mjs --dry-run                                  check fixtures and the metrics, no model
//   node scripts/bench/triage-score.mjs --run [--fixtures a,b,c] [--repeat 1]      scan, verify, score; spends model money
//   node scripts/bench/triage-score.mjs --run --scans dir                          reuse saved scan reports (<fixture>.json), verify only
//
// The scan and verify steps, the answer-key classification and the verdict tally are the ones verify-score.mjs uses;
// this script adds the precision, recall and noise-removal numbers and the written report.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { classify, runOnce, triageMetrics } from "./verify-score.mjs";
import { benchDir, defaultCli, isMain, pct, usd } from "./lib.mjs";

const DEFAULT_FIXTURES = ["clean-app", "python-flask", "node-express"];

export function parseArgs(argv) {
  const o = { run: false, dryRun: false, repeat: 1, scanBudget: 0.5, verifyBudget: 1, fixtures: DEFAULT_FIXTURES, model: undefined, scans: undefined, out: join(benchDir, "results"), cli: defaultCli, timeout: 900 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--scan-budget") o.scanBudget = Number(next());
    else if (a === "--verify-budget") o.verifyBudget = Number(next());
    else if (a === "--fixtures") o.fixtures = next().split(",");
    else if (a === "--model") o.model = next();
    else if (a === "--scans") o.scans = resolve(next());
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--cli") o.cli = resolve(next());
    else if (a === "--timeout") o.timeout = Number(next());
    else throw new Error(`unknown option ${a}`);
  }
  if (o.run === o.dryRun) throw new Error("pass exactly one of --run (spends model money) or --dry-run (free)");
  if (!Number.isInteger(o.repeat) || o.repeat < 1) throw new Error("--repeat must be a positive integer");
  if (!(o.scanBudget > 0) || !(o.verifyBudget > 0)) throw new Error("--scan-budget and --verify-budget must be positive numbers of USD");
  return o;
}

const share = (x) => (x === null || x === undefined ? "n/a" : pct(x));

export function renderTriage(runs, meta) {
  const rows = runs.flatMap((r) => r.rows);
  const m = triageMetrics(rows);
  const t = m.tally;
  const v = (b, k) => b.byVerdict[k] ?? 0;
  const spend = runs.reduce((a, r) => a + (r.scanCostUsd ?? 0) + (r.verifyCostUsd ?? 0), 0);
  const verifySpend = runs.reduce((a, r) => a + (r.verifyCostUsd ?? 0), 0);
  const lines = [
    `# Agent-triage measurement${meta.synthetic ? " (dry run, synthetic verdicts)" : ""}`,
    "",
    `- Date: ${meta.date}`,
    `- Model: ${meta.model}`,
    `- ${meta.truth ? `Ground truth: ${meta.truth}` : `Fixtures: ${meta.fixtures.join(", ")}`}`,
    `- Repeats: ${meta.repeat}`,
    `- Findings checked: ${rows.length} (${m.real} real, ${m.noise} noise, ${m.unknown} neither)`,
    `- Spend: ${usd(spend)} (verify ${usd(verifySpend)})`,
    "",
    `Real bugs that verify called false-positive: ${m.realCalledFalsePositive} of ${m.real}. Real bugs that --apply suppressed: ${m.realSuppressedByApply} (high or critical: ${m.realSuppressedHighOrCritical}).`,
    "",
    `Noise removed: ${share(m.noiseRemoved)} of the noise findings were called false-positive. Recall loss: ${share(m.recallLoss)} of the real bugs were called false-positive. Precision of the list before triage ${share(m.precisionBefore)}, after dropping false-positive verdicts ${share(m.precisionAfter)}.`,
    "",
    `${meta.truth ? "Real means the ground truth says the case is a vulnerability and the finding names its category. Noise means the ground truth says it is not, or a label says noise." : "Real means the finding matches a planted bug. Noise means it sits on a decoy or anywhere in a clean fixture."} Findings that are neither are left out of the rates. Precision is the share of findings with that verdict whose ground truth agrees; recall is the share of that ground truth that got the verdict.`,
    "",
    "| verdict | on real bugs | on noise | on neither | precision | recall |",
    "|---|---|---|---|---|---|",
    `| true-positive | ${v(t.tp, "true-positive")} | ${v(t.fp, "true-positive")} | ${v(t.other, "true-positive")} | ${share(m.truePositive.precision)} | ${share(m.truePositive.recall)} |`,
    `| false-positive | ${v(t.tp, "false-positive")} | ${v(t.fp, "false-positive")} | ${v(t.other, "false-positive")} | ${share(m.falsePositive.precision)} | ${share(m.falsePositive.recall)} |`,
    ...["uncertain", "fixed", "duplicate"].map((k) => `| ${k} | ${v(t.tp, k)} | ${v(t.fp, k)} | ${v(t.other, k)} | - | - |`),
    "",
    "| fixture | repeat | findings | real called false-positive | noise called false-positive | verify failed |",
    "|---|---|---|---|---|---|",
    ...runs.map((r) => {
      const x = triageMetrics(r.rows);
      return `| ${r.fixture} | ${r.repeat} | ${r.findings} | ${x.realCalledFalsePositive}/${x.real} | ${v(x.tally.fp, "false-positive")}/${x.noise} | ${r.verifyError ? "yes" : "no"} |`;
    }),
    "",
    "What this does not show: a handful of small fixtures with few planted bugs, so one finding moves a rate by several points. See docs/design/benchmark.md.",
    "",
  ];
  return lines.join("\n");
}

/** Dry run: the answer keys load and the metrics and the report render on made-up verdicts. */
function dryRun(o) {
  const rows = [];
  for (const name of o.fixtures) {
    const path = join(benchDir, "fixtures", name, "answer.json");
    if (!existsSync(path)) throw new Error(`unknown fixture ${name}`);
    const answer = JSON.parse(readFileSync(path, "utf8"));
    for (const it of answer.items) rows.push({ cls: classify(answer, { id: it.id, title: it.description, category: it.category, location: { path: it.path, startLine: it.startLine } }), verdict: "true-positive" });
    for (const d of answer.decoys) rows.push({ cls: "fp", verdict: "false-positive" });
  }
  const run = { fixture: o.fixtures.join("+"), repeat: 1, findings: rows.length, rows };
  const m = triageMetrics(rows);
  if (m.realCalledFalsePositive !== 0) throw new Error("synthetic verdicts should not call a real bug false-positive");
  console.log(`ok   ${o.fixtures.length} fixtures, ${m.real} real and ${m.noise} noise answer-key entries`);
  const text = renderTriage([run], { date: "dry-run", model: "none", fixtures: o.fixtures, repeat: 1, synthetic: true });
  if (!text.includes("| true-positive |")) throw new Error("the report did not render");
  console.log("dry run passed: no model was called.");
}

if (isMain(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/triage-score.mjs (--run | --dry-run) [--fixtures a,b,c] [--repeat N] [--scan-budget USD] [--verify-budget USD] [--model id] [--scans dir] [--out dir]`); process.exit(2); }
  try {
    if (o.dryRun) dryRun(o);
    else {
      if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build the engine and then the CLI first`);
      mkdirSync(o.out, { recursive: true });
      const runs = [];
      for (let rep = 1; rep <= o.repeat; rep++) for (const name of o.fixtures) {
        process.stdout.write(`${name} repeat ${rep} ... `);
        const r = runOnce({ ...o, out: join(o.out, "triage-scans") }, name, rep);
        console.log(`${r.findings} findings, ${r.rows.length} verified, scan ${usd(r.scanCostUsd ?? null)}, verify ${usd(r.verifyCostUsd ?? null)}${r.verifyError ? `, verify failed: ${r.verifyError}` : ""}`);
        runs.push(r);
      }
      const meta = { date: new Date().toISOString().slice(0, 10), model: o.model ?? "default (gpt-6-luna)", fixtures: o.fixtures, repeat: o.repeat };
      const md = renderTriage(runs, meta);
      const stamp = `triage-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      writeFileSync(join(o.out, `${stamp}.json`), `${JSON.stringify({ meta, metrics: { ...triageMetrics(runs.flatMap((r) => r.rows)), tally: undefined }, runs: runs.map(({ root, ...r }) => r) }, null, 2)}\n`);
      writeFileSync(join(o.out, `${stamp}.md`), md);
      console.log(`\n${md}\nwrote ${join(o.out, stamp)}.{md,json}`);
    }
  } catch (e) { console.error(e.message); process.exit(1); }
}
