#!/usr/bin/env node
// Scan-level OWASP Benchmark scorecard: what does `0security scan` itself report, with no triage step?
//   node scripts/bench/owasp-score.mjs --scan-file <scan.json> --owasp <BenchmarkJava checkout> [--per-class 3] [--seed 1] [--categories a,b | --all]
//   node scripts/bench/owasp-score.mjs --run --owasp <checkout> [...same sample options] [--budget 1] [--max-cost 3]
//   node scripts/bench/owasp-score.mjs --dry-run --owasp <checkout> [...]                  sample and render with no findings: no model
//
// A case counts as detected when a finding sits in that case's file and its text names the case's category (the same rule
// triage-truth.mjs uses). Per category: true-positive rate over the real cases, false-positive rate over the not-real
// cases, and their difference (the Benchmark's own score; 0 is no better than flagging at random). Findings that are in
// a case file but name another category are counted apart and do not enter the rates.
// --scan-file scores a saved report (`0security scan --format json -o`) of a folder holding the same sample's files.
// The checkout is not committed: it is GPL and large.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { CATEGORY_WORDS, parseExpectedResults, sampleCases } from "./triage-truth.mjs";
import { defaultCli, isMain, isolatedEnv, pct, repoRoot, run, usd } from "./lib.mjs";

/**
 * Score findings against OWASP cases. cases: rows of { name, category, real }. findings: scan report findings.
 * Returns { rows: per category, total } where each row has real, notReal, detectedReal, detectedNotReal, tpr, fpr, score,
 * and total.otherCategory counts findings in a case file that name another category.
 */
export function scoreOwasp(cases, findings) {
  const byName = new Map(cases.map((c) => [c.name, c]));
  const detected = new Set();
  let otherCategory = 0, outside = 0;
  for (const f of findings) {
    const file = f.location?.path ?? f.reviewAnnotation?.path;
    const row = file ? byName.get(basename(file).replace(/\.java$/, "")) : undefined;
    if (!row) { outside++; continue; }
    const text = `${f.title ?? ""} ${f.category ?? ""} ${f.description ?? ""}`;
    if (CATEGORY_WORDS[row.category]?.test(text)) detected.add(row.name); else otherCategory++;
  }
  const ratio = (n, d) => (d ? n / d : null);
  const rows = [...new Set(cases.map((c) => c.category))].sort().map((category) => {
    const mine = cases.filter((c) => c.category === category);
    const real = mine.filter((c) => c.real), notReal = mine.filter((c) => !c.real);
    const detectedReal = real.filter((c) => detected.has(c.name)).length;
    const detectedNotReal = notReal.filter((c) => detected.has(c.name)).length;
    const tpr = ratio(detectedReal, real.length), fpr = ratio(detectedNotReal, notReal.length);
    return { category, real: real.length, notReal: notReal.length, detectedReal, detectedNotReal, tpr, fpr, score: tpr === null || fpr === null ? null : tpr - fpr };
  });
  const sum = (k) => rows.reduce((a, r) => a + r[k], 0);
  const scored = rows.filter((r) => r.score !== null);
  const total = {
    real: sum("real"), notReal: sum("notReal"), detectedReal: sum("detectedReal"), detectedNotReal: sum("detectedNotReal"),
    tpr: ratio(sum("detectedReal"), sum("real")), fpr: ratio(sum("detectedNotReal"), sum("notReal")),
    meanCategoryScore: scored.length ? scored.reduce((a, r) => a + r.score, 0) / scored.length : null,
    otherCategory, outside,
  };
  total.score = total.tpr === null || total.fpr === null ? null : total.tpr - total.fpr;
  return { rows, total };
}

export function renderOwasp({ rows, total }, meta) {
  const lines = [
    `# OWASP Benchmark scan scorecard${meta.synthetic ? " (no scan: nothing was reported)" : ""}`,
    "",
    `- Date: ${meta.date}`,
    `- Model: ${meta.model}`,
    `- Sample: ${meta.sample}`,
    `- Spend: ${usd(meta.costUsd ?? null)}`,
    "",
    `True-positive rate ${pct(total.tpr)} (${total.detectedReal} of ${total.real} real cases detected), false-positive rate ${pct(total.fpr)} (${total.detectedNotReal} of ${total.notReal} not-real cases flagged), score ${total.score === null ? "n/a" : (total.score * 100).toFixed(0)} points (true-positive rate minus false-positive rate; 0 is no better than chance, 100 is perfect). Mean over categories ${total.meanCategoryScore === null ? "n/a" : (total.meanCategoryScore * 100).toFixed(0)} points.`,
    "",
    `A case is detected when a finding is in its file and names its category. ${total.otherCategory} finding(s) in case files named another category and ${total.outside} were in other files; neither enters the rates.`,
    "",
    "| category | real | not real | real detected | not real flagged | TPR | FPR | score |",
    "|---|---|---|---|---|---|---|---|",
    ...rows.map((r) => `| ${r.category} | ${r.real} | ${r.notReal} | ${r.detectedReal} | ${r.detectedNotReal} | ${pct(r.tpr)} | ${pct(r.fpr)} | ${r.score === null ? "n/a" : (r.score * 100).toFixed(0)} |`),
    "",
    "What this does not show: a small seeded sample per category, one run, and a category match made from the finding's words. Read docs/design/benchmark.md.",
    "",
  ];
  return lines.join("\n");
}

export function parseArgs(argv) {
  const o = { run: false, dryRun: false, scanFile: undefined, owasp: undefined, perClass: 3, seed: 1, categories: undefined, all: false, budget: 1, maxCost: 3, model: undefined, timeout: 900, out: join(repoRoot, "scripts/bench/results"), cli: defaultCli };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--scan-file") o.scanFile = resolve(next());
    else if (a === "--owasp") o.owasp = resolve(next());
    else if (a === "--per-class") o.perClass = Number(next());
    else if (a === "--seed") o.seed = Number(next());
    else if (a === "--categories") o.categories = next().split(",");
    else if (a === "--all") o.all = true;
    else if (a === "--budget") o.budget = Number(next());
    else if (a === "--max-cost") o.maxCost = Number(next());
    else if (a === "--model") o.model = next();
    else if (a === "--timeout") o.timeout = Number(next());
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--cli") o.cli = resolve(next());
    else throw new Error(`unknown option ${a}`);
  }
  if ([o.run, o.dryRun, Boolean(o.scanFile)].filter(Boolean).length !== 1) throw new Error("pass exactly one of --run (spends model money), --dry-run (free) or --scan-file <report> (free)");
  if (!o.owasp) throw new Error("--owasp <BenchmarkJava checkout> is required");
  if (!Number.isInteger(o.perClass) || o.perClass < 1) throw new Error("--per-class must be a positive integer");
  if (!(o.budget > 0)) throw new Error("--budget must be a positive number of USD");
  for (const c of o.categories ?? []) if (!CATEGORY_WORDS[c]) throw new Error(`unknown category ${c} (${Object.keys(CATEGORY_WORDS).join(", ")})`);
  return o;
}

/** The cases to score: every row with --all, else the seeded balanced sample triage-truth.mjs also uses. */
export function loadCases(o) {
  const csv = join(o.owasp, "expectedresults-1.2.csv");
  if (!existsSync(csv)) throw new Error(`${csv} not found: pass a BenchmarkJava checkout`);
  const rows = parseExpectedResults(readFileSync(csv, "utf8"));
  const wanted = o.categories ? rows.filter((r) => o.categories.includes(r.category)) : rows;
  return o.all ? wanted : sampleCases(rows, { perClass: o.perClass, seed: o.seed, categories: o.categories });
}

const describeSample = (o, cases) => (o.all ? `every case${o.categories ? ` in ${o.categories.join(", ")}` : ""}: ${cases.length} cases` : `seeded sample, ${cases.length} cases (${cases.filter((c) => c.real).length} real), seed ${o.seed}, per-class ${o.perClass}`);

/** Copy only the sampled test files to a scratch folder, so the scan sees exactly the cases that are scored. */
function stage(o, cases) {
  const root = mkdtempSync(join(tmpdir(), "0-owasp-score-"));
  const folder = join(root, "app");
  const dir = join(o.owasp, "src/main/java/org/owasp/benchmark/testcode");
  mkdirSync(folder, { recursive: true });
  for (const c of cases) cpSync(join(dir, `${c.name}.java`), join(folder, `${c.name}.java`));
  return { root, folder };
}

if (isMain(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/owasp-score.mjs (--run | --dry-run | --scan-file <report>) --owasp <checkout> [--per-class N] [--seed N] [--categories a,b] [--all] [--budget USD] [--max-cost USD] [--model id] [--out dir]`); process.exit(2); }
  try {
    const cases = loadCases(o);
    let findings = [], costUsd = null;
    if (o.scanFile) {
      const report = JSON.parse(readFileSync(o.scanFile, "utf8"));
      findings = report.findings ?? [];
      costUsd = report.usage?.costUsd ?? report.costUsd ?? null;
    } else if (o.dryRun) {
      const { folder } = stage(o, cases);
      console.log(`ok   ${describeSample(o, cases)}\nscratch folder with the sampled files: ${folder}`);
    } else {
      if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build the engine and then the CLI first`);
      const { root, folder } = stage(o, cases);
      console.log(`${describeSample(o, cases)}; scan budget $${o.budget}`);
      const out = join(root, "scan.json");
      const p = run(process.execPath, [o.cli, "scan", folder, "--budget", String(o.budget), "--format", "json", "-o", out, "--timeout", String(o.timeout), ...(o.model ? ["--model", o.model] : [])], { cwd: repoRoot, env: isolatedEnv(join(root, "home")), timeoutSeconds: o.timeout + 120 });
      let report; try { report = JSON.parse(readFileSync(out, "utf8")); } catch { throw new Error(`the scan wrote no report (exit ${p.status}): ${(p.stderr || p.stdout).slice(-300)}`); }
      findings = report.findings ?? [];
      costUsd = report.usage?.costUsd ?? report.costUsd ?? null;
      if (costUsd > o.maxCost) console.log(`warning: spend passed --max-cost ${o.maxCost}`);
    }
    const result = scoreOwasp(cases, findings);
    const meta = { date: new Date().toISOString().slice(0, 10), model: o.model ?? (o.scanFile ? "as scanned" : "default (gpt-6-luna)"), sample: describeSample(o, cases), costUsd, synthetic: o.dryRun };
    const md = renderOwasp(result, meta);
    if (o.dryRun) console.log("dry run passed: no model was called.");
    else {
      mkdirSync(o.out, { recursive: true });
      const stamp = `owasp-score-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      writeFileSync(join(o.out, `${stamp}.json`), `${JSON.stringify({ meta, ...result }, null, 2)}\n`);
      writeFileSync(join(o.out, `${stamp}.md`), md);
      console.log(`${md}\nwrote ${join(o.out, stamp)}.{md,json}`);
    }
  } catch (e) { console.error(e.message); process.exit(1); }
}
