#!/usr/bin/env node
// Agent-triage measurement against outside ground truth: the OWASP Benchmark or a hand-labelled set.
//   node scripts/bench/triage-truth.mjs --dry-run --owasp <BenchmarkJava checkout>        sample, classify, render: no model
//   node scripts/bench/triage-truth.mjs --run --owasp <BenchmarkJava checkout> [--per-class 3] [--seed 1] [--categories sqli,xss,...]
//   node scripts/bench/triage-truth.mjs --run --labels <labels.json> --app <folder>      score against hand labels
//
// The pipeline is the one `0 findings verify` is built for: deterministic leads (a scan of the folder), then agent
// triage (`findings verify`), then a comparison with the ground truth. The report gives the share of noise the triage
// removed, the share of real bugs it wrongly called false-positive (the recall loss), and the model spend.
//
// OWASP Benchmark: a checkout is not committed here (it is GPL, and large). The script reads its expectedresults CSV,
// takes a seeded, balanced sample (the same number of real and not-real cases per category), copies only those test
// files to a scratch folder and scans that. A finding counts against a case when it is in that case's file and its
// text names the case's category; any other finding is "other" and left out of the rates.
//
// Labels file: { "findings": [{ "path": "src/Foo.java", "line": 42, "label": "real" | "noise", "note": "why" }] }.
// A finding matches a label in the same file within 5 lines. Findings with no label are "other".
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { triageMetrics } from "./verify-score.mjs";
import { renderTriage } from "./triage-score.mjs";
import { defaultCli, isMain, isolatedEnv, repoRoot, run } from "./lib.mjs";

/** Words that must appear in a finding's text for it to count as being about an OWASP Benchmark category. */
export const CATEGORY_WORDS = {
  cmdi: /command|os command|exec|shell|cwe-78/i,
  crypto: /crypto|cipher|encrypt|des\b|ecb|cwe-327/i,
  hash: /hash|md5|sha-?1|digest|cwe-328/i,
  ldapi: /ldap|cwe-90/i,
  pathtraver: /path|travers|directory|file access|cwe-22/i,
  securecookie: /cookie|secure flag|cwe-614/i,
  sqli: /sql|cwe-89/i,
  trustbound: /trust|session|cwe-501/i,
  weakrand: /random|prng|cwe-330/i,
  xpathi: /xpath|cwe-643/i,
  xss: /xss|cross.?site|script|cwe-79/i,
};

/** Rows of expectedresults-*.csv: "BenchmarkTest00001,pathtraver,true,22". Comment and header lines are skipped. */
export function parseExpectedResults(csv) {
  return csv.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => l.split(",")).filter((p) => p.length >= 3 && /^BenchmarkTest\d+$/.test(p[0])).map((p) => ({ name: p[0], category: p[1], real: p[2] === "true", cwe: p[3] }));
}

function rng(seed) {
  let s = (seed >>> 0) || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}

/** A seeded sample: up to perClass real and perClass not-real cases in every wanted category. */
export function sampleCases(rows, { perClass = 3, seed = 1, categories } = {}) {
  const random = rng(seed);
  const shuffled = (list) => list.map((x) => [random(), x]).sort((a, b) => a[0] - b[0]).map((p) => p[1]);
  const out = [];
  for (const category of categories ?? [...new Set(rows.map((r) => r.category))].sort()) {
    for (const real of [true, false]) out.push(...shuffled(rows.filter((r) => r.category === category && r.real === real)).slice(0, perClass));
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** A classifier for findings: "tp" (real case, right category), "fp" (not-real case, right category) or "other". */
export function owaspClassifier(sample) {
  const byName = new Map(sample.map((r) => [r.name, r]));
  return (finding) => {
    const file = finding.location?.path ?? finding.reviewAnnotation?.path;
    const row = file ? byName.get(basename(file).replace(/\.java$/, "")) : undefined;
    if (!row) return "other";
    const text = `${finding.title ?? ""} ${finding.category ?? ""} ${finding.description ?? ""}`;
    if (!CATEGORY_WORDS[row.category]?.test(text)) return "other";
    return row.real ? "tp" : "fp";
  };
}

/** A classifier for a hand-labelled set. */
export function labelClassifier(labels, window = 5) {
  return (finding) => {
    const file = finding.location?.path ?? finding.reviewAnnotation?.path;
    const line = finding.location?.startLine ?? finding.reviewAnnotation?.startLine;
    if (!file) return "other";
    const hit = labels.find((l) => (file === l.path || file.endsWith(`/${l.path}`)) && (line === undefined || l.line === undefined || Math.abs(l.line - line) <= window));
    return hit ? (hit.label === "real" ? "tp" : "fp") : "other";
  };
}

export function parseArgs(argv) {
  const o = { run: false, dryRun: false, owasp: undefined, labels: undefined, app: undefined, perClass: 3, seed: 1, categories: undefined, scanBudget: 1, verifyBudget: 2, maxCost: 3, model: undefined, out: join(repoRoot, "scripts/bench/results"), cli: defaultCli, timeout: 900 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--owasp") o.owasp = resolve(next());
    else if (a === "--labels") o.labels = resolve(next());
    else if (a === "--app") o.app = resolve(next());
    else if (a === "--per-class") o.perClass = Number(next());
    else if (a === "--seed") o.seed = Number(next());
    else if (a === "--categories") o.categories = next().split(",");
    else if (a === "--scan-budget") o.scanBudget = Number(next());
    else if (a === "--verify-budget") o.verifyBudget = Number(next());
    else if (a === "--max-cost") o.maxCost = Number(next());
    else if (a === "--model") o.model = next();
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--cli") o.cli = resolve(next());
    else if (a === "--timeout") o.timeout = Number(next());
    else throw new Error(`unknown option ${a}`);
  }
  if (o.run === o.dryRun) throw new Error("pass exactly one of --run (spends model money) or --dry-run (free)");
  if (Boolean(o.owasp) === Boolean(o.labels)) throw new Error("pass exactly one of --owasp <checkout> or --labels <file>");
  if (o.labels && !o.app) throw new Error("--labels needs --app <folder> to scan");
  if (!Number.isInteger(o.perClass) || o.perClass < 1) throw new Error("--per-class must be a positive integer");
  for (const c of o.categories ?? []) if (!CATEGORY_WORDS[c]) throw new Error(`unknown category ${c} (${Object.keys(CATEGORY_WORDS).join(", ")})`);
  return o;
}

/** The scratch folder the scan sees, the classifier and a description of the sample. */
export function prepare(o) {
  const root = mkdtempSync(join(tmpdir(), "0-triage-truth-"));
  const folder = join(root, "app");
  if (o.owasp) {
    const csv = join(o.owasp, "expectedresults-1.2.csv");
    if (!existsSync(csv)) throw new Error(`${csv} not found: pass a BenchmarkJava checkout`);
    const sample = sampleCases(parseExpectedResults(readFileSync(csv, "utf8")), { perClass: o.perClass, seed: o.seed, categories: o.categories });
    const dir = join(o.owasp, "src/main/java/org/owasp/benchmark/testcode");
    mkdirSync(folder, { recursive: true });
    for (const r of sample) cpSync(join(dir, `${r.name}.java`), join(folder, `${r.name}.java`));
    return { root, folder, classify: owaspClassifier(sample), describe: `OWASP Benchmark 1.2 sample: ${sample.length} cases (${sample.filter((r) => r.real).length} real, ${sample.filter((r) => !r.real).length} not real), seed ${o.seed}, per-class ${o.perClass}`, name: "owasp-sample" };
  }
  const labels = JSON.parse(readFileSync(o.labels, "utf8")).findings ?? [];
  cpSync(o.app, folder, { recursive: true, filter: (src) => !src.includes("/.git/") });
  return { root, folder, classify: labelClassifier(labels), describe: `hand-labelled set: ${labels.length} labels (${labels.filter((l) => l.label === "real").length} real, ${labels.filter((l) => l.label !== "real").length} noise)`, name: "hand-labelled" };
}

/** Scan the folder, run verify --apply, classify each verified finding. */
function pipeline(o, prep) {
  const env = isolatedEnv(join(prep.root, "home"));
  const cli = (args, timeoutSeconds) => run(process.execPath, [o.cli, ...args], { cwd: repoRoot, env, timeoutSeconds });
  const model = o.model ? ["--model", o.model] : [];
  const scanFile = join(prep.root, "scan.json");
  const scan = cli(["scan", prep.folder, "--budget", String(o.scanBudget), "--format", "json", "-o", scanFile, "--timeout", String(o.timeout), ...model], o.timeout + 120);
  let report; try { report = JSON.parse(readFileSync(scanFile, "utf8")); } catch { /* no report */ }
  const findings = report?.findings ?? [];
  const result = { fixture: prep.name, repeat: 1, scanStatus: scan.status, findings: findings.length, rows: [], scanCostUsd: report?.usage?.costUsd ?? report?.costUsd ?? 0, root: prep.root };
  if (!findings.length) return result;
  const verify = cli(["findings", "verify", "--folder", prep.folder, "--apply", "--budget", String(o.verifyBudget), "--format", "json", "--timeout", "600", ...model], 1800);
  let verified; try { verified = JSON.parse(verify.stdout); } catch { result.verifyError = (verify.stderr || verify.stdout).slice(-400); return result; }
  result.verifyCostUsd = verified.costUsd;
  const byId = new Map(findings.map((f) => [f.id, f]));
  for (const item of verified.items) {
    const f = byId.get(item.finding);
    result.rows.push({ id: item.finding, title: f?.title, severity: item.severity, cls: f ? prep.classify(f) : "other", verdict: item.verdict ?? item.result, applied: Boolean(item.applied), reasoning: item.reasoning });
  }
  return result;
}

/** Dry run: classify made-up findings so the sampling, matching and report are checked without a model. */
function dryRun(o) {
  const prep = prepare(o);
  const sampleNames = prep.describe;
  console.log(`ok   ${sampleNames}`);
  const rows = [{ cls: "tp", verdict: "true-positive" }, { cls: "fp", verdict: "false-positive" }];
  const text = renderTriage([{ fixture: prep.name, repeat: 1, findings: 2, rows }], { date: "dry-run", model: "none", fixtures: [prep.name], repeat: 1, synthetic: true, truth: prep.describe });
  if (!text.includes("| true-positive |")) throw new Error("the report did not render");
  console.log(`scratch folder with the sampled files: ${prep.folder}\ndry run passed: no model was called.`);
}

if (isMain(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/triage-truth.mjs (--run | --dry-run) (--owasp <checkout> [--per-class N] [--seed N] [--categories a,b] | --labels <file> --app <folder>) [--scan-budget USD] [--verify-budget USD] [--max-cost USD] [--model id] [--out dir]`); process.exit(2); }
  try {
    if (o.dryRun) dryRun(o);
    else {
      if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build the engine and then the CLI first`);
      const prep = prepare(o);
      console.log(prep.describe);
      const r = pipeline(o, prep);
      const spent = (r.scanCostUsd ?? 0) + (r.verifyCostUsd ?? 0);
      console.log(`${r.findings} findings, ${r.rows.length} verified, spend $${spent.toFixed(4)}${r.verifyError ? `, verify failed: ${r.verifyError}` : ""}`);
      if (spent > o.maxCost) console.log(`warning: spend passed --max-cost ${o.maxCost}`);
      const meta = { date: new Date().toISOString().slice(0, 10), model: o.model ?? "default (gpt-6-luna)", fixtures: [prep.name], repeat: 1, truth: prep.describe };
      const md = renderTriage([r], meta);
      const stamp = `triage-truth-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      mkdirSync(o.out, { recursive: true });
      const { root, ...saved } = r;
      writeFileSync(join(o.out, `${stamp}.json`), `${JSON.stringify({ meta, metrics: { ...triageMetrics(r.rows), tally: undefined }, run: saved }, null, 2)}\n`);
      writeFileSync(join(o.out, `${stamp}.md`), md);
      console.log(`\n${md}\nwrote ${join(o.out, stamp)}.{md,json}`);
    }
  } catch (e) { console.error(e.message); process.exit(1); }
}
