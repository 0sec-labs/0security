#!/usr/bin/env node
// Real-application benchmark: scans public, intentionally vulnerable apps and scores the findings against answer keys
// built from each project's own documentation. See docs/design/benchmark.md, section "Real applications".
//
//   node scripts/bench/real-apps.mjs --clone [--root /tmp/realbench]   clone each app at its pinned commit (network, no model)
//   node scripts/bench/real-apps.mjs --dry-run [--root ...]            check the keys against the clones (no model, no cost)
//   node scripts/bench/real-apps.mjs --run [--repeat 2] [--budget 2] [--total-budget 18] [--configs a,b] [--apps x,y]
//
// The apps are UNTRUSTED code. The harness never installs, builds or runs them: it clones them as text, copies them to a
// scratch folder without .git, the answer source and vendored files, and the scan reads that copy. Nothing in the copy runs.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { familiesOf, LINE_TOLERANCE, lineDistance, mean, samePath, scoreFindings, spread, validateAnswer } from "./match.mjs";
import { defaultCli, git, isMain, isolatedEnv, pct, range, repoRoot, run as runProcess, usd } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const KEYS_DIR = join(here, "real-apps");
export const DEFAULT_ROOT = "/tmp/realbench";
export const CONFIGS = ["default", "prepass-off", "foxguard-semgrep", "batched", "single", "lean"];
const SEVERITY = ["critical", "high", "medium", "low", "info"];
const MAX_FILE_BYTES = 1_000_000;

export function loadKeys(only) {
  const files = readdirSync(KEYS_DIR).filter((f) => f.endsWith(".answer.json")).sort();
  const keys = files.map((f) => JSON.parse(readFileSync(join(KEYS_DIR, f), "utf8")));
  const picked = only ?? keys.map((k) => k.fixture);
  for (const n of picked) if (!keys.some((k) => k.fixture === n)) throw new Error(`unknown app ${n} (known: ${keys.map((k) => k.fixture).join(", ")})`);
  return keys.filter((k) => picked.includes(k.fixture));
}

export const cloneDir = (root, key) => join(root, key.fixture, "src");

export function parseArgs(argv) {
  const o = { mode: undefined, root: DEFAULT_ROOT, repeat: 1, budget: 2, totalBudget: 18, configs: ["default", "prepass-off", "foxguard-semgrep", "batched"], apps: undefined, model: undefined, out: join(here, "results", "real-apps"), cli: defaultCli, timeout: 1500, batchSize: 8, concurrency: 3 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--clone" || a === "--dry-run" || a === "--run" || a === "--report") { if (o.mode) throw new Error("pass exactly one of --clone, --dry-run, --run, --report"); o.mode = a.slice(2); }
    else if (a === "--root") o.root = resolve(next());
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--budget") o.budget = Number(next());
    else if (a === "--total-budget") o.totalBudget = Number(next());
    else if (a === "--configs") o.configs = next().split(",");
    else if (a === "--apps") o.apps = next().split(",");
    else if (a === "--model") o.model = next();
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--cli") o.cli = resolve(next());
    else if (a === "--timeout") o.timeout = Number(next());
    else if (a === "--batch-size") o.batchSize = Number(next());
    else if (a === "--concurrency") o.concurrency = Number(next());
    else if (a === "--stored-families") o.storedFamilies = true;
    else throw new Error(`unknown option ${a}`);
  }
  if (!o.mode) throw new Error("pass exactly one of --clone, --dry-run (free) or --run (spends model money)");
  if (!Number.isInteger(o.repeat) || o.repeat < 1) throw new Error("--repeat must be a positive integer");
  if (!(o.budget > 0) || !(o.totalBudget > 0)) throw new Error("--budget and --total-budget must be positive numbers of USD");
  for (const c of o.configs) if (!CONFIGS.includes(c)) throw new Error(`unknown config ${c} (known: ${CONFIGS.join(", ")})`);
  return o;
}

// ---- comment scrub -------------------------------------------------------------------------------------------------
// These apps teach with their code: some carry whole-line comments such as "Fix for A1" or "Insecure use of eval", and
// commented-out fixed code. A scan that reads those is reading the answer. The scanned copy blanks whole-line comments
// and trailing comments that name the flaw, keeping every line number, so the answer key still applies. Strings and URLs
// are left alone (a trailing comment is only cut when what comes before it has balanced quotes).
const TRAILING_HINT = /vuln|insecure|fix|attack|inject|bypass|exploit|enumerat|dos\b|unauthori|exposure|mass assign|\bbola\b|\ba\d{1,2}\b|owasp|safe|secure|xss|csrf|redos|ssrf|hash|weak|todo/i;
const balanced = (code) => ["\"", "'", "`"].every((q) => (code.split(q).length - 1) % 2 === 0);

/** Returns the text with comments blanked and the number of lines changed. Same number of lines in and out. */
export function scrubComments(text, language) {
  const lines = text.split("\n");
  let inBlock = false;
  let changed = 0;
  const out = lines.map((line) => {
    if (language === "html") {
      // HTML comments, whole or across lines: cut the comment, keep what is around it on the same line.
      let next = line;
      if (inBlock) { const end = next.indexOf("-->"); if (end === -1) next = ""; else { next = next.slice(end + 3); inBlock = false; } }
      for (let start = next.indexOf("<!--"); start !== -1; start = next.indexOf("<!--")) {
        const end = next.indexOf("-->", start + 4);
        if (end === -1) { next = next.slice(0, start); inBlock = true; } else next = next.slice(0, start) + next.slice(end + 3);
      }
      if (next !== line) changed++;
      return next;
    }
    const t = line.trim();
    let next = line;
    if (language === "js") {
      if (inBlock) { if (t.includes("*/")) inBlock = false; next = ""; }
      else if (t.startsWith("/*")) { if (!t.includes("*/")) inBlock = true; next = ""; }
      else if (t.startsWith("//")) next = "";
      else {
        const at = line.search(/\s\/\/\s/);
        if (at > 0 && balanced(line.slice(0, at)) && TRAILING_HINT.test(line.slice(at))) next = line.slice(0, at).replace(/\s+$/, "");
      }
    } else if (language === "py") {
      if (t.startsWith("#")) next = "";
      else {
        const at = line.search(/\s#\s?/);
        if (at > 0 && balanced(line.slice(0, at)) && TRAILING_HINT.test(line.slice(at))) next = line.slice(0, at).replace(/\s+$/, "");
      }
    }
    if (next !== line) changed++;
    return next;
  });
  return { text: out.join("\n"), changed };
}

const languageOf = (name) => (/\.(c|m)?js$/.test(name) ? "js" : name.endsWith(".py") ? "py" : /\.(html|ejs)$/.test(name) ? "html" : null);

/** Files of a clone that belong in the scanned copy: not .git, not excluded, not huge. Paths are relative with forward slashes. */
export function listScanFiles(dir, exclude = [], prefix = "") {
  const files = [];
  for (const e of readdirSync(join(dir, prefix), { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.name === ".git" || e.name === "node_modules") continue;
    if (exclude.some((x) => rel === x || rel.startsWith(`${x}/`))) continue;
    if (e.isDirectory()) files.push(...listScanFiles(dir, exclude, rel));
    else if (e.isFile() && statSync(join(dir, rel)).size <= MAX_FILE_BYTES) files.push(rel);
  }
  return files.sort();
}

/** Writes the scanned copy of an app into a new folder. Returns counts for the report. */
export function buildCopy(srcDir, key, dest) {
  const files = listScanFiles(srcDir, key.exclude);
  let scrubbed = 0;
  let lines = 0;
  for (const rel of files) {
    const target = join(dest, rel);
    mkdirSync(dirname(target), { recursive: true });
    const raw = readFileSync(join(srcDir, rel));
    const language = languageOf(rel);
    if (language && !raw.includes(0)) {
      const r = scrubComments(raw.toString("utf8"), language);
      scrubbed += r.changed;
      lines += r.text.split("\n").length;
      writeFileSync(target, r.text);
    } else writeFileSync(target, raw);
  }
  return { files: files.length, scrubbedLines: scrubbed, sourceLines: lines };
}

// ---- clone ---------------------------------------------------------------------------------------------------------
function cloneApp(key, root) {
  const dir = cloneDir(root, key);
  if (existsSync(dir) && readdirSync(dir).length) { console.log(`skip  ${key.fixture}: ${dir} already exists (never overwritten)`); return true; }
  mkdirSync(dir, { recursive: true });
  // Fetch exactly the pinned commit, shallow, without a shell. Nothing from the repository runs.
  const steps = [["init", "-q"], ["remote", "add", "origin", key.repo], ["fetch", "--depth", "1", "-q", "origin", key.sha], ["-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"]];
  for (const s of steps) {
    const r = git(dir, s, { timeoutSeconds: 300 });
    if (r.status !== 0) { console.error(`FAIL  ${key.fixture}: git ${s[0]} ${r.stderr.trim()}`); return false; }
  }
  console.log(`ok    ${key.fixture}: ${key.sha.slice(0, 12)} -> ${dir}`);
  return true;
}

// ---- dry run -------------------------------------------------------------------------------------------------------
const lineCounts = (dir, files) => Object.fromEntries(files.map((rel) => { const t = readFileSync(join(dir, rel), "utf8"); return [rel, t.split("\n").length - (t.endsWith("\n") ? 1 : 0)]; }));

/** Problems with one key against its clone: wrong commit, missing files, lines past the end, anchors not in range. */
export function checkKey(key, dir) {
  const problems = [];
  const head = runProcess("git", ["-C", dir, "rev-parse", "HEAD"]);
  if (head.status !== 0) return [`${key.fixture}: ${dir} is not a clone (run --clone)`];
  if (head.stdout.trim() !== key.sha) problems.push(`${key.fixture}: clone is at ${head.stdout.trim().slice(0, 12)}, the key pins ${key.sha.slice(0, 12)}`);
  const all = listScanFiles(dir, []);
  const inCopy = new Set(listScanFiles(dir, key.exclude));
  const counts = lineCounts(dir, all);
  problems.push(...validateAnswer({ ...key, items: key.items }, { fileLines: counts }).map((p) => `${key.fixture}: ${p}`));
  for (const entry of [...key.items, ...key.decoys]) {
    if (!inCopy.has(entry.path)) problems.push(`${key.fixture}/${entry.id}: ${entry.path} is excluded from the scanned copy`);
    if (!entry.docRef && key.items.includes(entry)) problems.push(`${key.fixture}/${entry.id}: no docRef`);
    if (!["doc-file-function", "located-by-us"].includes(entry.source) && key.items.includes(entry)) problems.push(`${key.fixture}/${entry.id}: source must be doc-file-function or located-by-us`);
    if (entry.anchor && counts[entry.path] !== undefined) {
      const body = readFileSync(join(dir, entry.path), "utf8").split("\n").slice(entry.startLine - 1, entry.endLine).join("\n");
      if (!body.includes(entry.anchor)) problems.push(`${key.fixture}/${entry.id}: anchor ${JSON.stringify(entry.anchor)} not found in ${entry.path}:${entry.startLine}-${entry.endLine}`);
    }
  }
  return problems;
}

const SYNTHETIC_TITLE = { sqli: "SQL injection", "command-injection": "command injection", secret: "hardcoded secret", authz: "missing authorization", "weak-crypto": "weak md5 hash", xxe: "XXE", csrf: "CSRF", "open-redirect": "open redirect", redos: "ReDoS", "vuln-dependency": "vulnerable dependency", authn: "session fixation", transport: "cleartext http", misconfig: "stack trace", "rate-limit": "rate limiting", "mass-assignment": "mass assignment", xss: "XSS", deserialization: "unsafe deserialization", ssrf: "SSRF" };

function dryRun(o) {
  let bad = 0;
  for (const key of loadKeys(o.apps)) {
    const dir = cloneDir(o.root, key);
    const problems = existsSync(dir) ? checkKey(key, dir) : [`${key.fixture}: no clone at ${dir} (run --clone)`];
    const docs = key.items.filter((i) => i.source === "doc-file-function").length;
    console.log(`${problems.length ? "FAIL" : "ok  "} ${key.fixture}: ${key.items.length} items (${docs} located by the docs, ${key.items.length - docs} located by us), ${key.decoys.length} decoys, sha ${key.sha.slice(0, 12)}`);
    for (const p of problems) console.log(`     ${p}`);
    bad += problems.length;
    if (!problems.length) {
      // The scanned copy must keep every line number and drop the answer source.
      const scratch = mkdtempSync(join(tmpdir(), "0-realbench-dry-"));
      const c = buildCopy(dir, key, scratch);
      const orig = lineCounts(dir, listScanFiles(dir, key.exclude));
      const copy = lineCounts(scratch, listScanFiles(scratch, []));
      const drift = Object.keys(orig).filter((f) => orig[f] !== copy[f]);
      if (drift.length) { console.log(`FAIL ${key.fixture}: scrub changed line counts of ${drift.join(", ")}`); bad++; }
      for (const x of key.exclude) if (existsSync(join(scratch, x))) { console.log(`FAIL ${key.fixture}: excluded path ${x} is in the copy`); bad++; }
      console.log(`     scanned copy: ${c.files} files, ${c.sourceLines} source lines, ${c.scrubbedLines} comment lines blanked (${scratch})`);
      // The matcher sees an item credited by a finding at its first line and not by one far away.
      const sample = key.items.map((it, i) => ({ id: `s${i}`, title: SYNTHETIC_TITLE[[].concat(it.category)[0]] ?? "unknown", category: "other", location: { path: it.path, startLine: it.startLine } }));
      const score = scoreFindings(key, sample);
      if (score.found !== key.items.length) { console.log(`FAIL ${key.fixture}: synthetic findings credit ${score.found} of ${key.items.length} items (missed: ${score.missedIds.join(", ")})`); bad++; }
    }
  }
  if (bad) { console.error(`\n${bad} problem(s)`); process.exit(1); }
  console.log("\ndry run passed: keys match the clones. No model was called.");
}

// ---- run -----------------------------------------------------------------------------------------------------------
export function scanArgs(config, folder, outFile, o) {
  const args = ["scan", folder, "--budget", String(o.budget), "--format", "json", "-o", outFile, "--timeout", String(o.timeout)];
  if (o.model) args.push("--model", o.model);
  if (config === "prepass-off") args.push("--prepass", "off");
  else if (config === "foxguard-semgrep") args.push("--prepass", "auto", "--scanner", "foxguard,semgrep");
  else if (config === "batched") args.push("--batches", "on", "--batch-size", String(o.batchSize), "--concurrency", String(o.concurrency));
  else if (config === "single") args.push("--batches", "off");
  else if (config === "lean") args.push("--batches", "off", "--prepass", "off");
  return args;
}

const sevRank = (s) => { const i = SEVERITY.indexOf(String(s).toLowerCase()); return i === -1 ? SEVERITY.length : i; };

function scanOnce(key, config, repeat, o, foxguard) {
  const root = mkdtempSync(join(tmpdir(), "0-realbench-run-"));
  const folder = join(root, "app");
  const copy = buildCopy(cloneDir(o.root, key), key, folder);
  const outFile = join(root, "report.json");
  const env = isolatedEnv(join(root, "home"));
  if (foxguard) env.ZERO_FOXGUARD_PATH = foxguard;
  const started = Date.now();
  const proc = spawnSync(process.execPath, [o.cli, ...scanArgs(config, folder, outFile, o)], { env, encoding: "utf8", timeout: (o.timeout + 180) * 1000, cwd: repoRoot, maxBuffer: 64 * 1024 * 1024 });
  const seconds = (Date.now() - started) / 1000;
  let report;
  try { report = JSON.parse(readFileSync(outFile, "utf8")); } catch { /* the scan failed before it wrote a report */ }
  const findings = report?.findings ?? [];
  const score = scoreFindings(key, findings);
  // Decoy hits and unmatched findings, with the severity so the worst can be read by hand.
  const bySeverity = (label) => { const f = findings.find((x) => (x.id ?? x.title) === label); return f ? sevRank(f.severity) : SEVERITY.length; };
  const unmatched = score.unmatched.map((u) => { const f = findings.find((x) => (x.id ?? x.title) === u.finding); return { ...u, severity: f?.severity, path: f?.location?.path, startLine: f?.location?.startLine, rank: bySeverity(u.finding) }; });
  return {
    app: key.fixture, config, repeat, seconds,
    costUsd: report?.costUsd ?? null, status: report?.status ?? `no-report (exit ${proc.status})`,
    error: report ? report.error : (proc.stderr ?? "").slice(-300),
    coverage: report?.coverage?.statement ?? null, threads: report?.threadIds?.length ?? (report ? 1 : null),
    prepass: report?.prepass ?? report?.scanners ?? null,
    log: (`${proc.stdout ?? ""}\n${proc.stderr ?? ""}`).split("\n").filter((l) => /pre-?pass|foxguard|semgrep|lead|batch|coverage|entry point|inventory/i.test(l)).slice(0, 20),
    copy, score: { ...score, unmatched }, reportKeys: report ? Object.keys(report) : [],
    findings: findings.map((f) => ({ id: f.id, title: f.title, severity: f.severity, category: f.category, location: f.location, families: [...familiesOf(f)] })),
    workdir: root,
  };
}

function findFoxguard() {
  const hit = [process.env.ZERO_FOXGUARD_PATH, join(process.env.HOME ?? "", ".0", "bin", "foxguard")].filter(Boolean).find((c) => existsSync(c));
  if (hit) return hit;
  const which = runProcess("which", ["foxguard"]);
  return which.status === 0 ? which.stdout.trim() : undefined;
}

/**
 * Items a person would credit for one scan. A finding credits an item when it sits within the line tolerance of the item
 * (or its alsoAt places) and either belongs to the item's category family or is a near miss that a person accepts, and its
 * title is not on the key's reject list. `nearMissIgnore` lists items whose wording-only matches never count; `nearMissReject`
 * lists {item, hint} pairs: a title containing the hint is a wrong match (also when the strict matcher credited it).
 */
export function adjudicate(key, run) {
  const ignore = key.nearMissIgnore ?? [];
  const reject = key.nearMissReject ?? [];
  const credited = new Set();
  for (const item of key.items) {
    const spots = [item, ...(item.alsoAt ?? [])];
    const cats = [].concat(item.category);
    for (const f of run.findings ?? []) {
      const loc = f.location;
      if (!loc || !Number.isFinite(loc.startLine)) continue;
      const near = spots.some((sp) => samePath(loc.path, sp.path) && lineDistance(loc.startLine, loc.endLine ?? loc.startLine, sp.startLine, sp.endLine) <= LINE_TOLERANCE);
      if (!near) continue;
      const family = (f.families ?? []).some((c) => cats.includes(c));
      if (!family && ignore.includes(item.id)) continue;
      const title = String(f.title ?? "").toLowerCase();
      if (reject.some((r) => r.item === item.id && title.includes(r.hint.toLowerCase()))) continue;
      credited.add(item.id);
      break;
    }
  }
  return credited;
}

/** One row per app and config: mean and spread over the repeats. */
export function summarize(runs, keys = {}) {
  const groups = new Map();
  for (const r of runs) { const k = `${r.app}|${r.config}`; groups.set(k, [...(groups.get(k) ?? []), r]); }
  return [...groups.values()].map((rs) => {
    const costs = rs.map((r) => r.costUsd).filter((x) => x !== null);
    return {
      app: rs[0].app, config: rs[0].config, repeats: rs.length, planted: rs[0].score.planted,
      recallMean: mean(rs.map((r) => r.score.recall)), recallSpread: spread(rs.map((r) => r.score.recall)),
      foundMean: mean(rs.map((r) => r.score.found)), found: rs.map((r) => r.score.found),
      // Items also credited when a finding sits on them but the wording names no family (read by hand before use).
      foundAdjudicated: rs.map((r) => (keys[r.app] ? adjudicate(keys[r.app], r).size : r.score.found)),
      // Decoy hits whose finding is not also on an item: a finding that spans a whole if/else reaches the safe branch by range.
      decoyAdjMean: mean(rs.map((r) => r.score.decoyHits.filter((d) => !r.score.nearMisses.some((n) => n.finding === d.finding)).length)),
      findingsMean: mean(rs.map((r) => r.score.findings)), unmatchedMean: mean(rs.map((r) => r.score.unmatched.length)),
      decoyHitsMean: mean(rs.map((r) => r.score.decoyHits.length)),
      costMean: mean(costs), costTotal: costs.reduce((a, b) => a + b, 0),
      secondsMean: mean(rs.map((r) => r.seconds)), secondsSpread: spread(rs.map((r) => r.seconds)),
      statuses: rs.map((r) => r.status), coverage: rs.map((r) => r.coverage).filter(Boolean),
      missedEvery: rs[0].score.missedIds.filter((id) => rs.every((r) => r.score.missedIds.includes(id))),
    };
  });
}

export function renderMarkdown(rows, meta) {
  const lines = [`# Real-application benchmark`, "", `- Date: ${meta.date}`, `- Model: ${meta.model}`, `- Repeats: ${meta.repeat}`, `- Per-scan budget: $${meta.budget}`, `- Total cost: ${usd(rows.reduce((a, r) => a + r.costTotal, 0))}`, "",
    "| app | config | recall (min-max) | found per repeat | found after hand review | unmatched | decoy hits | cost | time (s) | status | coverage | missed in every repeat |", "|---|---|---|---|---|---|---|---|---|---|---|---|"];
  for (const r of rows) lines.push(`| ${r.app} | ${r.config} | ${pct(r.recallMean)} (${range(r.recallSpread, pct)}) | ${r.found.join(", ")} of ${r.planted} | ${r.foundAdjudicated.join(", ")} | ${r.unmatchedMean.toFixed(1)} | ${r.decoyHitsMean.toFixed(1)} (${r.decoyAdjMean.toFixed(1)} not on an item) | ${usd(r.costMean)} | ${r.secondsMean.toFixed(0)} (${range(r.secondsSpread, (x) => x.toFixed(0))}) | ${[...new Set(r.statuses)].join("; ")} | ${r.coverage[0] ?? "-"} | ${r.missedEvery.join(", ") || "-"} |`);
  return `${lines.join("\n")}\n`;
}

function realRun(o) {
  if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build it with pnpm --filter @0/engine build && pnpm --filter @0/cli build`);
  const keys = loadKeys(o.apps);
  for (const key of keys) { const p = checkKey(key, cloneDir(o.root, key)); if (p.length) throw new Error(`keys are invalid, run --dry-run:\n${p.join("\n")}`); }
  const foxguard = findFoxguard();
  if (!foxguard && o.configs.some((c) => c !== "prepass-off")) console.log("note: foxguard is not installed, the pre-pass will not run for the default configs");
  const total = keys.length * o.configs.length * o.repeat;
  console.log(`${total} scans; worst case $${(total * o.budget).toFixed(2)} at --budget ${o.budget}; stops starting scans past --total-budget ${o.totalBudget}`);
  const runs = [];
  let spent = 0;
  mkdirSync(o.out, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  for (let rep = 1; rep <= o.repeat; rep++) for (const key of keys) for (const config of o.configs) {
    if (spent + o.budget > o.totalBudget) { console.log(`skip ${key.fixture}/${config}/${rep}: ${usd(spent)} spent, a scan could take it past $${o.totalBudget}`); continue; }
    process.stdout.write(`scan ${key.fixture} / ${config} / repeat ${rep} ... `);
    const r = scanOnce(key, config, rep, o, foxguard);
    spent += r.costUsd ?? 0;
    runs.push(r);
    writeFileSync(join(o.out, `${stamp}-${key.fixture}-${config}-${rep}.json`), `${JSON.stringify({ ...r, workdir: undefined }, null, 2)}\n`);
    console.log(`${r.status}, ${r.score.found}/${r.score.planted} found, ${r.score.findings} findings, ${r.score.unmatched.length} unmatched, ${r.score.decoyHits.length} decoy hits, ${usd(r.costUsd)}, ${r.seconds.toFixed(0)}s${r.coverage ? `, ${r.coverage}` : ""} (spent ${usd(spent)})`);
  }
  const rows = summarize(runs, Object.fromEntries(keys.map((k) => [k.fixture, k])));
  const meta = { date: new Date().toISOString().slice(0, 10), model: o.model ?? "default", repeat: o.repeat, budget: o.budget, spent };
  writeFileSync(join(o.out, `${stamp}-summary.json`), `${JSON.stringify({ meta, rows }, null, 2)}\n`);
  writeFileSync(join(o.out, `${stamp}-summary.md`), renderMarkdown(rows, meta));
  console.log(`\n${renderMarkdown(rows, meta)}\nwrote ${join(o.out, stamp)}-*.json (reports with findings, one per scan)`);
}

if (isMain(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/real-apps.mjs (--clone | --dry-run | --run) [--root ${DEFAULT_ROOT}] [--apps dvna,nodegoat,vampi] [--configs ${CONFIGS.join(",")}] [--repeat N] [--budget USD] [--total-budget USD] [--out dir]`); process.exit(2); }
  try {
    if (o.mode === "clone") { let ok = true; for (const key of loadKeys(o.apps)) ok = cloneApp(key, o.root) && ok; if (!ok) process.exit(1); }
    else if (o.mode === "dry-run") dryRun(o);
    else if (o.mode === "report") {
      // Re-summarise saved scans (the per-scan JSON files of a --run) without scanning again.
      const runs = readdirSync(o.out).filter((f) => f.endsWith(".json") && !f.includes("summary")).map((f) => JSON.parse(readFileSync(join(o.out, f), "utf8"))).filter((r) => !String(r.status).startsWith("no-report"));
      const keyMap0 = Object.fromEntries(loadKeys().map((k) => [k.fixture, k]));
      // Score the saved findings again, so a corrected key applies to scans that were already paid for. The families are worked
      // out again from each finding's category and title with the current rules (the category first goes through the engine's
      // category rules, as a new finding does), unless --stored-families asks for the families the scan was scored with.
      if (!o.storedFamilies) {
        let classify;
        try { ({ classifyFinding: classify } = await import(join(repoRoot, "packages/engine/dist/shared/index.js"))); } catch { console.error("note: the engine is not built, so saved categories are not re-filed (pnpm --filter @0/engine build)"); }
        for (const r of runs) r.findings = r.findings.map((f) => { const category = classify ? classify({ category: f.category, title: f.title }).category : f.category; return { ...f, category, families: [...familiesOf({ ...f, category, families: undefined })] }; });
      }
      for (const r of runs) r.score = scoreFindings(keyMap0[r.app], r.findings);
      const keyMap = Object.fromEntries(loadKeys().map((k) => [k.fixture, k]));
      console.log(renderMarkdown(summarize(runs, keyMap), { date: "saved", model: "saved", repeat: "saved", budget: "saved" }));
    }
    else realRun(o);
  } catch (e) { console.error(e.message); process.exit(1); }
}
