#!/usr/bin/env node
// Real-model A/B of the code-index tools and of variant hunting. See docs/design/code-index-variants-measurement.md.
//
//   node scripts/bench/code-index/run.mjs --dry-run
//   node scripts/bench/code-index/run.mjs --mode scan --run --repeat 3 --max-runs 27 --max-minutes 150
//   node scripts/bench/code-index/run.mjs --mode variants --run --repeat 3
//
// Scan arms (same fixture, same model, fresh HOME, --prepass off, no answer key in the copy):
//   baseline     plain scan, core toolset
//   index-full   plain scan prompt, but ZERO_TOOLSET=full so callers_of/callees_of/routes/trace_to_sink are advertised
//   index-skill  scan with --skill seedless-depth-review, the shipped way to load the code-index pack. Any skill other
//                than `scan` also turned batching off before the follow-up change; it now batches like a plain scan.
//   baseline-single  plain scan with --batches off: the fair control for index-skill
// Variant arms (fixture variants-docs, one fixed bug and six unfixed siblings):
//   variants     `findings import` of the seed finding, then `findings variants <id>`; variants are scored
//   plain-scan   a plain scan of the same folder (it is not told about the seed), scored on the same siblings
//
// The credential is never read here: the CLI finds it through ZERO_CODEX_AUTH_JSON_PATH (default ~/.codex/auth.json),
// and nothing from the environment, the CLI output or the sessions is written to the results except counts and
// finding titles and locations.
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scoreFindings, mean, spread, validateAnswer } from "../match.mjs";
import { benchDir, defaultCli, isolatedEnv, pct, range, repoRoot, usd } from "../lib.mjs";
import { loadFixtures as loadAll } from "../run.mjs";

/** Fixtures named in `only` that exist under root (a name can live in another root). */
function loadFixtures(only, root) {
  const names = existsSync(root) ? readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory() && existsSync(join(root, d.name, "answer.json"))).map((d) => d.name) : [];
  return loadAll(only ? only.filter((n) => names.includes(n)) : names, root);
}

export const INDEX_TOOLS = ["callers_of", "callees_of", "routes", "trace_to_sink"];
export const ARMS = {
  baseline: { skill: undefined, env: {} },
  "index-full": { skill: undefined, env: { ZERO_TOOLSET: "full" } },
  "index-skill": { skill: "seedless-depth-review", env: {} },
  // Added after the first round: a skill other than `scan` forces one thread (no batches), so index-skill must be
  // compared with a plain scan that is also one thread.
  "baseline-single": { skill: undefined, env: {}, extra: ["--batches", "off"] },
};
const here = join(benchDir, "code-index");
const RATE_LIMIT = /rate[- ]?limit|too many requests|\b429\b|usage limit|quota/i;

export function parseArgs(argv) {
  const o = { mode: "scan", run: false, dryRun: false, repeat: 3, arms: Object.keys(ARMS), fixtures: ["ts-shop", "java-bank", "medium-app"], fixturesDirs: [join(here, "fixtures"), join(benchDir, "fixtures")], variantsDir: join(here, "variants"), model: "gpt-6-luna", budget: 1, timeout: 900, maxRuns: 30, maxMinutes: 180, concurrency: 1, out: join(here, "results"), cli: defaultCli, label: "" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--mode") o.mode = next();
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--arms") o.arms = next().split(",");
    else if (a === "--fixtures") o.fixtures = next().split(",");
    else if (a === "--fixtures-dir") o.fixturesDirs = next().split(",").map((d) => resolve(repoRoot, d));
    else if (a === "--variants-dir") o.variantsDir = resolve(repoRoot, next());
    else if (a === "--model") o.model = next();
    else if (a === "--budget") o.budget = Number(next());
    else if (a === "--timeout") o.timeout = Number(next());
    else if (a === "--max-runs") o.maxRuns = Number(next());
    else if (a === "--max-minutes") o.maxMinutes = Number(next());
    else if (a === "--concurrency") o.concurrency = Number(next());
    else if (a === "--out") o.out = resolve(repoRoot, next());
    else if (a === "--label") o.label = next();
    else throw new Error(`unknown option ${a}`);
  }
  if (o.run === o.dryRun) throw new Error("pass exactly one of --run (calls the model) or --dry-run (free)");
  if (!["scan", "variants"].includes(o.mode)) throw new Error("--mode is scan or variants");
  if (!Number.isInteger(o.repeat) || o.repeat < 1) throw new Error("--repeat must be a positive integer");
  if (o.mode === "scan") for (const a of o.arms) if (!ARMS[a]) throw new Error(`unknown arm ${a} (known: ${Object.keys(ARMS).join(", ")})`);
  if (o.mode === "variants") o.fixtures = undefined;
  if (o.mode === "variants") o.arms = o.arms.filter((a) => ["variants", "plain-scan"].includes(a));
  if (o.mode === "variants" && !o.arms.length) o.arms = ["variants", "plain-scan"];
  return o;
}

/** Counts from one saved thread (console-sessions/<id>.json): assistant turns and tool calls by name. */
export function threadStats(session) {
  const tools = {};
  let turns = 0;
  for (const m of session.messages ?? []) {
    if (m.role !== "assistant") continue;
    turns++;
    if (Array.isArray(m.content)) for (const c of m.content) if (c.type === "tool_use") tools[c.name] = (tools[c.name] ?? 0) + 1;
  }
  return { turns, tools, model: session.model, provider: session.consoleState?.configuration?.runtime?.providerId };
}

/** Sum thread stats over every session a run left in its home. */
export function sessionTotals(home) {
  const dir = join(home, ".0", "console-sessions");
  const total = { threads: 0, turns: 0, tools: {}, models: new Set(), providers: new Set() };
  if (!existsSync(dir)) return { threads: 0, turns: 0, tools: {}, models: [], providers: [] };
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    let s; try { s = threadStats(JSON.parse(readFileSync(join(dir, f), "utf8"))); } catch { continue; }
    total.threads++; total.turns += s.turns;
    for (const [k, v] of Object.entries(s.tools)) total.tools[k] = (total.tools[k] ?? 0) + v;
    if (s.model) total.models.add(s.model);
    if (s.provider) total.providers.add(s.provider);
  }
  return { ...total, models: [...total.models], providers: [...total.providers] };
}

/** Tokens, cost and duration the CLI recorded for its command (metrics.ndjson, last line of each command). */
export function readMetrics(home, command) {
  const file = join(home, ".0", "metrics.ndjson");
  if (!existsSync(file)) return {};
  const rows = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((r) => r && r.command === command);
  const r = rows.at(-1);
  return r ? { tokens: r.tokens ?? null, costUsd: r.costUsd ?? null, seconds: r.durationSeconds ?? null, model: r.model } : {};
}

function foxguardPath() {
  const candidates = [process.env.ZERO_FOXGUARD_PATH, join(repoRoot, "target/foxguard-bin/foxguard"), join(repoRoot, "target/release/foxguard")].filter(Boolean);
  return candidates.find((c) => existsSync(c));
}

function childEnv(home, extra = {}) {
  const env = isolatedEnv(home);
  // The credential file stays where it is; only its location is passed on, never its contents.
  env.ZERO_CODEX_AUTH_JSON_PATH = process.env.ZERO_CODEX_AUTH_JSON_PATH ?? join(homedir(), ".codex", "auth.json");
  const fg = foxguardPath();
  if (fg) env.ZERO_FOXGUARD_PATH = fg;
  return { ...env, ...extra };
}

function exec(args, { env, cwd, timeoutSeconds }) {
  return new Promise((resolveP) => {
    const child = spawn(process.execPath, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = ""; let err = ""; let timedOut = false;
    child.stdout.on("data", (d) => { out += d; if (out.length > 4e6) out = out.slice(-2e6); });
    child.stderr.on("data", (d) => { err += d; if (err.length > 4e6) err = err.slice(-2e6); });
    const t = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutSeconds * 1000);
    child.on("close", (code) => { clearTimeout(t); resolveP({ status: code ?? 1, stdout: out, stderr: err, timedOut }); });
  });
}

// What is kept of each finding in the raw results: enough to score it again (title, category, description, location).
const keep = (f) => ({ title: f.title, category: f.category, severity: f.severity, location: f.location, description: typeof f.description === "string" ? f.description.slice(0, 1200) : undefined });
// The #710 scoring (5-line proximity, no oracle), kept next to the strict score so the two can be compared.
const looseKey = (answer) => ({ ...answer, cleanPaths: [], items: answer.items.map(({ oracle, ...rest }) => rest), decoys: answer.decoys.map(({ category, ...rest }) => rest) });
const slim = (score) => ({ planted: score.planted, found: score.found, foundIds: score.foundIds, missedIds: score.missedIds, recall: score.recall, findings: score.findings, falsePositives: score.falsePositives, decoyHits: score.decoyHits, unmatched: score.unmatched, nearMisses: score.nearMisses });
const isAuthz = (item) => [].concat(item.category).includes("authz");
const authzOf = (answer, score) => { const ids = answer.items.filter(isAuthz).map((i) => i.id); return { planted: ids.length, found: ids.filter((id) => score.foundIds.includes(id)).length }; };

async function scanRun(fx, arm, rep, o) {
  const root = mkdtempSync(join(tmpdir(), "0-ci-bench-"));
  const home = join(root, "home"); const folder = join(root, "app");
  cpSync(fx.dir, folder, { recursive: true, filter: (s) => !s.endsWith("answer.json") });
  const out = join(root, "report.json");
  const a = ARMS[arm];
  const args = [o.cli, "scan", folder, "--budget", String(o.budget), "--format", "json", "-o", out, "--timeout", String(o.timeout), "--prepass", "off", "--model", o.model];
  if (a.skill) args.push("--skill", a.skill);
  if (a.extra) args.push(...a.extra);
  const started = Date.now();
  const proc = await exec(args, { env: childEnv(home, a.env), cwd: repoRoot, timeoutSeconds: o.timeout + 120 });
  const seconds = (Date.now() - started) / 1000;
  let report; try { report = JSON.parse(readFileSync(out, "utf8")); } catch { /* no report */ }
  const score = scoreFindings(fx.answer, report?.findings ?? []);
  const sessions = sessionTotals(home); const metrics = readMetrics(home, "scan");
  const result = {
    kind: "scan", fixture: fx.name, arm, repeat: rep + 1, status: report?.status ?? `no-report (exit ${proc.status})`, seconds, costUsd: report?.costUsd ?? metrics.costUsd ?? null,
    tokens: metrics.tokens ?? null, threads: sessions.threads, turns: sessions.turns, toolCalls: sessions.tools, indexToolCalls: INDEX_TOOLS.reduce((n, t) => n + (sessions.tools[t] ?? 0), 0),
    provider: sessions.providers, model: sessions.models, coverage: report?.coverage?.statement ?? null,
    // From the report itself: its token total includes helper threads; `children` lists them (absent in reports of older builds).
    reportTokens: report?.tokens ?? null, children: report?.children?.count ?? 0, childTurns: report?.children?.turns ?? 0, childTokens: report?.children ? (report.children.inputTokens ?? 0) + (report.children.outputTokens ?? 0) : 0, warnings: report?.warnings ?? [],
    score: slim(score), authz: authzOf(fx.answer, score), loose: (({ found, foundIds, falsePositives }) => ({ found, foundIds, falsePositives }))(scoreFindings(looseKey(fx.answer), report?.findings ?? [])),
    findings: (report?.findings ?? []).map(keep),
    rateLimited: RATE_LIMIT.test(`${proc.stderr}\n${report?.error ?? ""}`) && !report,
  };
  if (result.status !== "complete") result.error = String(report?.error ?? proc.stderr).replace(/\s+/g, " ").slice(-300);
  return result;
}

function seedSarif(fx) {
  const s = fx.answer.seed;
  return { version: "2.1.0", runs: [{ tool: { driver: { name: "bench-seed", rules: [{ id: "authz-read" }] } }, results: [{ ruleId: "authz-read", level: "error", message: { text: `${s.title}. ${s.description}` }, locations: [{ physicalLocation: { artifactLocation: { uri: s.path }, region: { startLine: s.startLine, endLine: s.endLine } } }] }] }] };
}

async function variantsRun(fx, arm, rep, o) {
  if (arm === "plain-scan") return { ...(await scanRun(fx, "baseline", rep, o)), kind: "variants", arm };
  const root = mkdtempSync(join(tmpdir(), "0-ci-bench-"));
  const home = join(root, "home"); const folder = join(root, "app");
  cpSync(fx.dir, folder, { recursive: true, filter: (s) => !s.endsWith("answer.json") });
  const env = childEnv(home);
  const db = join(home, ".0", "bench.db"); mkdirSync(join(home, ".0"), { recursive: true });
  const sarif = join(root, "seed.sarif"); writeFileSync(sarif, JSON.stringify(seedSarif(fx)));
  const started = Date.now();
  const imp = await exec([o.cli, "findings", "import", sarif, "--root", folder, "--db-path", db, "--format", "json"], { env, cwd: repoRoot, timeoutSeconds: 120 });
  const listed = await exec([o.cli, "findings", "list", "--db-path", db, "--format", "json"], { env, cwd: repoRoot, timeoutSeconds: 60 });
  let seedId; try { const j = JSON.parse(listed.stdout); seedId = (j.findings ?? [])[0]?.id; } catch { /* below */ }
  if (!seedId) return { kind: "variants", fixture: fx.name, arm, repeat: rep + 1, status: "no-seed", error: `${imp.stderr}${listed.stderr}`.slice(-300), seconds: 0, score: slim(scoreFindings(fx.answer, [])), findings: [] };
  const hunt = await exec([o.cli, "findings", "variants", seedId, "--folder", folder, "--db-path", db, "--budget", String(o.budget), "--model", o.model, "--timeout", String(o.timeout), "--format", "json"], { env, cwd: repoRoot, timeoutSeconds: o.timeout + 120 });
  const seconds = (Date.now() - started) / 1000;
  const after = await exec([o.cli, "findings", "list", "--db-path", db, "--format", "json"], { env, cwd: repoRoot, timeoutSeconds: 60 });
  let rows = []; try { const j = JSON.parse(after.stdout); rows = j.findings ?? []; } catch { /* none */ }
  const variants = rows.filter((r) => r.id !== seedId).map((r) => ({ ...keep(r), location: r.location ?? r.reviewAnnotation, variantOf: r.variantOf ?? null }));
  let report; try { report = JSON.parse(hunt.stdout); } catch { /* text */ }
  const score = scoreFindings(fx.answer, variants);
  const sessions = sessionTotals(home);
  return {
    kind: "variants", fixture: fx.name, arm, repeat: rep + 1, status: report?.hunt?.error ? `error: ${report.hunt.error}` : hunt.status === 0 ? "complete" : `exit ${hunt.status}`, seconds,
    costUsd: report?.hunt?.costUsd ?? null, tokens: report?.hunt?.tokens ?? null, threads: sessions.threads, turns: sessions.turns, toolCalls: sessions.tools, provider: sessions.providers, model: sessions.models,
    rootCauseSource: report?.hunt?.rootCauseSource ?? null, checklist: report?.hunt?.checklist ?? null, huntError: report?.hunt?.error ?? null, skipped: report?.hunt?.skipped ?? null, score: slim(score), loose: (({ found, foundIds, falsePositives }) => ({ found, foundIds, falsePositives }))(scoreFindings(looseKey(fx.answer), variants)), findings: variants,
    rateLimited: RATE_LIMIT.test(`${hunt.stderr}${report?.hunt?.error ?? ""}`) && !variants.length,
  };
}

export function summarize(runs) {
  const groups = new Map();
  for (const r of runs) { const k = `${r.fixture}|${r.arm}`; (groups.get(k) ?? groups.set(k, []).get(k)).push(r); }
  return [...groups.values()].map((rs) => {
    const ok = rs.filter((r) => r.status === "complete");
    const col = (f, set = rs) => set.map(f).filter((x) => x !== null && x !== undefined);
    return {
      fixture: rs[0].fixture, arm: rs[0].arm, runs: rs.length, complete: ok.length, planted: rs[0].score.planted,
      found: col((r) => r.score.found), recall: col((r) => r.score.recall), falsePositives: col((r) => r.score.falsePositives), unmatched: col((r) => r.score.unmatched.length),
      authzFound: col((r) => r.authz?.found), authzPlanted: rs[0].authz?.planted ?? null,
      tokens: col((r) => r.tokens), turns: col((r) => r.turns), seconds: col((r) => r.seconds), costUsd: col((r) => r.costUsd), indexToolCalls: col((r) => r.indexToolCalls),
    };
  });
}

const fmt = (xs, f = (x) => x.toFixed(1)) => (xs.length ? `${f(mean(xs))} (${range(spread(xs), f)})` : "n/a");
export function renderMarkdown(rows, meta) {
  const L = [`# Code-index and variant measurement (${meta.mode})`, "", `- Date: ${meta.date}`, `- Provider/model seen in the sessions: ${meta.providers.join(", ") || "n/a"} / ${meta.models.join(", ") || "n/a"}`, `- Runs executed: ${meta.runs}; stopped early: ${meta.stoppedEarly ?? "no"}`, "", "Cells are mean with the min-max range over repeats in brackets. Cost is the CLI's estimate; this model is included in the subscription, so nothing was billed.", "", "| fixture | arm | runs ok/total | found/planted | false pos. | unmatched | authz found/planted | turns | tokens | time (s) | index tool calls |", "|---|---|---|---|---|---|---|---|---|---|---|"];
  for (const r of rows) L.push(`| ${r.fixture} | ${r.arm} | ${r.complete}/${r.runs} | ${fmt(r.found)}/${r.planted} | ${fmt(r.falsePositives)} | ${fmt(r.unmatched)} | ${r.authzPlanted === null ? "-" : `${fmt(r.authzFound)}/${r.authzPlanted}`} | ${fmt(r.turns, (x) => x.toFixed(0))} | ${fmt(r.tokens, (x) => `${(x / 1000).toFixed(0)}k`)} | ${fmt(r.seconds, (x) => x.toFixed(0))} | ${fmt(r.indexToolCalls, (x) => x.toFixed(1))} |`);
  return `${L.join("\n")}\n`;
}

/** Line counts of every file an answer key points at (items, alsoAt spots, decoys, cleanPaths), to catch a key that drifted. */
function fileLinesOf(dir, answer) {
  const paths = new Set([...answer.items, ...answer.decoys].flatMap((e) => [e.path, ...(e.alsoAt ?? []).map((a) => a.path)]).concat(answer.cleanPaths ?? []));
  const lines = {};
  for (const p of paths) { const f = join(dir, p); if (existsSync(f)) lines[p] = readFileSync(f, "utf8").split("\n").length - (readFileSync(f, "utf8").endsWith("\n") ? 1 : 0); }
  return lines;
}

async function dryRun(o) {
  let bad = 0;
  const dirs = o.mode === "variants" ? [o.variantsDir] : o.fixturesDirs;
  for (const d of dirs) for (const fx of loadFixtures(o.fixtures, d)) {
    const problems = validateAnswer(fx.answer, { fileLines: fileLinesOf(fx.dir, fx.answer) });
    if (o.mode === "variants" && !fx.answer.seed) problems.push("a variant fixture needs a seed");
    const findings = fx.answer.items.map((it, i) => ({ id: `s${i}`, title: `synthetic ${[].concat(it.category)[0]}`, description: it.description, category: [].concat(it.category)[0] === "authn" ? "broken-authentication" : "other", location: { path: it.path, startLine: it.startLine + 1 } }));
    const score = scoreFindings(fx.answer, findings);
    if (score.found !== fx.answer.items.length) problems.push(`synthetic findings found ${score.found}/${fx.answer.items.length}`);
    console.log(`${problems.length ? "FAIL" : "ok  "} ${fx.name}: ${fx.answer.items.length} planted, ${fx.answer.decoys.length} decoys`);
    for (const p of problems) console.log(`     ${p}`);
    bad += problems.length;
  }
  if (bad) process.exit(1);
  console.log("dry run passed. No model was called.");
}

async function realRun(o) {
  if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: pnpm build`);
  const dirs = o.mode === "variants" ? [o.variantsDir] : o.fixturesDirs;
  const fixtures = dirs.flatMap((d) => loadFixtures(o.fixtures, d));
  const plan = [];
  for (let rep = 0; rep < o.repeat; rep++) for (const fx of fixtures) for (const arm of o.arms) plan.push({ fx, arm, rep });
  if (plan.length > o.maxRuns) throw new Error(`${plan.length} runs planned, over --max-runs ${o.maxRuns}`);
  console.log(`${plan.length} runs, model ${o.model}, per-run budget $${o.budget}, cap ${o.maxMinutes} minutes`);
  const deadline = Date.now() + o.maxMinutes * 60000;
  const runs = []; let stoppedEarly = null; let cursor = 0;
  const worker = async () => {
    while (cursor < plan.length && !stoppedEarly) {
      if (Date.now() > deadline) { stoppedEarly = `time cap of ${o.maxMinutes} minutes`; break; }
      const { fx, arm, rep } = plan[cursor++];
      const r = await (o.mode === "scan" ? scanRun(fx, arm, rep, o) : variantsRun(fx, arm, rep, o));
      runs.push(r);
      console.log(`${fx.name} / ${arm} / #${r.repeat}: ${r.status}, ${r.score.found}/${r.score.planted} found, ${r.score.falsePositives} FP, ${r.turns ?? "?"} turns, ${r.tokens ?? "?"} tokens, ${r.seconds.toFixed(0)}s, index calls ${r.indexToolCalls ?? 0}`);
      if (r.rateLimited) { stoppedEarly = `rate limit seen on ${fx.name}/${arm}/#${r.repeat}`; console.log(`STOP: ${stoppedEarly}`); }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, o.concurrency) }, worker));
  return { runs, stoppedEarly };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  try {
    if (o.dryRun) await dryRun(o);
    else {
      const { runs, stoppedEarly } = await realRun(o);
      const rows = summarize(runs);
      const meta = { mode: o.mode, date: new Date().toISOString(), requestedModel: o.model, providers: [...new Set(runs.flatMap((r) => r.provider ?? []))], models: [...new Set(runs.flatMap((r) => r.model ?? []))], runs: runs.length, stoppedEarly, repeat: o.repeat, arms: o.arms, budgetPerRun: o.budget, label: o.label };
      mkdirSync(o.out, { recursive: true });
      const stamp = `${o.mode}${o.label ? `-${o.label}` : ""}-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      writeFileSync(join(o.out, `${stamp}.json`), `${JSON.stringify({ meta, rows, runs }, null, 2)}\n`);
      writeFileSync(join(o.out, `${stamp}.md`), renderMarkdown(rows, meta));
      console.log(`\n${renderMarkdown(rows, meta)}wrote ${join(o.out, stamp)}.{md,json}`);
      if (stoppedEarly) process.exit(3);
    }
  } catch (e) { console.error(e.message); process.exit(1); }
}
