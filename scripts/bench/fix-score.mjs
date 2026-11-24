#!/usr/bin/env node
// Fix-quality scorecard: does `0 findings fix` remove a planted vulnerability without breaking the project?
//   node scripts/bench/fix-score.mjs --dry-run                       validate every case, no model, no cost
//   node scripts/bench/fix-score.mjs --run [--repeat 2] [--budget 0.5] [--total-budget 4] [--cases a,b] [--model id]
//
// Each case under fix-cases/<name>/ has: repo/ (a tiny project with its own tests), finding.sarif (the imported
// finding), answer.json (what a correct fix must do), exploit.mjs (hidden check: exit 0 means the vulnerability is
// blocked) and solution/ (a reference fix, used only by --dry-run to prove the checks can pass).
// A run copies repo/ to a fresh git repository and a fresh HOME, imports the finding, runs the fix with --no-pr, then
// scores the committed branch with the original tests and the exploit check. The model never sees the exploit,
// the answer or the solution: they stay outside the copy.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { aggregate, parseNumstat, renderFixMarkdown, rescanVerdict, scoreCase, summarizeCases } from "./fix-score-lib.mjs";
import { benchDir, defaultCli, git, isMain, isolatedEnv, run, usd } from "./lib.mjs";

const CASES = join(benchDir, "fix-cases");

export function parseArgs(argv) {
  const o = { run: false, dryRun: false, repeat: 1, budget: 0.5, totalBudget: undefined, cases: undefined, model: undefined, out: join(benchDir, "results"), cli: defaultCli, timeout: 900 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--run") o.run = true;
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--repeat") o.repeat = Number(next());
    else if (a === "--budget") o.budget = Number(next());
    else if (a === "--total-budget") o.totalBudget = Number(next());
    else if (a === "--cases") o.cases = next().split(",");
    else if (a === "--model") o.model = next();
    else if (a === "--out") o.out = resolve(next());
    else if (a === "--cli") o.cli = resolve(next());
    else if (a === "--timeout") o.timeout = Number(next());
    else throw new Error(`unknown option ${a}`);
  }
  if (o.run === o.dryRun) throw new Error("pass exactly one of --run (spends model money) or --dry-run (free)");
  if (!Number.isInteger(o.repeat) || o.repeat < 1) throw new Error("--repeat must be a positive integer");
  if (!(o.budget > 0)) throw new Error("--budget must be a positive number of USD");
  if (o.totalBudget !== undefined && !(o.totalBudget > 0)) throw new Error("--total-budget must be a positive number of USD");
  return o;
}

export function loadCases(only) {
  const names = readdirSync(CASES, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  for (const n of only ?? []) if (!names.includes(n)) throw new Error(`unknown case ${n} (known: ${names.join(", ")})`);
  return (only ?? names).map((name) => {
    const dir = join(CASES, name);
    return { name, dir, answer: JSON.parse(readFileSync(join(dir, "answer.json"), "utf8")) };
  });
}

const isJava = (c) => c.answer.language === "java";

/** The project's own test files and folders, relative to the repo: restored from the base commit before scoring. */
function testFiles(repo, c) {
  if (isJava(c)) return ["run-tests.sh", "test"];
  const dir = join(repo, "test");
  return existsSync(dir) ? readdirSync(dir).filter((f) => /\.test\.[cm]?js$/.test(f)).sort().map((f) => `test/${f}`) : [];
}

/** A fresh git repository holding a copy of the case's project on branch main. */
function makeRepo(c, root) {
  const repo = join(root, "repo");
  cpSync(join(c.dir, "repo"), repo, { recursive: true });
  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "base"]);
  return repo;
}

/** The shell-free command the project's checks run: Node cases use node --test, Java cases use their run-tests.sh. */
const testCommand = (repo, c) => (isJava(c) ? { command: "sh", args: ["run-tests.sh"] } : { command: process.execPath, args: ["--test", ...testFiles(repo, c)] });
/** The same check as one string, for the --test option of the fix command. */
const testCommandLine = (repo, c) => (isJava(c) ? "sh run-tests.sh" : `node --test ${testFiles(repo, c).join(" ")}`);
const runTests = (repo, c) => { const t = testCommand(repo, c); return run(t.command, t.args, { cwd: repo, timeoutSeconds: 300 }); };

/** Java sources under a folder, as paths. */
function javaSources(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? javaSources(join(dir, e.name)) : e.name.endsWith(".java") ? [join(dir, e.name)] : []));
}

/** Compile the project's production sources. Node projects have no build step: null. */
function compile(repo, c) {
  if (!isJava(c)) return null;
  const out = mkdtempSync(join(tmpdir(), "0-fixcase-out-"));
  const sources = javaSources(join(repo, "src"));
  return sources.length > 0 && run("javac", ["-d", out, ...sources], { cwd: repo, timeoutSeconds: 120 }).status === 0;
}

/** The hidden check. Node cases ship exploit.mjs; Java cases ship pov/*.java, compiled against the project's sources and run as Pov. */
function runExploit(c, repo) {
  if (!isJava(c)) return run(process.execPath, [join(c.dir, "exploit.mjs"), repo], { cwd: tmpdir(), timeoutSeconds: 120 });
  const out = mkdtempSync(join(tmpdir(), "0-fixcase-pov-"));
  const built = run("javac", ["-d", out, ...javaSources(join(repo, "src")), ...javaSources(join(c.dir, "pov"))], { cwd: tmpdir(), timeoutSeconds: 120 });
  if (built.status !== 0) return { ...built, status: 2 }; // the project no longer compiles: the function does not work
  return run("java", ["-cp", out, "Pov"], { cwd: tmpdir(), timeoutSeconds: 120 });
}

function findFoxguard() {
  return [process.env.ZERO_FOXGUARD_PATH, join(homedir(), ".0", "bin", "foxguard")].filter(Boolean).find((x) => existsSync(x)) ?? "foxguard";
}

/** The free scanner's findings for a repo as { rule, file } with repo-relative paths, or null when it cannot run. */
function scanRules(repo) {
  const p = run(findFoxguard(), ["--format", "json", "."], { cwd: repo, timeoutSeconds: 120 });
  try { return JSON.parse(p.stdout).findings.map((f) => ({ rule: f.rule_id, file: String(f.file).replace(/^\.\//, "") })); } catch { return null; }
}

/** Static check of one case: the finding points at real lines, the tests pass, the exploit works before and is blocked by the reference fix. */
export function validateCase(c) {
  const problems = [];
  for (const f of ["answer.json", "finding.sarif", ...(isJava(c) ? ["pov/Pov.java", "repo/run-tests.sh"] : ["exploit.mjs", "repo/package.json"])]) if (!existsSync(join(c.dir, f))) problems.push(`missing ${f}`);
  if (problems.length) return problems;
  if (c.answer.id !== c.name) problems.push(`answer.id ${c.answer.id} does not match the folder`);
  if (!Array.isArray(c.answer.expectedFiles) || !c.answer.expectedFiles.length || !c.answer.note) problems.push("answer needs expectedFiles and note");
  let location;
  try { location = JSON.parse(readFileSync(join(c.dir, "finding.sarif"), "utf8")).runs[0].results[0].locations[0].physicalLocation; } catch { problems.push("finding.sarif has no result with a location"); }
  if (location) {
    const file = join(c.dir, "repo", location.artifactLocation.uri);
    if (!existsSync(file)) problems.push(`finding points at missing file ${location.artifactLocation.uri}`);
    else if (location.region.endLine > readFileSync(file, "utf8").split("\n").length) problems.push("finding line is past the end of its file");
  }
  const root = mkdtempSync(join(tmpdir(), "0-fixcase-"));
  const repo = makeRepo(c, root);
  if (!testFiles(repo, c).length) problems.push("the project has no test files");
  if (compile(repo, c) === false) problems.push("the vulnerable project does not compile");
  const rulesBefore = scanRules(repo);
  const before = runTests(repo, c);
  if (before.status !== 0) problems.push(`the tests fail on the vulnerable code:\n${(before.stdout + before.stderr).slice(-400)}`);
  const exploit = runExploit(c, repo);
  if (exploit.status !== 1) problems.push(`the exploit check should exit 1 on the vulnerable code, got ${exploit.status}: ${(exploit.stderr || exploit.stdout).trim().slice(-200)}`);
  // The reference fix must pass both, and change only the expected files.
  const solution = join(c.dir, "solution");
  if (!existsSync(solution)) { problems.push("missing solution/"); return problems; }
  cpSync(solution, repo, { recursive: true });
  const after = runTests(repo, c);
  if (compile(repo, c) === false) problems.push("the project does not compile with the reference fix");
  const rulesAfter = scanRules(repo);
  if (rulesBefore && rulesAfter && rescanVerdict(rulesBefore, rulesAfter, c.answer.expectedFiles).rescan === "still-flagged") problems.push("the rescan still flags the finding with the reference fix");
  if (after.status !== 0) problems.push(`the tests fail with the reference fix:\n${(after.stdout + after.stderr).slice(-400)}`);
  const blocked = runExploit(c, repo);
  if (blocked.status !== 0) problems.push(`the exploit check should exit 0 with the reference fix, got ${blocked.status}: ${(blocked.stderr || blocked.stdout).trim().slice(-200)}`);
  const changed = git(repo, ["status", "--porcelain"]).stdout.split("\n").filter(Boolean).map((l) => l.slice(3));
  const stray = changed.filter((f) => !c.answer.expectedFiles.includes(f));
  if (stray.length) problems.push(`the reference fix touches files that are not expected: ${stray.join(", ")}`);
  return problems;
}

function dryRun(o) {
  const cases = loadCases(o.cases);
  let bad = 0;
  for (const c of cases) {
    const problems = validateCase(c);
    console.log(`${problems.length ? "FAIL" : "ok  "} ${c.name} (${c.answer.language}): ${c.answer.category}, expects ${c.answer.expectedFiles.join(", ")}`);
    for (const p of problems) console.log(`     ${p}`);
    bad += problems.length;
  }
  console.log(`\n${cases.length} cases x ${o.repeat} repeat(s) = ${cases.length * o.repeat} fixes; worst-case cost $${(cases.length * o.repeat * o.budget).toFixed(2)} at --budget ${o.budget}`);
  if (bad) { console.error(`\n${bad} problem(s)`); process.exit(1); }
  console.log("\ndry run passed: every case fails its exploit check before the fix and passes it with the reference fix. No model was called.");
}

function fixOne(c, repeatIndex, o) {
  const root = mkdtempSync(join(tmpdir(), "0-fixscore-"));
  const repo = makeRepo(c, root);
  const env = isolatedEnv(join(root, "home"));
  const cli = (args, timeoutSeconds) => run(process.execPath, [o.cli, ...args], { cwd: root, env, timeoutSeconds });
  const base = { case: c.name, repeat: repeatIndex + 1, workdir: root };
  const fail = (status, error) => ({ ...base, ...scoreCase({ answer: c.answer, committed: false, testsPass: false, exploitCode: null, status }), error });

  const imported = cli(["findings", "import", join(c.dir, "finding.sarif"), "--root", repo, "--format", "json"], 120);
  if (imported.status !== 0) return fail("import-failed", (imported.stderr || imported.stdout).slice(-300));
  let id;
  try { id = JSON.parse(cli(["findings", "list", "--format", "json"], 60).stdout).findings[0].id; } catch { return fail("no-finding-id"); }

  const tests = testFiles(repo, c);
  const rulesBefore = scanRules(repo);
  const args = ["findings", "fix", id, "--repo", repo, "--test", testCommandLine(repo, c), "--no-pr", "--budget", String(o.budget), "--timeout", String(o.timeout), "--format", "json"];
  if (o.model) args.push("--model", o.model);
  const started = Date.now();
  const proc = cli(args, o.timeout + 180);
  const seconds = (Date.now() - started) / 1000;
  let outcome;
  try { outcome = JSON.parse(proc.stdout); } catch { /* no JSON: the fix failed before reporting */ }
  const costUsd = outcome?.costUsd ?? null;
  const status = outcome ? (outcome.timedOut ? "timed-out" : outcome.budgetExhausted ? "budget-exhausted" : "complete") : `no-outcome (exit ${proc.status})`;
  if (!outcome?.committed) return { ...base, ...scoreCase({ answer: c.answer, committed: false, testsPass: false, exploitCode: null, costUsd, seconds, status }), error: outcome ? undefined : (proc.stderr || proc.stdout).slice(-300) };

  // Score the committed branch in the copy: original tests, hidden exploit, diff against the base.
  git(repo, ["checkout", "-q", outcome.branch]);
  const numstat = parseNumstat(git(repo, ["diff", "--numstat", "main", outcome.branch]).stdout);
  git(repo, ["checkout", "-q", "main", "--", ...tests]); // the original tests, whatever the model did to them
  const compiles = compile(repo, c);
  const testsPass = runTests(repo, c).status === 0;
  const exploit = runExploit(c, repo);
  const rulesAfter = scanRules(repo);
  const { rescan, rescanNew } = rulesBefore && rulesAfter ? rescanVerdict(rulesBefore, rulesAfter, c.answer.expectedFiles) : { rescan: "not-applicable", rescanNew: 0 };
  return { ...base, ...scoreCase({ answer: c.answer, committed: true, compiles, testsPass, exploitCode: exploit.status, rescan, rescanNew, numstat, costUsd, seconds, status }), branch: outcome.branch, exploitOutput: (exploit.stderr || exploit.stdout).trim().slice(-200) };
}

function realRun(o) {
  const cases = loadCases(o.cases);
  const problems = cases.flatMap((c) => validateCase(c).map((p) => `${c.name}: ${p}`));
  if (problems.length) throw new Error(`cases are invalid, run --dry-run:\n${problems.join("\n")}`);
  if (!existsSync(o.cli)) throw new Error(`${o.cli} not found: build it with pnpm --filter @0/engine build && pnpm --filter @0/cli build`);
  console.log(`${cases.length} cases x ${o.repeat} repeat(s) = ${cases.length * o.repeat} fixes; worst case $${(cases.length * o.repeat * o.budget).toFixed(2)} at --budget ${o.budget}${o.totalBudget ? `; stops starting new fixes at $${o.totalBudget} total` : ""}`);
  const runs = []; let spent = 0;
  outer: for (let rep = 0; rep < o.repeat; rep++) for (const c of cases) {
    if (o.totalBudget !== undefined && spent >= o.totalBudget) { console.log(`total budget $${o.totalBudget} reached; stopping`); break outer; }
    process.stdout.write(`fix ${c.name} / repeat ${rep + 1} ... `);
    const r = fixOne(c, rep, o);
    spent += r.costUsd ?? 0;
    runs.push(r);
    console.log(`${r.fixed ? "FIXED" : "not fixed"} (${r.status}; committed ${r.committed}, compiles ${r.compiles}, tests ${r.testsPass}, rescan ${r.rescan}, exploit ${r.exploitBlocked}${r.exploitExit ? ` exit ${r.exploitExit}` : ""}), ${r.files} files, ${r.linesAdded + r.linesRemoved} lines, ${usd(r.costUsd)}, ${r.seconds.toFixed(0)}s`);
  }
  return runs;
}

if (isMain(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/fix-score.mjs (--run | --dry-run) [--repeat N] [--budget USD] [--total-budget USD] [--cases a,b] [--model id] [--out dir]`); process.exit(2); }
  try {
    if (o.dryRun) dryRun(o);
    else {
      const runs = realRun(o);
      const rows = summarizeCases(runs);
      const total = aggregate(runs, o.repeat);
      const meta = { date: new Date().toISOString().slice(0, 10), model: o.model ?? "default (gpt-6-luna)", repeat: o.repeat, budget: o.budget };
      mkdirSync(o.out, { recursive: true });
      const stamp = `fix-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      const md = renderFixMarkdown(rows, total, meta);
      writeFileSync(join(o.out, `${stamp}.json`), `${JSON.stringify({ meta, total, rows, runs: runs.map(({ workdir, ...r }) => r) }, null, 2)}\n`);
      writeFileSync(join(o.out, `${stamp}.md`), md);
      console.log(`\n${md}\nwrote ${join(o.out, stamp)}.{md,json}`);
    }
  } catch (e) { console.error(e.message); process.exit(1); }
}
