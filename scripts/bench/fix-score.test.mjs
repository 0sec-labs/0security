import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { aggregate, parseNumstat, patternRescan, renderFixMarkdown, renderReferenceMarkdown, rescanVerdict, scoreCase, summarizeCases } from "./fix-score-lib.mjs";
import { parseArgs, runCasesWithBudget } from "./fix-score.mjs";

const answer = { id: "sqli", expectedFiles: ["src/users.js"] };
const numstat = parseNumstat("3\t1\tsrc/users.js\n10\t0\ttest/users.test.js\n-\t-\tlogo.png\n");

test("parseNumstat reads added and removed lines and treats binary files as zero", () => {
  assert.deepEqual(numstat, [
    { file: "src/users.js", added: 3, removed: 1 },
    { file: "test/users.test.js", added: 10, removed: 0 },
    { file: "logo.png", added: 0, removed: 0 },
  ]);
});

test("a fix needs a commit, passing tests and a blocked exploit", () => {
  const good = scoreCase({ answer, committed: true, testsPass: true, exploitCode: 0, numstat: numstat.slice(0, 1), costUsd: 0.02, seconds: 30 });
  assert.equal(good.fixed, true);
  assert.equal(good.onlyExpectedFiles, true);
  assert.equal(good.linesAdded, 3);
  assert.equal(scoreCase({ answer, committed: true, testsPass: false, exploitCode: 0, numstat }).fixed, false);
  assert.equal(scoreCase({ answer, committed: true, testsPass: true, exploitCode: 1, numstat }).fixed, false);
  // Exit 2 means the function broke: not blocked.
  assert.equal(scoreCase({ answer, committed: true, testsPass: true, exploitCode: 2, numstat }).exploitBlocked, false);
});

test("an uncommitted change can never count as blocked", () => {
  const none = scoreCase({ answer, committed: false, testsPass: true, exploitCode: 0 });
  assert.equal(none.fixed, false);
  assert.equal(none.exploitBlocked, false);
  assert.equal(none.testsPass, false);
});

test("added tests are reported but are not unexpected files", () => {
  const s = scoreCase({ answer, committed: true, testsPass: true, exploitCode: 0, numstat: numstat.slice(0, 2) });
  assert.deepEqual(s.testFilesChanged, ["test/users.test.js"]);
  assert.equal(s.onlyExpectedFiles, true);
  const stray = scoreCase({ answer, committed: true, testsPass: true, exploitCode: 0, numstat });
  assert.deepEqual(stray.unexpectedFiles, ["logo.png"]);
  assert.equal(stray.onlyExpectedFiles, false);
});

const run = (repeat, name, fixed, cost) => ({ ...scoreCase({ answer: { id: name, expectedFiles: [] }, committed: fixed, testsPass: fixed, exploitCode: fixed ? 0 : 1, costUsd: cost, seconds: 10 }), repeat });

test("aggregate reports the fix rate with min and max over the repeats", () => {
  const runs = [run(1, "a", true, 0.02), run(1, "b", true, 0.04), run(2, "a", true, 0.02), run(2, "b", false, 0.06)];
  const total = aggregate(runs, 2);
  assert.equal(total.fixRate, 0.75);
  assert.deepEqual(total.fixRateSpread, [0.5, 1]);
  assert.ok(Math.abs(total.costTotal - 0.14) < 1e-9);
  // Cost per fixed case counts what the failed attempts cost too.
  assert.ok(Math.abs(total.costPerFix - 0.14 / 3) < 1e-9);
});

test("summarizeCases groups by case", () => {
  const rows = summarizeCases([run(1, "a", true, 0.02), run(2, "a", false, 0.04), run(1, "b", true, 0.01)]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].case, "a");
  assert.equal(rows[0].fixed, 1);
  assert.equal(rows[0].repeats, 2);
  assert.deepEqual(rows[0].costSpread, [0.02, 0.04]);
});

test("the markdown states the fix rate and labels the run", () => {
  const runs = [run(1, "a", true, 0.02), run(2, "a", false, 0.04)];
  const text = renderFixMarkdown(summarizeCases(runs), aggregate(runs, 2), { date: "2026-01-01", model: "m", repeat: 2, budget: 0.5 });
  assert.match(text, /Fix rate: 50% of 2 attempts \(range over repeats 0%-100%\)/);
  assert.match(text, /- Model: m/);
  assert.match(text, /\| a \| 1\/2 \|/);
});

test("parseArgs requires exactly one of --run and --dry-run", () => {
  assert.throws(() => parseArgs([]));
  assert.throws(() => parseArgs(["--run", "--dry-run"]));
  const o = parseArgs(["--run", "--repeat", "2", "--budget", "0.3", "--total-budget", "4", "--cases", "sqli,unsafe-eval"]);
  assert.equal(o.repeat, 2);
  assert.equal(o.totalBudget, 4);
  assert.deepEqual(o.cases, ["sqli", "unsafe-eval"]);
  assert.throws(() => parseArgs(["--run", "--repeat", "0"]));
  assert.throws(() => parseArgs(["--run", "--bogus"]));
});

test("a fix that does not compile or that a rescan still flags is not fixed", () => {
  const base = { answer, committed: true, testsPass: true, exploitCode: 0, numstat: numstat.slice(0, 1) };
  assert.equal(scoreCase({ ...base, compiles: true, rescan: "clean" }).fixed, true);
  assert.equal(scoreCase({ ...base, compiles: false }).fixed, false);
  assert.equal(scoreCase({ ...base, compiles: true, rescan: "still-flagged" }).fixed, false);
  // No build step (null) and a scanner that never flagged the original (not-applicable) do not block a fix.
  assert.equal(scoreCase({ ...base }).fixed, true);
  assert.equal(scoreCase({ ...base, compiles: false, committed: false }).compiles, null);
});

test("rescanVerdict compares the same rule in the same file before and after", () => {
  const before = [{ rule: "java/no-xxe", file: "src/A.java" }, { rule: "java/other", file: "src/B.java" }];
  assert.deepEqual(rescanVerdict(before, [], ["src/A.java"]), { rescan: "clean", rescanNew: 0 });
  assert.equal(rescanVerdict(before, [before[0]], ["src/A.java"]).rescan, "still-flagged");
  // A finding elsewhere does not count against the fix.
  assert.equal(rescanVerdict(before, [before[1]], ["src/A.java"]).rescan, "clean");
  // The scanner was silent on the original: a clean rescan proves nothing.
  assert.equal(rescanVerdict([], [], ["src/A.java"]).rescan, "not-applicable");
  // A new rule firing after the fix is counted, not failed.
  assert.equal(rescanVerdict(before, [{ rule: "java/no-path-traversal", file: "src/A.java" }], ["src/A.java"]).rescanNew, 1);
});

test("the markdown shows compile and rescan columns", () => {
  const runs = [{ ...run(1, "a", true, 0.02), compiles: true, rescan: "clean" }, { ...run(2, "a", true, 0.02), compiles: true, rescan: "not-applicable" }];
  const text = renderFixMarkdown(summarizeCases(runs), aggregate(runs, 2), { date: "2026-01-01", model: "m", repeat: 2, budget: 0.5 });
  assert.match(text, /\| compiles \|/);
  assert.match(text, /\| a \| 2\/2 \| 2\/2 \| 2\/2 \|/);
  assert.match(text, /compiles 100%/);
  assert.match(text, /rescan clean 100%/);
});

const options = extra => ({ repeat: 1, budget: 0.5, ...extra });
const cases = ["a", "b", "c", "d"].map(name => ({ name }));

test("the total-budget gate clamps the final new fix to remaining receipts and starts no extra case", () => {
  const allowances = [];
  const { runs, accounting } = runCasesWithBudget(cases, options({ totalBudget: 0.8 }), (c, rep, o) => {
    allowances.push(o.budget);
    return run(rep + 1, c.name, true, o.budget);
  }, () => {});
  assert.equal(runs.length, 2);
  assert.equal(allowances[0], 0.5);
  assert.ok(Math.abs(allowances[1] - 0.3) < 1e-12);
  assert.equal(accounting.stoppedReason, "total-budget-reached");
  assert.equal(accounting.remainingBudgetUsd, 0);
  assert.equal(accounting.costComplete, true);
});

test("the gate accounts for actual returned spend and stops after an in-flight overshoot", () => {
  const allowances = [], messages = [];
  const result = runCasesWithBudget(cases, options({ totalBudget: 1 }), (c, rep, o) => {
    allowances.push(o.budget);
    return run(rep + 1, c.name, true, allowances.length === 1 ? 0.8 : 0.25);
  }, text => messages.push(text));
  assert.equal(allowances.length, 2);
  assert.ok(Math.abs(allowances[1] - 0.2) < 1e-12);
  assert.equal(result.accounting.knownCostUsd, 1.05);
  assert.equal(result.accounting.remainingBudgetUsd, 0);
  assert.match(result.accounting.gate, /in-flight requests can overshoot/);
});

test("a missing or invalid receipt stops total-budget runs without becoming zero spend", () => {
  for (const missing of [undefined, null, Number.NaN, Number.POSITIVE_INFINITY, -0.1, "0.1"]) {
    let called = 0;
    const result = runCasesWithBudget(cases, options({ totalBudget: 1 }), (c, rep) => {
      called++;
      return run(rep + 1, c.name, false, missing);
    }, () => {});
    assert.equal(called, 1);
    assert.equal(result.runs[0].costUsd, null);
    assert.equal(result.accounting.costComplete, false);
    assert.equal(result.accounting.remainingBudgetUsd, null);
    assert.equal(result.accounting.stoppedReason, "cost-unavailable");
  }
});

test("without a total gate unknown receipts do not alter attempt scheduling or masquerade as a total", () => {
  const allowances = [];
  const result = runCasesWithBudget(cases.slice(0, 2), options({ repeat: 2 }), (c, rep, o) => {
    allowances.push(o.budget);
    return run(rep + 1, c.name, true, allowances.length === 1 ? null : 0.1);
  }, () => {});
  assert.deepEqual(allowances, [0.5, 0.5, 0.5, 0.5]);
  assert.equal(result.accounting.stoppedReason, null);
  const total = aggregate(result.runs, 2);
  assert.equal(total.costComplete, false);
  assert.equal(total.costTotal, null);
  assert.equal(total.costPerFix, null);
  assert.ok(Math.abs(total.knownCostUsd - 0.3) < 1e-12);
  const row = summarizeCases(result.runs).find(row => row.case === "a");
  assert.equal(row.costMean, null);
  assert.equal(row.costTotal, null);
  const md = renderFixMarkdown(summarizeCases(result.runs), total, { date: "test", model: "m", repeat: 2, budget: 0.5 });
  assert.match(md, /Total cost: n\/a/);
});

test("budget, total budget, timeout and repeats reject nonfinite or nonpositive parameters", () => {
  for (const flag of ["--budget", "--total-budget", "--timeout", "--repeat"]) {
    for (const value of ["Infinity", "NaN", "0", "-1"]) assert.throws(() => parseArgs(["--run", flag, value]), /positive/);
  }
});


test("the actual harness forwards a clamped budget to child CLI processes and writes honest accounting", t => {
  const dir = mkdtempSync(join(tmpdir(), "0-fixscore-budget-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const cli = join(dir, "cli.mjs"), log = join(dir, "budgets.jsonl"), out = join(dir, "out");
  writeFileSync(cli, `import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
if (args[1] === "list") console.log(JSON.stringify({ findings: [{ id: "fixture-finding" }] }));
else if (args[1] === "fix") { if (!args.includes("--no-variants")) throw new Error("benchmark must disable variant threads"); const budget = Number(args[args.indexOf("--budget") + 1]); appendFileSync(${JSON.stringify(log)}, JSON.stringify(budget) + "\\n"); console.log(JSON.stringify({ committed: false, costUsd: budget })); }
else console.log("{}");
`);
  const env = Object.fromEntries(["PATH", "HOME", "TMPDIR", "LANG"].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  env.DO_NOT_TRACK = "1"; env.GIT_CONFIG_GLOBAL = "/dev/null"; env.GIT_CONFIG_SYSTEM = "/dev/null";
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./fix-score.mjs", import.meta.url)), "--run", "--cases", "sqli,unsafe-eval,prototype-pollution", "--budget", "0.5", "--total-budget", "0.8", "--cli", cli, "--out", out], { env, encoding: "utf8", timeout: 120_000 });
  assert.equal(result.status, 0, result.stderr);
  const budgets = readFileSync(log, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(budgets.length, 2);
  assert.equal(budgets[0], 0.5);
  assert.ok(Math.abs(budgets[1] - 0.3) < 1e-12);
  const report = JSON.parse(readFileSync(join(out, readdirSync(out).find(name => name.endsWith(".json"))), "utf8"));
  assert.equal(report.accounting.costComplete, true);
  assert.equal(report.accounting.stoppedReason, "total-budget-reached");
  assert.equal(report.total.costTotal, 0.8);
  assert.match(result.stdout, /not a hard provider billing limit/);
  assert.doesNotMatch(result.stdout, /worst.case/i);
});

test("patternRescan flags a file that still holds the vulnerable construct", () => {
  const forbid = [{ file: "src/proxy.js", pattern: "startsWith\\(\"https://\" \\+ ALLOWED_HOST\\)" }];
  const vulnerable = 'return raw.startsWith("https://" + ALLOWED_HOST);';
  assert.equal(patternRescan(forbid, () => vulnerable), "still-flagged");
  assert.equal(patternRescan(forbid, () => "return url.hostname === ALLOWED_HOST;"), "clean");
  assert.equal(patternRescan(forbid, () => null), "clean");
  assert.equal(patternRescan(undefined, () => vulnerable), "not-applicable");
  assert.equal(patternRescan([], () => vulnerable), "not-applicable");
});

test("renderReferenceMarkdown says no model ran and lists every case", () => {
  const ok = { case: "a", language: "java", category: "xxe", testsBefore: true, testsAfter: true, compilesBefore: true, compilesAfter: true, exploitBefore: 1, exploitAfter: 0, rescan: "foxguard clean", problems: [] };
  const bad = { ...ok, case: "b", language: "javascript", compilesBefore: null, compilesAfter: null, exploitAfter: 1, rescan: "n/a", problems: ["x"] };
  const md = renderReferenceMarkdown([ok, bad], { date: "2026-01-01" });
  assert.match(md, /Model: none/);
  assert.match(md, /\| a \| java \| xxe \| yes \| yes \| yes \| yes \| works \| blocked \| foxguard clean \| yes \|/);
  assert.match(md, /\| b \| javascript \| .* \| n\/a \| n\/a \| works \| works \| n\/a \| no \|/);
});

test("--reference-table belongs to the dry run", () => {
  assert.throws(() => parseArgs(["--run", "--reference-table", "/tmp/x.md"]), /dry-run/);
  assert.ok(parseArgs(["--dry-run", "--reference-table", "/tmp/x.md"]).referenceTable);
});
