import assert from "node:assert/strict";
import test from "node:test";
import { aggregate, parseNumstat, renderFixMarkdown, rescanVerdict, scoreCase, summarizeCases } from "./fix-score-lib.mjs";
import { parseArgs } from "./fix-score.mjs";

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
