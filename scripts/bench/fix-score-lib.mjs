// Pure scoring and summary logic for the fix-quality scorecard. No I/O: see fix-score.mjs for the runner.
import { mean, spread } from "./match.mjs";
import { pct, range, usd } from "./lib.mjs";

/** `git diff --numstat` output to rows. Binary files show "-" and count as zero lines. */
export function parseNumstat(text) {
  return text.split("\n").filter(Boolean).map((line) => {
    const [added, removed, ...rest] = line.split("\t");
    return { file: rest.join("\t"), added: Number(added) || 0, removed: Number(removed) || 0 };
  });
}

const isTestFile = (file) => /(^|\/)(test|tests|__tests__)\//.test(file) || /\.(test|spec)\.[cm]?[jt]s$/.test(file);

/**
 * Score one fix attempt.
 * input: { answer, committed, testsPass, exploitCode, numstat, costUsd, seconds, status }
 * exploitCode 0 means the exploit check says the vulnerability is blocked; anything else means it is not (1: still
 * exploitable, 2: the function no longer works). A change that was not committed cannot be blocked.
 */
export function scoreCase({ answer, committed, testsPass, exploitCode, numstat = [], costUsd = null, seconds = 0, status = "complete" }) {
  const files = numstat.map((r) => r.file);
  const expected = new Set(answer.expectedFiles ?? []);
  // Tests the fix adds or edits are reported on their own and do not count as unexpected.
  const unexpectedFiles = files.filter((f) => !expected.has(f) && !isTestFile(f));
  const exploitBlocked = committed && exploitCode === 0;
  const tests = committed && testsPass === true;
  return {
    case: answer.id, committed, testsPass: tests, exploitBlocked,
    fixed: committed && tests && exploitBlocked,
    exploitExit: committed ? exploitCode ?? null : null,
    files: files.length, linesAdded: numstat.reduce((a, r) => a + r.added, 0), linesRemoved: numstat.reduce((a, r) => a + r.removed, 0),
    onlyExpectedFiles: committed && unexpectedFiles.length === 0, unexpectedFiles,
    testFilesChanged: files.filter(isTestFile),
    costUsd, seconds, status,
  };
}

const share = (runs, pick) => (runs.length ? runs.filter(pick).length / runs.length : null);

/** One row per case with rates and min/max over the repeats. */
export function summarizeCases(runs) {
  const byCase = new Map();
  for (const r of runs) { if (!byCase.has(r.case)) byCase.set(r.case, []); byCase.get(r.case).push(r); }
  return [...byCase.entries()].map(([name, rs]) => {
    const costs = rs.map((r) => r.costUsd).filter((x) => x !== null && x !== undefined);
    const lines = rs.filter((r) => r.committed).map((r) => r.linesAdded + r.linesRemoved);
    return {
      case: name, repeats: rs.length,
      fixed: rs.filter((r) => r.fixed).length,
      committed: rs.filter((r) => r.committed).length,
      testsPass: rs.filter((r) => r.testsPass).length,
      exploitBlocked: rs.filter((r) => r.exploitBlocked).length,
      onlyExpected: rs.filter((r) => r.onlyExpectedFiles).length,
      testsTouched: rs.filter((r) => r.testFilesChanged.length > 0).length,
      filesSpread: spread(rs.filter((r) => r.committed).map((r) => r.files)),
      linesMean: mean(lines), linesSpread: spread(lines),
      costMean: mean(costs), costSpread: spread(costs), costTotal: costs.reduce((a, b) => a + b, 0),
      secondsMean: mean(rs.map((r) => r.seconds)), secondsSpread: spread(rs.map((r) => r.seconds)),
      failed: rs.filter((r) => r.status !== "complete").map((r) => r.status),
    };
  });
}

/**
 * Aggregate over everything. The fix rate is fixed attempts / attempts. Min and max are over the repeats: each repeat
 * has its own rate over the cases, and the range is across those rates.
 */
export function aggregate(runs, repeats) {
  const perRepeat = [];
  for (let i = 1; i <= repeats; i++) {
    const rs = runs.filter((r) => r.repeat === i);
    if (rs.length) perRepeat.push(share(rs, (r) => r.fixed));
  }
  const costs = runs.map((r) => r.costUsd).filter((x) => x !== null && x !== undefined);
  const fixedCosts = runs.filter((r) => r.fixed).map((r) => r.costUsd).filter((x) => x !== null && x !== undefined);
  return {
    attempts: runs.length,
    fixRate: share(runs, (r) => r.fixed), fixRateSpread: spread(perRepeat),
    committedRate: share(runs, (r) => r.committed),
    testsPassRate: share(runs, (r) => r.testsPass),
    exploitBlockedRate: share(runs, (r) => r.exploitBlocked),
    onlyExpectedRate: share(runs.filter((r) => r.committed), (r) => r.onlyExpectedFiles),
    costTotal: costs.reduce((a, b) => a + b, 0),
    costPerFix: fixedCosts.length ? costs.reduce((a, b) => a + b, 0) / fixedCosts.length : null,
    secondsMean: mean(runs.map((r) => r.seconds)),
  };
}

export function renderFixMarkdown(rows, total, meta) {
  const lines = [
    `# Fix-quality scorecard${meta.synthetic ? " (dry run, no model)" : ""}`,
    "",
    `- Date: ${meta.date}`,
    `- Model: ${meta.model}`,
    `- Repeats: ${meta.repeat}`,
    `- Per-fix budget: $${meta.budget}`,
    `- Total cost: ${usd(total.costTotal)}`,
    `- Cases: ${rows.length}`,
    "",
    `Fix rate: ${pct(total.fixRate)} of ${total.attempts} attempts (range over repeats ${range(total.fixRateSpread, pct)}). A fix counts when 0 committed a change, the project's own tests still pass and the hidden exploit check no longer succeeds.`,
    "",
    `Committed ${pct(total.committedRate)}, tests pass ${pct(total.testsPassRate)}, exploit blocked ${pct(total.exploitBlockedRate)}, only the expected files touched ${pct(total.onlyExpectedRate)} of committed changes. Cost per fixed case ${usd(total.costPerFix)}.`,
    "",
    "Cells for fixed, committed, tests, exploit and expected files count attempts over the repeats. Lines are added plus removed; cost and time show the mean with min-max over the repeats.",
    "",
    "| case | fixed | committed | tests pass | exploit blocked | expected files only | files | lines | cost | time (s) | not complete |",
    "|---|---|---|---|---|---|---|---|---|---|---|",
  ];
  for (const r of rows) {
    lines.push(`| ${r.case} | ${r.fixed}/${r.repeats} | ${r.committed}/${r.repeats} | ${r.testsPass}/${r.repeats} | ${r.exploitBlocked}/${r.repeats} | ${r.onlyExpected}/${r.repeats} | ${range(r.filesSpread, String)} | ${r.linesMean === null ? "n/a" : r.linesMean.toFixed(0)} (${range(r.linesSpread, String)}) | ${usd(r.costMean)} (${range(r.costSpread, usd)}) | ${r.secondsMean.toFixed(0)} (${range(r.secondsSpread, (x) => x.toFixed(0))}) | ${r.failed.length ? r.failed.join("; ") : "-"} |`);
  }
  const touched = rows.filter((r) => r.testsTouched > 0).map((r) => r.case);
  if (touched.length) lines.push("", `Test files were added or edited in: ${touched.join(", ")}. They are not counted as unexpected files, and scoring runs the original test files.`);
  lines.push("", "What this does not show: see docs/design/benchmark.md. Small single-bug repositories and few repeats; differences smaller than the range are noise.", "");
  return lines.join("\n");
}
