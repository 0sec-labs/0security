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
 * What a rescan says about one finding. before and after are lists of { rule, file } from the same scanner run on the
 * original and on the fixed code. The finding counts as removed when the rule no longer fires in that file.
 * "not-applicable" means the scanner did not flag the original, so a clean rescan would prove nothing.
 * rescanNew counts rules that fire after the fix in a file where they did not fire before.
 */
export function rescanVerdict(before, after, files) {
  const key = (f) => `${f.rule}\u0000${f.file}`;
  const watched = before.filter((f) => files.includes(f.file));
  const afterKeys = new Set(after.map(key));
  const beforeKeys = new Set(before.map(key));
  const rescan = !watched.length ? "not-applicable" : watched.some((f) => afterKeys.has(key(f))) ? "still-flagged" : "clean";
  return { rescan, rescanNew: [...afterKeys].filter((k) => !beforeKeys.has(k)).length };
}

/**
 * A rescan with fixed patterns, for cases the scanner did not flag. answer.rescanForbid lists { file, pattern } entries:
 * the exact vulnerable construct must be gone from that file. read(file) returns the file's text or null.
 * "not-applicable" when the case lists none. It only checks that one construct is absent, so it cannot see a fix that
 * keeps the flaw in another form; the hidden exploit check does that.
 */
export function patternRescan(forbid, read) {
  if (!Array.isArray(forbid) || !forbid.length) return "not-applicable";
  return forbid.some(({ file, pattern }) => new RegExp(pattern).test(read(file) ?? "")) ? "still-flagged" : "clean";
}

/**
 * Score one fix attempt.
 * input: { answer, committed, compiles, testsPass, exploitCode, rescan, rescanNew, numstat, costUsd, seconds, status }
 * compiles is true or false for a language with a build step and null when there is none (Node cases).
 * rescan is "clean", "still-flagged" or "not-applicable" (see rescanVerdict); only still-flagged fails a fix.
 * exploitCode 0 means the exploit check says the vulnerability is blocked; anything else means it is not (1: still
 * exploitable, 2: the function no longer works). A change that was not committed cannot be blocked.
 */
export function scoreCase({ answer, committed, compiles = null, testsPass, exploitCode, rescan = "not-applicable", rescanNew = 0, numstat = [], costUsd = null, seconds = 0, status = "complete" }) {
  const files = numstat.map((r) => r.file);
  const expected = new Set(answer.expectedFiles ?? []);
  // Tests the fix adds or edits are reported on their own and do not count as unexpected.
  const unexpectedFiles = files.filter((f) => !expected.has(f) && !isTestFile(f));
  const exploitBlocked = committed && exploitCode === 0;
  const tests = committed && testsPass === true;
  return {
    case: answer.id, committed, compiles: committed ? compiles : null, testsPass: tests, exploitBlocked,
    rescan: committed ? rescan : "not-applicable", rescanNew: committed ? rescanNew : 0,
    fixed: committed && compiles !== false && tests && exploitBlocked && rescan !== "still-flagged",
    exploitExit: committed ? exploitCode ?? null : null,
    files: files.length, linesAdded: numstat.reduce((a, r) => a + r.added, 0), linesRemoved: numstat.reduce((a, r) => a + r.removed, 0),
    onlyExpectedFiles: committed && unexpectedFiles.length === 0, unexpectedFiles,
    testFilesChanged: files.filter(isTestFile),
    costUsd, seconds, status,
  };
}

const knownCost = value => typeof value === "number" && Number.isFinite(value) && value >= 0;

const share = (runs, pick) => (runs.length ? runs.filter(pick).length / runs.length : null);

/** One row per case with rates and min/max over the repeats. */
export function summarizeCases(runs) {
  const byCase = new Map();
  for (const r of runs) { if (!byCase.has(r.case)) byCase.set(r.case, []); byCase.get(r.case).push(r); }
  return [...byCase.entries()].map(([name, rs]) => {
    const costs = rs.map((r) => r.costUsd).filter(knownCost);
    const costComplete = costs.length === rs.length;
    const lines = rs.filter((r) => r.committed).map((r) => r.linesAdded + r.linesRemoved);
    return {
      case: name, repeats: rs.length,
      fixed: rs.filter((r) => r.fixed).length,
      committed: rs.filter((r) => r.committed).length,
      compiles: rs.filter((r) => r.compiles === true).length,
      compileApplies: rs.filter((r) => r.compiles !== null).length,
      rescanClean: rs.filter((r) => r.rescan === "clean").length,
      rescanApplies: rs.filter((r) => r.rescan !== "not-applicable").length,
      testsPass: rs.filter((r) => r.testsPass).length,
      exploitBlocked: rs.filter((r) => r.exploitBlocked).length,
      onlyExpected: rs.filter((r) => r.onlyExpectedFiles).length,
      testsTouched: rs.filter((r) => r.testFilesChanged.length > 0).length,
      filesSpread: spread(rs.filter((r) => r.committed).map((r) => r.files)),
      linesMean: mean(lines), linesSpread: spread(lines),
      costMean: costComplete ? mean(costs) : null, costSpread: costComplete ? spread(costs) : null, costTotal: costComplete ? costs.reduce((a, b) => a + b, 0) : null,
      knownCostUsd: costs.reduce((a, b) => a + b, 0), costComplete,
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
  const costs = runs.map((r) => r.costUsd).filter(knownCost);
  const costComplete = costs.length === runs.length;
  const fixed = runs.filter((r) => r.fixed).length;
  return {
    attempts: runs.length,
    fixRate: share(runs, (r) => r.fixed), fixRateSpread: spread(perRepeat),
    committedRate: share(runs, (r) => r.committed),
    compileRate: share(runs.filter((r) => r.compiles !== null), (r) => r.compiles === true),
    rescanCleanRate: share(runs.filter((r) => r.rescan !== "not-applicable"), (r) => r.rescan === "clean"),
    testsPassRate: share(runs, (r) => r.testsPass),
    exploitBlockedRate: share(runs, (r) => r.exploitBlocked),
    onlyExpectedRate: share(runs.filter((r) => r.committed), (r) => r.onlyExpectedFiles),
    costTotal: costComplete ? costs.reduce((a, b) => a + b, 0) : null,
    knownCostUsd: costs.reduce((a, b) => a + b, 0), costComplete,
    costPerFix: costComplete && fixed ? costs.reduce((a, b) => a + b, 0) / fixed : null,
    secondsMean: mean(runs.map((r) => r.seconds)),
  };
}

/**
 * The per-case table of the reference-fix check. No model ran: each row says what the case's own checks do on the
 * vulnerable code and with the hand-written reference fix. facts: { case, language, category, testsBefore, exploitBefore,
 * testsAfter, exploitAfter, compilesBefore, compilesAfter, rescan, problems }.
 */
export function renderReferenceMarkdown(facts, meta) {
  const yes = (v) => (v === null ? "n/a" : v ? "yes" : "no");
  const exploit = (code) => (code === 0 ? "blocked" : code === 1 ? "works" : `exit ${code}`);
  const lines = [
    "# Fix cases: reference-fix check",
    "",
    `- Date: ${meta.date}`,
    "- Model: none. This is not a model result and says nothing about how often `0security findings fix` succeeds.",
    `- Cases: ${facts.length}, of which ${facts.filter((f) => f.language === "java").length} Java`,
    "",
    "Each row runs the case's own checks twice: on the vulnerable project and with the hand-written reference fix. A valid case has green tests both times, an exploit check that works before and is blocked after, and a rescan that no longer flags the finding. The rescan column names the source of that check: FoxGuard where it flagged the original, a fixed pattern for the vulnerable construct where the case lists one, and n/a where neither applies.",
    "",
    "| case | language | category | tests before | tests after | compiles before | compiles after | exploit before | exploit after | rescan | valid |",
    "|---|---|---|---|---|---|---|---|---|---|---|",
  ];
  for (const f of facts) lines.push(`| ${f.case} | ${f.language} | ${f.category} | ${yes(f.testsBefore)} | ${yes(f.testsAfter)} | ${yes(f.compilesBefore)} | ${yes(f.compilesAfter)} | ${exploit(f.exploitBefore)} | ${exploit(f.exploitAfter)} | ${f.rescan} | ${f.problems.length ? "no" : "yes"} |`);
  lines.push("", "Run `node scripts/bench/fix-score.mjs --dry-run --reference-table <file>` to write this table again. Model results per case come from `--run` and are not committed.", "");
  return lines.join("\n");
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
    `Fix rate: ${pct(total.fixRate)} of ${total.attempts} attempts (range over repeats ${range(total.fixRateSpread, pct)}). A fix counts when 0 committed a change, the project compiles (where it has a build), the project's own tests still pass, the hidden exploit check no longer succeeds and a rescan no longer flags the finding (where the scanner flagged the original).`,
    "",
    `Committed ${pct(total.committedRate)}, compiles ${pct(total.compileRate)} (cases with a build), rescan clean ${pct(total.rescanCleanRate)} (cases the scanner flagged), tests pass ${pct(total.testsPassRate)}, exploit blocked ${pct(total.exploitBlockedRate)}, only the expected files touched ${pct(total.onlyExpectedRate)} of committed changes. Cost per fixed case ${usd(total.costPerFix)}.`,
    "",
    "Cells for fixed, committed, tests, exploit and expected files count attempts over the repeats. Lines are added plus removed; cost and time show the mean with min-max over the repeats.",
    "",
    "| case | fixed | committed | compiles | tests pass | exploit blocked | rescan clean | expected files only | files | lines | cost | time (s) | not complete |",
    "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
  ];
  for (const r of rows) {
    lines.push(`| ${r.case} | ${r.fixed}/${r.repeats} | ${r.committed}/${r.repeats} | ${r.compileApplies ? `${r.compiles}/${r.compileApplies}` : "n/a"} | ${r.testsPass}/${r.repeats} | ${r.exploitBlocked}/${r.repeats} | ${r.rescanApplies ? `${r.rescanClean}/${r.rescanApplies}` : "n/a"} | ${r.onlyExpected}/${r.repeats} | ${range(r.filesSpread, String)} | ${r.linesMean === null ? "n/a" : r.linesMean.toFixed(0)} (${range(r.linesSpread, String)}) | ${usd(r.costMean)} (${range(r.costSpread, usd)}) | ${r.secondsMean.toFixed(0)} (${range(r.secondsSpread, (x) => x.toFixed(0))}) | ${r.failed.length ? r.failed.join("; ") : "-"} |`);
  }
  const touched = rows.filter((r) => r.testsTouched > 0).map((r) => r.case);
  if (touched.length) lines.push("", `Test files were added or edited in: ${touched.join(", ")}. They are not counted as unexpected files, and scoring runs the original test files.`);
  lines.push("", "What this does not show: see docs/design/benchmark.md. Small single-bug repositories and few repeats; differences smaller than the range are noise.", "");
  return lines.join("\n");
}
