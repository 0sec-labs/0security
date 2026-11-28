import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCases, parseArgs, renderOwasp, scoreOwasp } from "./owasp-score.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const cases = [
  { name: "BenchmarkTest00001", category: "sqli", real: true },
  { name: "BenchmarkTest00002", category: "sqli", real: true },
  { name: "BenchmarkTest00003", category: "sqli", real: false },
  { name: "BenchmarkTest00004", category: "sqli", real: false },
  { name: "BenchmarkTest00005", category: "xss", real: true },
  { name: "BenchmarkTest00006", category: "xss", real: false },
];
const at = (name, title) => ({ title, location: { path: `src/${name}.java`, startLine: 30 } });

test("scoreOwasp gives per-category rates and the true minus false positive score", () => {
  const { rows, total } = scoreOwasp(cases, [
    at("BenchmarkTest00001", "SQL injection"), // real, detected
    at("BenchmarkTest00003", "SQL injection"), // not real, flagged
    at("BenchmarkTest00003", "SQL injection again"), // the same case twice counts once
    at("BenchmarkTest00005", "Weak hash"), // right file, wrong category
    at("Other", "SQL injection"), // not a case file
  ]);
  const sqli = rows.find((r) => r.category === "sqli");
  assert.deepEqual([sqli.detectedReal, sqli.detectedNotReal, sqli.tpr, sqli.fpr, sqli.score], [1, 1, 0.5, 0.5, 0]);
  const xss = rows.find((r) => r.category === "xss");
  assert.deepEqual([xss.detectedReal, xss.tpr, xss.fpr, xss.score], [0, 0, 0, 0]);
  assert.equal(total.detectedReal, 1);
  assert.equal(total.detectedNotReal, 1);
  assert.equal(total.otherCategory, 1);
  assert.equal(total.outside, 1);
  assert.equal(total.score, 1 / 3 - 1 / 3);
});

test("a perfect scan scores 100 and an empty scan scores 0", () => {
  const perfect = scoreOwasp(cases, cases.filter((c) => c.real).map((c) => at(c.name, c.category === "sqli" ? "SQL injection" : "XSS")));
  assert.equal(perfect.total.score, 1);
  assert.equal(scoreOwasp(cases, []).total.score, 0);
});

test("a category with only one kind of case has no score and is left out of the mean", () => {
  const { rows, total } = scoreOwasp([{ name: "BenchmarkTest00001", category: "sqli", real: true }, { name: "BenchmarkTest00002", category: "xss", real: true }, { name: "BenchmarkTest00003", category: "xss", real: false }], [at("BenchmarkTest00001", "SQL injection")]);
  assert.equal(rows.find((r) => r.category === "sqli").score, null);
  assert.equal(total.meanCategoryScore, 0);
});

test("renderOwasp lists every category and states the limits", () => {
  const md = renderOwasp(scoreOwasp(cases, [at("BenchmarkTest00001", "SQL injection")]), { date: "d", model: "m", sample: "s", costUsd: 0.1 });
  assert.match(md, /\| sqli \| 2 \| 2 \| 1 \| 0 \| 50% \| 0% \| 50 \|/);
  assert.match(md, /What this does not show/);
});

test("parseArgs needs one mode and a checkout", () => {
  assert.throws(() => parseArgs(["--owasp", "/x"]));
  assert.throws(() => parseArgs(["--dry-run", "--run", "--owasp", "/x"]));
  assert.throws(() => parseArgs(["--dry-run"]));
  assert.throws(() => parseArgs(["--dry-run", "--owasp", "/x", "--categories", "nope"]));
  assert.ok(parseArgs(["--scan-file", "/s.json", "--owasp", "/x"]).scanFile);
});

// A made-up BenchmarkJava checkout and a saved scan: the whole --scan-file path with no model.
function fakeCheckout() {
  const root = mkdtempSync(join(tmpdir(), "0-owasp-fake-"));
  const rows = ["# test name, category, real vulnerability, cwe"];
  for (let i = 1; i <= 6; i++) rows.push(`BenchmarkTest0000${i},${i <= 4 ? "sqli" : "xss"},${i % 2 === 1},${i <= 4 ? 89 : 79}`);
  writeFileSync(join(root, "expectedresults-1.2.csv"), `${rows.join("\n")}\n`);
  const code = join(root, "src/main/java/org/owasp/benchmark/testcode");
  mkdirSync(code, { recursive: true });
  for (let i = 1; i <= 6; i++) writeFileSync(join(code, `BenchmarkTest0000${i}.java`), "class T {}\n");
  return root;
}

test("loadCases takes the seeded sample or everything with --all", () => {
  const owasp = fakeCheckout();
  assert.equal(loadCases(parseArgs(["--dry-run", "--owasp", owasp, "--per-class", "1"])).length, 4);
  assert.equal(loadCases(parseArgs(["--dry-run", "--owasp", owasp, "--all"])).length, 6);
  assert.equal(loadCases(parseArgs(["--dry-run", "--owasp", owasp, "--all", "--categories", "xss"])).length, 2);
});

test("--scan-file scores a saved report end to end and --dry-run needs no model", () => {
  const owasp = fakeCheckout();
  const dir = mkdtempSync(join(tmpdir(), "0-owasp-scan-"));
  const scan = join(dir, "scan.json");
  writeFileSync(scan, JSON.stringify({ usage: { costUsd: 0.05 }, findings: [at("BenchmarkTest00001", "SQL injection"), at("BenchmarkTest00002", "SQL injection"), at("BenchmarkTest00005", "Reflected XSS")] }));
  const out = join(dir, "out");
  const p = spawnSync(process.execPath, [join(here, "owasp-score.mjs"), "--scan-file", scan, "--owasp", owasp, "--all", "--out", out], { encoding: "utf8" });
  assert.equal(p.status, 0, p.stderr);
  // Real: 1, 3, 5. Not real: 2, 4, 6. Flagged: 1 (real), 2 (not real), 5 (real).
  assert.match(p.stdout, /True-positive rate 67% \(2 of 3 real cases detected\), false-positive rate 33% \(1 of 3 not-real cases flagged\), score 33 points/);
  const dry = spawnSync(process.execPath, [join(here, "owasp-score.mjs"), "--dry-run", "--owasp", owasp, "--per-class", "1"], { encoding: "utf8" });
  assert.equal(dry.status, 0, dry.stderr);
  assert.match(dry.stdout, /dry run passed: no model was called/);
});
