import assert from "node:assert/strict";
import test from "node:test";
import { labelClassifier, owaspClassifier, parseArgs, parseExpectedResults, sampleCases } from "./triage-truth.mjs";

const csv = `# test name, category, real vulnerability, cwe
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,false,22
BenchmarkTest00003,sqli,true,89
BenchmarkTest00004,sqli,true,89
BenchmarkTest00005,sqli,false,89
BenchmarkTest00006,sqli,false,89
`;

test("parseExpectedResults skips comments and reads the truth column", () => {
  const rows = parseExpectedResults(csv);
  assert.equal(rows.length, 6);
  assert.deepEqual(rows[1], { name: "BenchmarkTest00002", category: "pathtraver", real: false, cwe: "22" });
});

test("sampleCases is balanced, seeded and limited to the wanted categories", () => {
  const rows = parseExpectedResults(csv);
  const a = sampleCases(rows, { perClass: 1, seed: 7 });
  assert.equal(a.length, 4);
  assert.equal(a.filter((r) => r.category === "sqli" && r.real).length, 1);
  assert.equal(a.filter((r) => r.category === "sqli" && !r.real).length, 1);
  assert.deepEqual(sampleCases(rows, { perClass: 1, seed: 7 }), a);
  assert.deepEqual(sampleCases(rows, { perClass: 5, categories: ["pathtraver"] }).map((r) => r.name), ["BenchmarkTest00001", "BenchmarkTest00002"]);
});

test("owaspClassifier needs the right file and the right category", () => {
  const classify = owaspClassifier(parseExpectedResults(csv));
  const at = (name, title) => ({ title, location: { path: `${name}.java`, startLine: 40 } });
  assert.equal(classify(at("BenchmarkTest00003", "SQL injection in query")), "tp");
  assert.equal(classify(at("BenchmarkTest00005", "SQL injection in query")), "fp");
  // A finding about another class of bug in a case file proves nothing either way.
  assert.equal(classify(at("BenchmarkTest00003", "Weak hash")), "other");
  assert.equal(classify(at("Other", "SQL injection")), "other");
  assert.equal(classify({ title: "SQL injection" }), "other");
});

test("labelClassifier matches the file within five lines", () => {
  const classify = labelClassifier([{ path: "src/A.java", line: 40, label: "real" }, { path: "src/B.java", line: 10, label: "noise" }]);
  assert.equal(classify({ location: { path: "app/src/A.java", startLine: 44 } }), "tp");
  assert.equal(classify({ location: { path: "src/A.java", startLine: 60 } }), "other");
  assert.equal(classify({ location: { path: "src/B.java", startLine: 9 } }), "fp");
});

test("parseArgs needs one mode and one ground truth", () => {
  assert.throws(() => parseArgs(["--owasp", "/x"]));
  assert.throws(() => parseArgs(["--dry-run"]));
  assert.throws(() => parseArgs(["--dry-run", "--owasp", "/x", "--labels", "/y"]));
  assert.throws(() => parseArgs(["--dry-run", "--labels", "/y"]));
  assert.throws(() => parseArgs(["--dry-run", "--owasp", "/x", "--categories", "nope"]));
  const o = parseArgs(["--run", "--owasp", "/x", "--per-class", "4", "--categories", "sqli,xss"]);
  assert.equal(o.perClass, 4);
  assert.deepEqual(o.categories, ["sqli", "xss"]);
});

// Label files, scored end to end with a stand-in CLI: no model, no network.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkLabelsAgainstApp, labelCoverage, labelsFromAnswer, parseLabels } from "./triage-truth.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const good = { app: "x", findings: [{ path: "src/A.java", line: 40, label: "real", note: "tainted query" }, { path: "src/B.java", line: 10, label: "noise", note: "constant" }] };

test("parseLabels accepts a well-formed file", () => {
  const { labels, problems } = parseLabels(good);
  assert.equal(labels.length, 2);
  assert.deepEqual(problems, []);
});

test("parseLabels names every problem", () => {
  const { problems } = parseLabels({ findings: [
    { path: "/abs/A.java", line: 1, label: "real", note: "n" },
    { path: "../up.java", line: 1, label: "real", note: "n" },
    { path: "a.java", line: 0, label: "real", note: "n" },
    { path: "a.java", line: 3, label: "maybe", note: "n" },
    { path: "a.java", line: 4, label: "real", note: " " },
    { path: "a.java", line: 5, label: "real", note: "n" },
    { path: "a.java", line: 5, label: "noise", note: "n" },
  ] });
  assert.equal(problems.length, 6);
  assert.deepEqual(parseLabels({}).problems, ["the file needs a findings array"]);
});

test("checkLabelsAgainstApp finds a missing file and a line past the end", () => {
  const app = mkdtempSync(join(tmpdir(), "0-labels-app-"));
  mkdirSync(join(app, "src"));
  writeFileSync(join(app, "src/A.java"), "a\nb\nc\n");
  const problems = checkLabelsAgainstApp([{ path: "src/A.java", line: 2 }, { path: "src/A.java", line: 40 }, { path: "src/Gone.java", line: 1 }], app);
  assert.equal(problems.length, 2);
  assert.match(problems[0], /A\.java:40/);
  assert.match(problems[1], /not found/);
});

test("labelCoverage counts the labels a scan reached", () => {
  const labels = good.findings;
  const c = labelCoverage(labels, [{ location: { path: "app/src/A.java", startLine: 42 } }]);
  assert.deepEqual(c, { real: 1, noise: 1, realReached: 1, noiseReached: 0 });
});

test("the committed label file for a fixture matches its answer key and its source", () => {
  const file = join(here, "labels/node-express.labels.json");
  const { labels, problems } = parseLabels(JSON.parse(readFileSync(file, "utf8")));
  assert.deepEqual(problems, []);
  assert.deepEqual(checkLabelsAgainstApp(labels, join(here, "fixtures/node-express")), []);
  const answer = JSON.parse(readFileSync(join(here, "fixtures/node-express/answer.json"), "utf8"));
  assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), labelsFromAnswer(answer, "node-express"));
  assert.equal(labels.filter((l) => l.label === "real").length, answer.items.length);
});

test("--run --labels scores a stand-in scan and verify, and reports coverage", () => {
  const root = mkdtempSync(join(tmpdir(), "0-labels-run-"));
  const app = join(root, "app");
  mkdirSync(join(app, "src"), { recursive: true });
  writeFileSync(join(app, "src/A.java"), `${"x\n".repeat(60)}`);
  writeFileSync(join(app, "src/B.java"), `${"y\n".repeat(20)}`);
  const labels = join(root, "labels.json");
  writeFileSync(labels, JSON.stringify(good));
  // The stand-in: `scan` writes a report with three findings; `findings verify` calls the real one true-positive and the noise one false-positive.
  const cli = join(root, "fake-cli.mjs");
  writeFileSync(cli, `
import { writeFileSync } from "node:fs";
const a = process.argv.slice(2);
if (a[0] === "scan") {
  const out = a[a.indexOf("-o") + 1];
  writeFileSync(out, JSON.stringify({ costUsd: 0.01, findings: [
    { id: "f1", title: "SQL injection", location: { path: "src/A.java", startLine: 41 } },
    { id: "f2", title: "Weak hash", location: { path: "src/B.java", startLine: 11 } },
    { id: "f3", title: "Other", location: { path: "src/C.java", startLine: 1 } } ] }));
} else {
  console.log(JSON.stringify({ costUsd: 0.02, items: [
    { finding: "f1", verdict: "true-positive", severity: "high", applied: false },
    { finding: "f2", verdict: "false-positive", severity: "low", applied: true },
    { finding: "f3", verdict: "uncertain", severity: "low", applied: false } ] }));
}
`);
  const out = join(root, "out");
  const p = spawnSync(process.execPath, [join(here, "triage-truth.mjs"), "--run", "--labels", labels, "--app", app, "--cli", cli, "--out", out], { encoding: "utf8" });
  assert.equal(p.status, 0, p.stderr + p.stdout);
  assert.match(p.stdout, /Real bugs that verify called false-positive: 0 of 1/);
  assert.match(p.stdout, /Noise removed: 100%/);
  assert.match(p.stdout, /Labelled set reached by the scan: 1 of 1 real labels and 1 of 1 noise labels/);
});

test("--run --labels refuses a label file that does not fit the app", () => {
  const root = mkdtempSync(join(tmpdir(), "0-labels-bad-"));
  mkdirSync(join(root, "app"));
  const labels = join(root, "labels.json");
  writeFileSync(labels, JSON.stringify(good));
  const p = spawnSync(process.execPath, [join(here, "triage-truth.mjs"), "--dry-run", "--labels", labels, "--app", join(root, "app")], { encoding: "utf8" });
  assert.notEqual(p.status, 0);
  assert.match(p.stderr, /file not found/);
});

test("--validate-labels and --labels-from-fixture need no run mode", () => {
  assert.ok(parseArgs(["--validate-labels", "/x.json"]).validateLabels);
  assert.throws(() => parseArgs(["--validate-labels", "/x.json", "--run"]));
  assert.equal(parseArgs(["--labels-from-fixture", "clean-app"]).labelsFromFixture, "clean-app");
});
