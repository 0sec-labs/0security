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
