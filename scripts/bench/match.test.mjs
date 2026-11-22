import assert from "node:assert/strict";
import test from "node:test";
import { familiesOf, lineDistance, mean, samePath, scoreFindings, spread, validateAnswer } from "./match.mjs";

const answer = {
  fixture: "x",
  items: [
    { id: "a", path: "app.js", startLine: 20, endLine: 22, category: "sqli", description: "d" },
    { id: "b", path: "app.js", startLine: 40, endLine: 40, category: "secret", description: "d" },
  ],
  decoys: [{ id: "d1", path: "app.js", startLine: 60, endLine: 62, description: "safe" }],
};
const f = (over) => ({ id: "f", title: "SQL injection in handler", category: "sql-injection", location: { path: "app.js", startLine: 21 }, ...over });

test("families come from category, title, then description", () => {
  assert.ok(familiesOf({ category: "sql-injection" }).has("sqli"));
  assert.ok(familiesOf({ category: "other", title: "Hardcoded API key" }).has("secret"));
  assert.ok(familiesOf({ category: "other", title: "x", description: "uses pickle.loads on input" }).has("deserialization"));
  assert.equal(familiesOf({ category: "other", title: "style" }).size, 0);
  assert.ok(familiesOf({ category: "other", title: "Unescaped agent reply is inserted into HTML" }).has("output-handling"));
  assert.ok(familiesOf({ category: "other", title: "Model-controlled shell tool executes ticket-influenced commands" }).has("prompt-injection"));
});

test("infrastructure families come from the title", () => {
  const fam = (title, category = "other") => familiesOf({ category, title });
  assert.ok(fam("Private subnet routes 0.0.0.0/0 to an internet gateway").has("iac-network"));
  assert.ok(fam("Database security group reachable through an open group").has("iac-network"));
  assert.ok(fam("iam:PassRole on Resource * allows privilege escalation").has("iac-iam"));
  assert.ok(fam("Privileged container mounts docker.sock").has("iac-privilege"));
  assert.ok(fam("Install script piped into sh in the image build").has("iac-supply"));
  assert.ok(fam("Script injection from the pull request title in a workflow").has("ci-injection"));
  assert.ok(fam("pull_request_target checks out untrusted code with secrets").has("ci-injection"));
  assert.equal(fam("Ensure that the S3 bucket has versioning enabled").has("iac-iam"), false);
});

test("paths match by suffix, ranges by distance", () => {
  assert.ok(samePath("/tmp/x/app.js", "app.js"));
  assert.ok(samePath("./src/app.js", "src/app.js"));
  assert.ok(!samePath("other.js", "app.js"));
  assert.equal(lineDistance(10, 12, 12, 20), 0);
  assert.equal(lineDistance(10, 12, 18, 20), 6);
  assert.equal(lineDistance(30, 31, 10, 12), 18);
});

test("a finding within 5 lines, right path and family finds the item", () => {
  const r = scoreFindings(answer, [f({ location: { path: "app.js", startLine: 27 } })]);
  assert.deepEqual(r.foundIds, ["a"]);
  assert.equal(r.recall, 0.5);
  assert.deepEqual(r.missedIds, ["b"]);
});

test("too far, wrong path or wrong family does not match", () => {
  assert.equal(scoreFindings(answer, [f({ location: { path: "app.js", startLine: 28 } })]).found, 0);
  assert.equal(scoreFindings(answer, [f({ location: { path: "b.js", startLine: 21 } })]).found, 0);
  assert.equal(scoreFindings(answer, [f({ category: "xss", title: "XSS" })]).found, 0);
});

test("one finding credits one item, the closest", () => {
  const two = { ...answer, items: [answer.items[0], { id: "a2", path: "app.js", startLine: 25, endLine: 25, category: "sqli", description: "d" }] };
  const r = scoreFindings(two, [f({ location: { path: "app.js", startLine: 25 } })]);
  assert.deepEqual(r.foundIds, ["a2"]);
});

test("a finding on a decoy is a false positive; a stray one is only unmatched", () => {
  const r = scoreFindings(answer, [f({ location: { path: "app.js", startLine: 61 } }), f({ id: "g", location: { path: "app.js", startLine: 100 } })]);
  assert.equal(r.falsePositives, 1);
  assert.equal(r.decoyHits[0].decoy, "d1");
  assert.equal(r.unmatched.length, 1);
});

test("in a clean fixture every finding is a false positive, located or not", () => {
  const clean = { fixture: "c", clean: true, items: [], decoys: [] };
  const r = scoreFindings(clean, [f(), f({ id: "n", location: undefined })]);
  assert.equal(r.falsePositives, 2);
  assert.equal(r.recall, null);
});

test("dense items are paired one-to-one so the most are found, and a duplicate is not noise", () => {
  const dense = { fixture: "d", items: [
    { id: "p", path: "a.py", startLine: 11, endLine: 11, category: "weak-crypto", description: "d" },
    { id: "q", path: "a.py", startLine: 15, endLine: 15, category: "weak-crypto", description: "d" },
  ], decoys: [] };
  const w = (id, line) => ({ id, title: "weak crypto", category: "weak-crypto", location: { path: "a.py", startLine: line } });
  assert.equal(scoreFindings(dense, [w("x", 14), w("y", 18)]).found, 2);
  const far = { ...dense, items: [dense.items[0], { ...dense.items[1], startLine: 40, endLine: 40 }] };
  const dup = scoreFindings(far, [w("x", 11), w("y", 11)]);
  assert.equal(dup.found, 1);
  assert.equal(dup.unmatched.length, 0);
});

test("mean and spread", () => {
  assert.equal(mean([1, 2, 3]), 2);
  assert.equal(mean([]), null);
  assert.deepEqual(spread([3, 1, 2]), [1, 3]);
});

test("validateAnswer catches bad keys", () => {
  assert.deepEqual(validateAnswer(answer, { fileLines: { "app.js": 70 } }), []);
  assert.ok(validateAnswer(answer, { fileLines: { "app.js": 30 } }).some((p) => p.includes("past the end")));
  assert.ok(validateAnswer({ ...answer, items: [{ ...answer.items[0], category: "nope" }] }).some((p) => p.includes("unknown category")));
  assert.ok(validateAnswer({ fixture: "c", clean: true, items: [answer.items[0]], decoys: [] }).length > 0);
});

test("an item can name other places the same flaw shows, and the authz family reads access-control wording", () => {
  const key = { fixture: "x", items: [{ id: "ssrf", path: "routes/hook.js", startLine: 20, endLine: 21, category: "ssrf", description: "d", alsoAt: [{ path: "lib/http.js", startLine: 4, endLine: 16 }] }, { id: "idor", path: "routes/orders.js", startLine: 22, endLine: 23, category: "authz", description: "d" }], decoys: [] };
  const hit = (path, line, category, title) => ({ id: `${path}:${line}`, title, category, location: { path, startLine: line } });
  assert.deepEqual(scoreFindings(key, [hit("lib/http.js", 9, "ssrf", "SSRF")]).foundIds, ["ssrf"]);
  assert.deepEqual(scoreFindings(key, [hit("routes/hook.js", 20, "ssrf", "SSRF")]).foundIds, ["ssrf"]);
  assert.equal(scoreFindings(key, [hit("lib/other.js", 9, "ssrf", "SSRF")]).found, 0);
  assert.equal(scoreFindings(key, [hit("routes/orders.js", 22, "authorization", "Missing ownership check on order read")]).found, 1);
  assert.ok(validateAnswer(key, { fileLines: { "routes/hook.js": 30, "lib/http.js": 10, "routes/orders.js": 40 } }).some((p) => p.includes("past the end of lib/http.js")));
  assert.ok(validateAnswer(key, { fileLines: { "routes/hook.js": 30, "routes/orders.js": 40 } }).some((p) => p.includes("alsoAt file lib/http.js not found")));
});
