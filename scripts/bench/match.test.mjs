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

test("web-application families come from the title", () => {
  const fam = (title, category = "other") => familiesOf({ category, title });
  assert.ok(fam("XML external entity processing in bulk import").has("xxe"));
  assert.ok(fam("Missing CSRF protection on state-changing forms").has("csrf"));
  assert.ok(fam("Open redirect through the url parameter").has("open-redirect"));
  assert.ok(fam("Regular expression denial of service in email check").has("redos"));
  assert.ok(fam("Outdated mathjs dependency with known vulnerabilities").has("vuln-dependency"));
  assert.ok(fam("Session fixation: id not regenerated on login").has("authn"));
  assert.ok(fam("Username enumeration through distinct login errors").has("authn"));
  assert.ok(fam("Server listens over plain HTTP instead of HTTPS").has("transport"));
  assert.ok(fam("Stack trace returned to the client").has("misconfig"));
  assert.ok(fam("No rate limiting on login").has("rate-limit"));
  assert.ok(fam("Mass assignment of the admin flag on registration").has("mass-assignment"));
  assert.equal(fam("SQL injection in search").has("xxe"), false);
});

test("a finding on an item with a label that fits no family is a near miss, not a hit", () => {
  const key = { fixture: "x", items: [{ id: "p", path: "u.py", startLine: 10, endLine: 12, category: "sqli", description: "d" }], decoys: [] };
  const r = scoreFindings(key, [{ id: "n", title: "Input is validated late", category: "missing-validation", location: { path: "u.py", startLine: 11 } }]);
  assert.equal(r.found, 0);
  assert.deepEqual(r.nearMisses, [{ finding: "n", item: "p", distance: 0 }]);
  assert.deepEqual(scoreFindings(key, [{ id: "n", title: "x", category: "other", location: { path: "u.py", startLine: 40 } }]).nearMisses, []);
});

test("access-control wording about other users reads as authz", () => {
  assert.ok(familiesOf({ category: "missing-validation", title: "Authenticated users can reset another user's password" }).has("authz"));
  assert.ok(familiesOf({ category: "other", title: "Registration permits administrator self-assignment" }).has("authz"));
  assert.equal(familiesOf({ category: "style", title: "Users page is slow" }).has("authz"), false);
});

test("an item may list several categories and any of them credits it", () => {
  const key = { fixture: "x", items: [{ id: "m", path: "a.js", startLine: 10, endLine: 12, category: ["authz", "weak-crypto"], description: "d" }], decoys: [] };
  const found = (finding) => scoreFindings(key, [{ location: { path: "a.js", startLine: 11 }, ...finding }]).found;
  assert.equal(found({ title: "Weak MD5 reset token", category: "weak-crypto" }), 1);
  assert.equal(found({ title: "Missing authorization on reset", category: "authz" }), 1);
  assert.equal(found({ title: "SQL injection", category: "sql-injection" }), 0);
  assert.deepEqual(validateAnswer(key), []);
  assert.ok(validateAnswer({ ...key, items: [{ ...key.items[0], category: ["authz", "nope"] }] }).some((p) => p.includes("unknown category nope")));
});

test("the engine's web categories map to families without needing the title", () => {
  const fam = (category) => familiesOf({ category, title: "x" });
  assert.ok(fam("broken-access-control").has("authz"));
  assert.ok(fam("broken-authentication").has("authn"));
  assert.ok(fam("mass-assignment").has("authz") && fam("mass-assignment").has("mass-assignment"));
  assert.ok(fam("insecure-randomness").has("weak-crypto"));
  assert.ok(fam("insecure-storage").has("secret"));
  assert.ok(fam("insecure-transport").has("transport"));
  assert.ok(fam("missing-rate-limit").has("rate-limit"));
  assert.ok(fam("hardcoded-secret").has("secret"));
  for (const c of ["csrf", "open-redirect", "xxe"]) assert.ok(fam(c).has(c));
  assert.ok(familiesOf({ category: "code-injection", title: "MongoDB $where JavaScript injection" }).has("sqli"));
});

test("missing-validation maps to the business-logic family, which an item can name next to authz", () => {
  const key = { fixture: "f", items: [{ id: "r", path: "a.ts", startLine: 5, endLine: 8, category: ["authz", "business-logic"] }], decoys: [] };
  const s = scoreFindings(key, [{ id: "x", title: "Refund amount not checked against paid total", category: "missing-validation", location: { path: "a.ts", startLine: 6 } }]);
  assert.equal(s.found, 1);
});
