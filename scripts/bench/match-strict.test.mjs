import assert from "node:assert/strict";
import test from "node:test";
import { scoreFindings, validateAnswer } from "./match.mjs";

const key = {
  fixture: "x",
  items: [{ id: "hist", path: "routes/tasks.ts", startLine: 50, endLine: 54, category: "authz", description: "d", oracle: { mention: ["history|activity"] }, alsoAt: [{ path: "services/activity.ts", startLine: 10, endLine: 14 }] }],
  decoys: [{ id: "dec", path: "routes/tasks.ts", startLine: 70, endLine: 74, category: "authz", description: "guarded" }],
  cleanPaths: ["routes/labels.ts"],
};
const g = (over) => ({ id: "g", title: "Any user can read task history of another org", category: "broken-access-control", description: "history lookup lacks org check", location: { path: "routes/tasks.ts", startLine: 51 }, ...over });

test("strict oracle credits path, close lines, family and mention together", () => {
  assert.equal(scoreFindings(key, [g()]).found, 1);
  assert.equal(scoreFindings(key, [g({ location: { path: "services/activity.ts", startLine: 12 } })]).found, 1);
});

test("strict oracle: too far, wrong topic or wrong family is not credited", () => {
  // the loose matcher allows 5 lines; the oracle allows 3
  assert.equal(scoreFindings(key, [g({ location: { path: "routes/tasks.ts", startLine: 59 } })]).found, 0);
  assert.equal(scoreFindings(key, [g({ title: "Cancel route allows another user", description: "cancel ignores owner" })]).found, 0);
  assert.equal(scoreFindings(key, [g({ category: "xss", title: "history xss" })]).found, 0);
});

test("false positives: a decoy hit needs its family, a clean file needs an authorization-class finding", () => {
  assert.equal(scoreFindings(key, [g({ title: "Another user can read it", description: "x", location: { path: "routes/tasks.ts", startLine: 72 } })]).decoyHits.length, 1);
  assert.equal(scoreFindings(key, [g({ category: "xss", title: "xss", description: "x", location: { path: "routes/tasks.ts", startLine: 72 } })]).decoyHits.length, 0);
  const clean = scoreFindings(key, [g({ description: "x", location: { path: "routes/labels.ts", startLine: 9 } })]);
  assert.equal(clean.cleanHits.length, 1);
  assert.equal(clean.falsePositives, 1);
  assert.equal(scoreFindings(key, [g({ category: "xss", title: "xss", location: { path: "routes/labels.ts", startLine: 9 } })]).falsePositives, 0);
});

test("validateAnswer checks oracle patterns", () => {
  assert.ok(validateAnswer({ ...key, items: [{ ...key.items[0], oracle: { mention: ["("] } }] }).some((p) => /bad oracle/.test(p)));
  assert.deepEqual(validateAnswer(key), []);
});
