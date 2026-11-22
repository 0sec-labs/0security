import assert from "node:assert/strict";
import test from "node:test";
import { classify, render, tally } from "./verify-score.mjs";

const answer = { fixture: "x", items: [{ id: "a", path: "app.js", startLine: 20, endLine: 22, category: "sqli", description: "d" }], decoys: [{ id: "d1", path: "app.js", startLine: 60, endLine: 62, description: "safe" }] };
const at = (line, category = "sql injection") => ({ id: `f${line}`, title: "t", category, location: { path: "app.js", startLine: line } });

test("classify separates planted bugs, decoys and other findings", () => {
  assert.equal(classify(answer, at(21)), "tp");
  assert.equal(classify(answer, at(61, "xss")), "fp");
  assert.equal(classify(answer, at(90, "xss")), "other");
  assert.equal(classify({ ...answer, clean: true, items: [] }, at(21)), "fp");
});

test("tally counts real bugs that --apply suppressed", () => {
  const t = tally([
    { cls: "tp", verdict: "false-positive", applied: true, severity: "high" },
    { cls: "tp", verdict: "true-positive", applied: false, severity: "high" },
    { cls: "fp", verdict: "false-positive", applied: true, severity: "low" },
  ]);
  assert.equal(t.wronglySuppressed, 1);
  assert.equal(t.wronglySuppressedHighOrCritical, 1);
  assert.equal(t.suppressedFalsePositives, 1);
  assert.equal(t.tp.byVerdict["false-positive"], 1);
});

test("render puts the dangerous number first", () => {
  const text = render([{ fixture: "x", repeat: 1, findings: 1, rows: [{ cls: "tp", verdict: "false-positive", applied: true, severity: "low" }] }]);
  assert.match(text.split("\n")[0], /called false-positive: 1\/1/);
});
