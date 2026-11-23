import assert from "node:assert/strict";
import test from "node:test";
import { parseArgs, renderTriage } from "./triage-score.mjs";
import { triageMetrics } from "./verify-score.mjs";

const rows = [
  { cls: "tp", verdict: "true-positive" },
  { cls: "tp", verdict: "true-positive" },
  { cls: "tp", verdict: "false-positive", applied: true, severity: "high" },
  { cls: "tp", verdict: "uncertain" },
  { cls: "fp", verdict: "false-positive" },
  { cls: "fp", verdict: "false-positive" },
  { cls: "fp", verdict: "true-positive" },
  { cls: "other", verdict: "true-positive" },
];

test("triageMetrics gives precision and recall per verdict and the loss to watch", () => {
  const m = triageMetrics(rows);
  assert.equal(m.real, 4);
  assert.equal(m.noise, 3);
  assert.equal(m.unknown, 1);
  assert.equal(m.realCalledFalsePositive, 1);
  assert.equal(m.realSuppressedHighOrCritical, 1);
  // true-positive verdict: 2 real + 1 noise carry it; 2 of the 4 real bugs have it.
  assert.ok(Math.abs(m.truePositive.precision - 2 / 3) < 1e-9);
  assert.equal(m.truePositive.recall, 0.5);
  // false-positive verdict: 2 noise + 1 real carry it; 2 of the 3 noise findings have it.
  assert.ok(Math.abs(m.falsePositive.precision - 2 / 3) < 1e-9);
  assert.ok(Math.abs(m.falsePositive.recall - 2 / 3) < 1e-9);
  assert.equal(m.recallLoss, 0.25);
  assert.ok(Math.abs(m.noiseRemoved - 2 / 3) < 1e-9);
  assert.ok(Math.abs(m.precisionBefore - 4 / 7) < 1e-9);
  // After dropping false-positive verdicts: 3 real and 1 noise remain.
  assert.equal(m.precisionAfter, 0.75);
});

test("triageMetrics returns null rates when a group is empty", () => {
  const m = triageMetrics([{ cls: "other", verdict: "uncertain" }]);
  assert.equal(m.recallLoss, null);
  assert.equal(m.truePositive.precision, null);
});

test("the report leads with real bugs called false-positive and labels the run", () => {
  const text = renderTriage([{ fixture: "x", repeat: 1, findings: 8, rows, scanCostUsd: 0.01, verifyCostUsd: 0.05 }], { date: "2026-01-01", model: "m", fixtures: ["x"], repeat: 1 });
  assert.match(text, /Real bugs that verify called false-positive: 1 of 4\./);
  assert.match(text, /- Model: m/);
  assert.match(text, /Spend: \$0\.0600/);
  assert.match(text, /\| false-positive \| 1 \| 2 \| 0 \|/);
});

test("parseArgs needs exactly one mode and defaults to three fixtures", () => {
  assert.throws(() => parseArgs([]));
  assert.throws(() => parseArgs(["--run", "--dry-run"]));
  const o = parseArgs(["--run", "--repeat", "2", "--scans", "/tmp/x"]);
  assert.equal(o.repeat, 2);
  assert.equal(o.fixtures.length, 3);
  assert.throws(() => parseArgs(["--run", "--nope"]));
});
