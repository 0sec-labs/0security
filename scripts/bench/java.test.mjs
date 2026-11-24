import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadFixtures, parseArgs, planRuns } from "./run.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const javaDir = join(here, "java", "fixtures");

test("the Java fixture set loads, has planted bugs and decoys, and one clean app", () => {
  const fixtures = loadFixtures(undefined, javaDir);
  assert.deepEqual(fixtures.map((f) => f.name), ["java-clean", "java-crypto", "java-servlet", "java-spring"]);
  const planted = fixtures.reduce((n, f) => n + f.answer.items.length, 0);
  assert.equal(planted, 11);
  assert.ok(fixtures.find((f) => f.name === "java-clean").answer.clean);
  for (const f of fixtures) assert.ok(f.answer.decoys.length > 0, `${f.name} has decoys`);
});

test("--fixtures-dir points the runner at another fixture folder and keeps the default otherwise", () => {
  assert.equal(parseArgs(["--dry-run"]).fixturesDir, resolve(here, "fixtures"));
  assert.equal(parseArgs(["--dry-run", "--fixtures-dir", javaDir]).fixturesDir, javaDir);
  assert.equal(planRuns(loadFixtures(undefined, javaDir), ["generic"]).length, 4);
});

test("the Java dry run passes without a model", () => {
  const run = spawnSync(process.execPath, [join(here, "run.mjs"), "--dry-run", "--fixtures-dir", javaDir], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /No model was called/);
});
