import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { repoRoot } from "../lib.mjs";
import { validateAnswer } from "../match.mjs";

const here = join(repoRoot, "scripts/bench/code-index-hard");
const fixtures = [
  ["fixtures/ts-workspace", "ts-workspace"],
  ["fixtures/java-ledger", "java-ledger"],
  ["variants/variants-tenant", "variants-tenant"],
];

// A file that .gitignore hides exists in a working copy but not in a clone, so the key is checked against git, not the disk.
const tracked = new Set(spawnSync("git", ["ls-files", "scripts/bench/code-index-hard"], { cwd: repoRoot, encoding: "utf8" }).stdout.split("\n").filter(Boolean));

for (const [dir, name] of fixtures) {
  test(`${name}: every file the answer key points at is tracked by git`, () => {
    const root = join(here, dir);
    const answer = JSON.parse(readFileSync(join(root, "answer.json"), "utf8"));
    const paths = new Set([...answer.items, ...answer.decoys].flatMap((e) => [e.path, ...(e.alsoAt ?? []).map((a) => a.path)]).concat(answer.cleanPaths ?? [], answer.seed ? [answer.seed.path] : []));
    const missing = [...paths].filter((p) => !tracked.has(relative(repoRoot, join(root, p))));
    assert.deepEqual(missing, [], `not tracked by git (ignored by .gitignore?): ${missing.join(", ")}`);
    const lines = {};
    for (const p of paths) if (existsSync(join(root, p))) lines[p] = readFileSync(join(root, p), "utf8").split("\n").length - 1;
    assert.deepEqual(validateAnswer(answer, { fileLines: lines }), []);
  });
}
