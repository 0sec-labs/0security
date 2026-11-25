import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { detect, MANIFEST } from "./ai-security.mjs";
import { renderDetection, scoreClean, scorePlanted, validateManifest } from "./ai-security-score.mjs";
import { build } from "./fixtures/agent-config-repo/build.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "fixtures/agent-config-repo");
const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const f = (ruleId, file, line) => ({ ruleId, file, line });

const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));

test("the manifest names real rules and has unique ids", () => {
  const rules = readFileSync(resolve(here, "../../packages/engine/src/agentconfig/rules.ts"), "utf8");
  const ids = [...rules.matchAll(/id: "(agent-config\/[a-z-]+)"/g)].map((m) => m[1]);
  assert.ok(ids.length >= 9);
  assert.deepEqual(validateManifest(manifest, ids), []);
  assert.ok(manifest.planted.length >= 15 && manifest.decoys.length >= 8);
});

test("the repository holds no hidden characters, no symbolic links and no key-shaped strings in the fixture", () => {
  for (const file of files(fixtureDir)) {
    assert.ok(!lstatSync(file).isSymbolicLink(), `${file} is a symbolic link`);
    const text = readFileSync(file, "utf8");
    assert.ok(!/[\p{Cf}\p{Co}\p{Cn}\u2028\u2029]/u.test(text), `${file} holds an invisible character`);
    assert.ok(!/\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}|xox[abprs]-[A-Za-z0-9-]{10,})/.test(text), `${file} holds a key-shaped string`);
  }
});

test("the generator builds the folders and refuses a folder that is not empty", () => {
  const out = join(mkdtempSync(join(tmpdir(), "0-ai-bench-test-")), "x");
  const made = build(out);
  assert.ok(lstatSync(join(made.planted, ".cursor/rules/team.mdc")).isSymbolicLink());
  assert.ok(!lstatSync(join(made.clean, ".cursor/rules/team.mdc")).isSymbolicLink());
  assert.ok(/\u{e0041}|[\u{e0020}-\u{e007e}]/u.test(readFileSync(join(made.planted, ".cursor/rules/style.mdc"), "utf8")));
  assert.ok(existsSync(join(made.planted, ".cursor/mcp.json")));
  assert.throws(() => build(out), /not empty/);
});

test("scoring needs the same rule, file and line, exactly", () => {
  const exact = manifest.planted.map((p) => f(p.ruleId, p.file, p.line));
  assert.equal(scorePlanted(manifest, exact).recall, 1);
  const off = exact.map((x, i) => (i === 0 ? { ...x, line: x.line + 1 } : x));
  const miss = scorePlanted(manifest, off);
  assert.equal(miss.found, exact.length - 1);
  assert.equal(miss.missed.length, 1);
  assert.equal(miss.unexpected.length, 1);
  const wrongRule = exact.map((x, i) => (i === 0 ? { ...x, ruleId: "agent-config/mcp-secret" } : x));
  assert.equal(scorePlanted(manifest, wrongRule).found, exact.length - 1);
});

test("a finding on a decoy, a repeated finding and a context finding are classified apart", () => {
  const exact = manifest.planted.map((p) => f(p.ruleId, p.file, p.line));
  const decoy = scorePlanted(manifest, [...exact, f("agent-config/mcp-unpinned-launcher", ".mcp.json", 20)]);
  assert.equal(decoy.decoyHits.length, 1);
  assert.equal(decoy.decoyHits[0].decoy, "acd-npx-pinned");
  assert.equal(decoy.falsePositives, 1);
  assert.ok(decoy.precision < 1);
  const twice = scorePlanted(manifest, [...exact, exact[0]]);
  assert.equal(twice.unexpected.length, 1);
  const context = scorePlanted(manifest, [...exact, f("agent-config/mcp-project-autostart", ".mcp.json", 19)]);
  assert.equal(context.context, 1);
  assert.equal(context.falsePositives, 0);
  assert.equal(scoreClean([f("agent-config/mcp-secret", "x.json", 1)]).falsePositives, 1);
  assert.match(renderDetection(decoy, scoreClean([])), /Decoy hit acd-npx-pinned/);
});

test("the rules find every planted item with no false positive, and the clean twin has no finding", () => {
  // Needs the compiled CLI: pnpm --filter @0/engine build && pnpm --filter @0/cli build
  const r = detect();
  assert.deepEqual(r.planted.missed, []);
  assert.equal(r.planted.recall, 1);
  assert.deepEqual(r.planted.decoyHits, []);
  assert.deepEqual(r.planted.unexpected, []);
  assert.equal(r.planted.precision, 1);
  assert.deepEqual(r.clean.findings, []);
});
