import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const script = join(import.meta.dirname, "stage-release-assets.sh");
const platforms = ["darwin-arm64", "linux-x64", "linux-arm64", "windows-x64.exe"];
const sha = (buf) => createHash("sha256").update(buf).digest("hex");

function staged(skip, skipFox) {
  const dir = mkdtempSync(join(tmpdir(), "0-stage-test-"));
  for (const p of platforms) if (p !== skip) writeFileSync(join(dir, `0-${p}`), `binary ${p}\n`);
  for (const p of platforms) if (p !== skipFox) writeFileSync(join(dir, `foxguard-${p}`), `foxguard ${p}\n`);
  return dir;
}

test("each binary is copied to the 0security name and checksums.txt lists both sets", () => {
  const dir = staged();
  try {
    const run = spawnSync("bash", [script, dir], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const names = platforms.flatMap((p) => [`0-${p}`, `0security-${p}`, `foxguard-${p}`]);
    assert.deepEqual(readdirSync(dir).sort(), [...names, "checksums.txt"].sort());
    const lines = readFileSync(join(dir, "checksums.txt"), "utf8").trim().split("\n");
    assert.equal(lines.length, 12);
    for (const p of platforms) {
      const oldBytes = readFileSync(join(dir, `0-${p}`));
      assert.deepEqual(readFileSync(join(dir, `0security-${p}`)), oldBytes);
      for (const name of [`0-${p}`, `0security-${p}`]) {
        assert.ok(lines.some((l) => l.startsWith(`${sha(oldBytes)} `) && l.endsWith(` ${name}`)), name);
      }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a missing binary fails and writes no checksums.txt", () => {
  const dir = staged("linux-arm64");
  try {
    const run = spawnSync("bash", [script, dir], { encoding: "utf8" });
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /missing 0-linux-arm64/);
    assert.equal(existsSync(join(dir, "checksums.txt")), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a missing foxguard binary fails and writes no checksums.txt", () => {
  const dir = staged(undefined, "linux-x64");
  try {
    const run = spawnSync("bash", [script, dir], { encoding: "utf8" });
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /missing foxguard-linux-x64/);
    assert.equal(existsSync(join(dir, "checksums.txt")), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("foxguard binaries are checksummed with the same digests as their bytes", () => {
  const dir = staged();
  try {
    assert.equal(spawnSync("bash", [script, dir], { encoding: "utf8" }).status, 0);
    const text = readFileSync(join(dir, "checksums.txt"), "utf8");
    for (const p of platforms) assert.ok(text.includes(`${sha(readFileSync(join(dir, `foxguard-${p}`)))}  foxguard-${p}`), p);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("unrelated files in the folder are not listed", () => {
  const dir = staged();
  try {
    writeFileSync(join(dir, "stray.txt"), "x");
    assert.equal(spawnSync("bash", [script, dir], { encoding: "utf8" }).status, 0);
    assert.ok(!readFileSync(join(dir, "checksums.txt"), "utf8").includes("stray"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
