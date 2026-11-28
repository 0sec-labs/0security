import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const airgap = join(dirname(fileURLToPath(import.meta.url)), "airgap");
const build = join(airgap, "build-bundle.sh");
const install = join(airgap, "install-bundle.sh");

// A fake release served by a curl stub, so no network is used.
function release({ corrupt = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "0-airgap-test-"));
  const served = join(root, "served");
  const tools = join(root, "tools");
  mkdirSync(served); mkdirSync(tools);
  const binary = '#!/bin/sh\nprintf "installed\\n"\n';
  writeFileSync(join(served, "0security-linux-x64"), binary);
  const digest = corrupt ? "0".repeat(64) : createHash("sha256").update(binary).digest("hex");
  writeFileSync(join(served, "checksums.txt"), `${digest}  0security-linux-x64\n`);
  writeFileSync(join(tools, "curl"), `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in -o) shift; dest="$1" ;; http*) asset="\${1##*/}" ;; esac
  shift
done
cp "${served}/$asset" "$dest" 2>/dev/null || exit 22
`, { mode: 0o755 });
  const env = { ...process.env, HOME: join(root, "home"), PATH: `${tools}:${process.env.PATH}` };
  mkdirSync(env.HOME);
  return { root, env };
}

function buildBundle(env, out, extra = []) {
  return spawnSync("sh", [build, "--version", "0.44.0", "--out", out, "--allow-unsigned", ...extra], { env, encoding: "utf8" });
}

test("the bundle holds the binary, checksums, a manifest and the installer", () => {
  const { root, env } = release();
  try {
    const out = join(root, "bundle");
    const built = buildBundle(env, out);
    assert.equal(built.status, 0, built.stderr);
    assert.deepEqual(readdirSync(out).sort(), ["0security-linux-x64", "BINARY", "MANIFEST.sha256", "VERSION", "checksums.txt", "install-bundle.sh"].sort());
    assert.match(readFileSync(join(out, "MANIFEST.sha256"), "utf8"), /^[0-9a-f]{64} {2}0security-linux-x64$/m);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a checksum mismatch stops the build, and an unsigned release needs --allow-unsigned", () => {
  const bad = release({ corrupt: true });
  try {
    const built = buildBundle(bad.env, join(bad.root, "bundle"));
    assert.notEqual(built.status, 0);
    assert.match(built.stderr, /checksum mismatch/);
  } finally { rmSync(bad.root, { recursive: true, force: true }); }
  const { root, env } = release();
  try {
    const built = spawnSync("sh", [build, "--version", "0.44.0", "--out", join(root, "bundle")], { env, encoding: "utf8" });
    assert.notEqual(built.status, 0);
    assert.match(built.stderr, /cosign is required|no signature bundle/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the offline installer verifies the manifest, installs and links 0", () => {
  const { root, env } = release();
  try {
    const out = join(root, "bundle");
    assert.equal(buildBundle(env, out).status, 0);
    const installDir = join(root, "bin");
    const ran = spawnSync("sh", [join(out, "install-bundle.sh")], { env: { ...env, INSTALL_DIR: installDir }, encoding: "utf8" });
    assert.equal(ran.status, 0, ran.stderr);
    assert.match(ran.stderr, /ZERO_NO_EGRESS=1/);
    assert.equal(spawnSync(join(installDir, "0security"), { encoding: "utf8" }).stdout.trim(), "installed");
    assert.equal(lstatSync(join(installDir, "0")).isSymbolicLink(), true);
    assert.equal(readlinkSync(join(installDir, "0")), "0security");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the offline installer refuses a changed file and an extra file", () => {
  const { root, env } = release();
  try {
    const out = join(root, "bundle");
    assert.equal(buildBundle(env, out).status, 0);
    const installDir = join(root, "bin");
    writeFileSync(join(out, "0security-linux-x64"), '#!/bin/sh\necho tampered\n');
    const changed = spawnSync("sh", [join(out, "install-bundle.sh")], { env: { ...env, INSTALL_DIR: installDir }, encoding: "utf8" });
    assert.notEqual(changed.status, 0);
    assert.match(changed.stderr, /checksum mismatch/);
    assert.equal(existsSync(join(installDir, "0security")), false);

    const again = join(root, "bundle2");
    assert.equal(buildBundle(env, again).status, 0);
    writeFileSync(join(again, "extra.sh"), "echo hi\n");
    const extra = spawnSync("sh", [join(again, "install-bundle.sh")], { env: { ...env, INSTALL_DIR: installDir }, encoding: "utf8" });
    assert.notEqual(extra.status, 0);
    assert.match(extra.stderr, /not in the manifest/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the offline installer contains no network command", () => {
  const text = readFileSync(install, "utf8").replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(text, /\b(curl|wget|ssh|scp|gh|nc)\b/);
});
