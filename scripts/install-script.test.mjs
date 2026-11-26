import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

// `names` are the assets the release (or mirror) serves; `listed` are the names in checksums.txt.
function fixture(corrupt = false, names = ["0security-linux-arm64", "0-linux-arm64"], listed = names) {
  const root = mkdtempSync(join(tmpdir(), "0-install-test-"));
  const tools = join(root, "tools");
  const home = join(root, "home with ' quote");
  mkdirSync(tools); mkdirSync(home);
  const binary = '#!/bin/sh\nprintf "installed\\n"\n';
  for (const name of names) writeFileSync(join(root, name), binary);
  const digest = corrupt ? "0".repeat(64) : createHash("sha256").update(binary).digest("hex");
  writeFileSync(join(root, "checksums.txt"), listed.map((name) => `${digest}  ${name}\n`).join(""));
  writeFileSync(join(tools, "uname"), '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo aarch64;; esac\n', { mode: 0o755 });
  writeFileSync(join(tools, "curl"), `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; dest="$1" ;;
    https:*) asset="\${1##*/}" ;;
  esac
  shift
done
echo "$asset" >> "$FIXTURE/curl.log"
cp "$FIXTURE/$asset" "$dest" 2>/dev/null || exit 22
`, { mode: 0o755 });
  // Default gh stub: not logged in, so the attestation step falls back deterministically.
  writeFileSync(join(tools, "gh"), '#!/bin/sh\nif [ "$1" = auth ]; then exit "${GH_AUTH_EXIT:-1}"; fi\nif [ "$1" = attestation ] && [ "$2" = --help ]; then exit "${GH_ATTESTATION_HELP_EXIT:-0}"; fi\nif [ "$1" = attestation ]; then echo "$*" >> "$FIXTURE/gh.log"; [ "${GH_VERIFY_EXIT:-0}" = 0 ] || echo "gh: HTTP 404: Not Found" >&2; exit "${GH_VERIFY_EXIT:-0}"; fi\nexit 1\n', { mode: 0o755 });
  // cosign stub: records its arguments; COSIGN_EXIT controls the verdict. A missing one is simulated with NO_COSIGN.
  writeFileSync(join(tools, "cosign"), '#!/bin/sh\necho "$*" >> "$FIXTURE/cosign.log"\nexit "${COSIGN_EXIT:-0}"\n', { mode: 0o755 });
  const env = { ...process.env, HOME: home, SHELL: "/bin/bash", PATH: `${tools}:${process.env.PATH}`, FIXTURE: root, INSTALL_FOXGUARD: "0", INSTALL_SIGNATURE: "0" };
  delete env.INSTALL_DIR;
  return { root, home, env };
}
test("installer makes fresh shells usable, quotes paths, and does not duplicate profile entries", () => {
  const { root, home, env } = fixture();
  try {
    for (let i = 0; i < 2; i++) {
      const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
      assert.equal(installed.status, 0, installed.stderr);
    }
    for (const profile of [".profile", ".bashrc"]) {
      const text = readFileSync(join(home, profile), "utf8");
      assert.equal(text.match(/# 0.security CLI/g).length, 1);
      const shell = spawnSync("bash", ["-c", `. "$HOME/${profile}"; 0security --help`], { env, encoding: "utf8" });
      assert.equal(shell.status, 0, shell.stderr);
      assert.equal(shell.stdout.trim(), "installed");
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("checksum failure does not install a binary or modify shell startup", () => {
  const { root, home, env } = fixture(true);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.match(installed.stderr, /checksum mismatch/);
    assert.equal(existsSync(join(home, ".0", "bin", "0")), false);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), false);
    assert.equal(existsSync(join(home, ".profile")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("without a logged-in gh the installer falls back to checksums.txt and says so", () => {
  const { root, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /attestation was not verified/);
    assert.equal(existsSync(join(root, "gh.log")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a verified attestation is accepted and checked against this repository", () => {
  const { root, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, GH_AUTH_EXIT: "0" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /attestation verified/);
    assert.match(readFileSync(join(root, "gh.log"), "utf8"), /attestation verify .* --repo 0sec-labs\/0security/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a failed attestation blocks the install unless explicitly skipped", () => {
  const { root, home, env } = fixture();
  try {
    const failing = { ...env, GH_AUTH_EXIT: "0", GH_VERIFY_EXIT: "1" };
    const blocked = spawnSync("bash", ["install.sh"], { env: failing, encoding: "utf8" });
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /could not verify the checksums.txt attestation/);
    assert.match(blocked.stderr, /HTTP 404: Not Found/, "gh's own error is shown");
    assert.equal(existsSync(join(home, ".0", "bin", "0")), false);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), false);
    const skipped = spawnSync("bash", ["install.sh"], { env: { ...failing, INSTALL_ATTESTATION: "0" }, encoding: "utf8" });
    assert.equal(skipped.status, 0, skipped.stderr);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("INSTALL_ATTESTATION=require fails when gh cannot verify", () => {
  const { root, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_ATTESTATION: "require" }, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.match(installed.stderr, /requires?|needs an authenticated/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a logged-in gh without the attestation subcommand is treated like a missing gh", () => {
  const { root, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, GH_AUTH_EXIT: "0", GH_ATTESTATION_HELP_EXIT: "1" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /too old for `gh attestation`/);
    assert.equal(existsSync(join(root, "gh.log")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("installs 0security and links 0 to it with a relative symlink", () => {
  const { root, home, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    const dir = join(home, ".0", "bin");
    assert.equal(lstatSync(join(dir, "0security")).isFile(), true);
    assert.equal(lstatSync(join(dir, "0")).isSymbolicLink(), true);
    assert.equal(readlinkSync(join(dir, "0")), "0security");
    assert.equal(realpathSync(join(dir, "0")), realpathSync(join(dir, "0security")));
    for (const name of ["0", "0security"]) {
      const run = spawnSync(join(dir, name), [], { encoding: "utf8" });
      assert.equal(run.stdout.trim(), "installed");
    }
    assert.match(installed.stderr, /0security to .*\/0security \(also available as .*\/0\)/);
    assert.deepEqual(readdirSync(dir).sort(), ["0", "0security"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("upgrading over an older plain 0 file replaces it with the symlink", () => {
  const { root, home, env } = fixture();
  try {
    const dir = join(home, ".0", "bin");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "0"), '#!/bin/sh\nprintf "old\\n"\n', { mode: 0o755 });
    assert.equal(spawnSync(join(dir, "0"), [], { encoding: "utf8" }).stdout.trim(), "old");
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.equal(lstatSync(join(dir, "0")).isSymbolicLink(), true);
    assert.equal(spawnSync(join(dir, "0"), [], { encoding: "utf8" }).stdout.trim(), "installed");
    assert.equal(spawnSync(join(dir, "0security"), [], { encoding: "utf8" }).stdout.trim(), "installed");
    // A second run over the new layout stays correct and leaves no temporary files.
    assert.equal(spawnSync("bash", ["install.sh"], { env, encoding: "utf8" }).status, 0);
    assert.deepEqual(readdirSync(dir).sort(), ["0", "0security"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a checksum failure leaves an older plain 0 file untouched", () => {
  const { root, home, env } = fixture(true);
  try {
    const dir = join(home, ".0", "bin");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "0"), '#!/bin/sh\nprintf "old\\n"\n', { mode: 0o755 });
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.equal(lstatSync(join(dir, "0")).isFile(), true);
    assert.equal(spawnSync(join(dir, "0"), [], { encoding: "utf8" }).stdout.trim(), "old");
    assert.deepEqual(readdirSync(dir), ["0"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

const downloaded = (root) => readFileSync(join(root, "curl.log"), "utf8").trim().split("\n").filter((n) => n !== "checksums.txt");
function assertInstalled(home) {
  const dir = join(home, ".0", "bin");
  assert.equal(lstatSync(join(dir, "0security")).isFile(), true);
  assert.equal(readlinkSync(join(dir, "0")), "0security");
  assert.equal(spawnSync(join(dir, "0"), [], { encoding: "utf8" }).stdout.trim(), "installed");
  assert.deepEqual(readdirSync(dir).sort(), ["0", "0security"]);
}
test("a release with the new asset name downloads only that asset", () => {
  const { root, home, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.deepEqual(downloaded(root), ["0security-linux-arm64"]);
    assertInstalled(home);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a release with only the old asset name falls back to it and verifies that name", () => {
  const { root, home, env } = fixture(false, ["0-linux-arm64"]);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.deepEqual(downloaded(root), ["0security-linux-arm64", "0-linux-arm64"]);
    assert.match(installed.stderr, /0security-linux-arm64 is not available in this release; downloading 0-linux-arm64/);
    assertInstalled(home);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a mirror that serves and lists only the old names installs", () => {
  const { root, home, env } = fixture(false, ["0-linux-arm64"], ["0-linux-arm64"]);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, RELEASE_BASE_URL: "https://mirror.example/releases/v0.43.0" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assertInstalled(home);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a fallback download is still checked against checksums.txt", () => {
  const { root, home, env } = fixture(true, ["0-linux-arm64"]);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.match(installed.stderr, /checksum mismatch for 0-linux-arm64/);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), false);
    assert.equal(existsSync(join(home, ".0", "bin", "0")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a new-name download with a checksum mismatch installs nothing and does not fall back", () => {
  const { root, home, env } = fixture(true);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.match(installed.stderr, /checksum mismatch for 0security-linux-arm64/);
    assert.deepEqual(downloaded(root), ["0security-linux-arm64"]);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a missing checksum entry for the downloaded name installs nothing", () => {
  const { root, home, env } = fixture(false, ["0security-linux-arm64"], ["0-linux-arm64"]);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.match(installed.stderr, /no entry for 0security-linux-arm64/);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a signature bundle is verified with cosign against the release workflow identity", () => {
  const { root, env } = fixture();
  try {
    writeFileSync(join(root, "checksums.txt.sigstore.json"), "{}");
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_SIGNATURE: "auto" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /signature verified/);
    const log = readFileSync(join(root, "cosign.log"), "utf8");
    assert.match(log, /verify-blob --bundle \S+ --certificate-identity-regexp \^https:\/\/github\\\.com\/0sec-labs\/0security\/\\\.github\/workflows\/release\\\.yml@refs/);
    assert.match(log, /--certificate-oidc-issuer https:\/\/token\.actions\.githubusercontent\.com/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a bad signature stops the install before any download", () => {
  const { root, home, env } = fixture();
  try {
    writeFileSync(join(root, "checksums.txt.sigstore.json"), "{}");
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_SIGNATURE: "auto", COSIGN_EXIT: "1" }, encoding: "utf8" });
    assert.notEqual(installed.status, 0);
    assert.match(installed.stderr, /could not verify the checksums\.txt signature/);
    assert.doesNotMatch(readFileSync(join(root, "curl.log"), "utf8"), /0security-linux-arm64/);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a release without a signature bundle installs with a note unless the signature is required", () => {
  const { root, env } = fixture();
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_SIGNATURE: "auto" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /no signature bundle/);
    const required = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_SIGNATURE: "require" }, encoding: "utf8" });
    assert.notEqual(required.status, 0);
    assert.match(required.stderr, /no checksums\.txt\.sigstore\.json/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("INSTALL_SIGNATURE=require fails without cosign, and 0 skips the check", () => {
  const { root, env } = fixture();
  try {
    const noCosign = { ...env, PATH: `${join(root, "tools-no-cosign")}:/usr/bin:/bin` };
    mkdirSync(join(root, "tools-no-cosign"));
    for (const name of ["uname", "curl", "gh"]) writeFileSync(join(root, "tools-no-cosign", name), readFileSync(join(root, "tools", name)), { mode: 0o755 });
    const required = spawnSync("bash", ["install.sh"], { env: { ...noCosign, INSTALL_SIGNATURE: "require" }, encoding: "utf8" });
    assert.notEqual(required.status, 0);
    assert.match(required.stderr, /needs cosign/);
    const skipped = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_SIGNATURE: "0" }, encoding: "utf8" });
    assert.equal(skipped.status, 0, skipped.stderr);
    assert.match(skipped.stderr, /Skipping signature check/);
    assert.equal(existsSync(join(root, "cosign.log")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

const withFoxguard = ["0security-linux-arm64", "0-linux-arm64", "foxguard-linux-arm64"];
test("Foxguard is installed next to 0 from the same checksums.txt unless opted out", () => {
  const { root, home, env } = fixture(false, withFoxguard);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_FOXGUARD: "1" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    const dir = join(home, ".0", "bin");
    assert.match(installed.stderr, /Installed verified Foxguard/);
    assert.equal(readFileSync(join(dir, "foxguard"), "utf8"), readFileSync(join(dir, "0security"), "utf8"));
    assert.ok(readFileSync(join(root, "curl.log"), "utf8").includes("foxguard-linux-arm64"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("INSTALL_FOXGUARD=0 does not download or install Foxguard", () => {
  const { root, home, env } = fixture(false, withFoxguard);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.equal(existsSync(join(home, ".0", "bin", "foxguard")), false);
    assert.ok(!readFileSync(join(root, "curl.log"), "utf8").includes("foxguard"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a Foxguard checksum mismatch keeps 0security installed and installs no Foxguard", () => {
  const { root, home, env } = fixture(false, withFoxguard);
  try {
    writeFileSync(join(root, "foxguard-linux-arm64"), "tampered\n");
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_FOXGUARD: "1" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /foxguard-linux-arm64 checksum mismatch/);
    assert.equal(existsSync(join(home, ".0", "bin", "foxguard")), false);
    assert.equal(existsSync(join(home, ".0", "bin", "0security")), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("a release without a Foxguard entry installs 0security and says so", () => {
  const { root, home, env } = fixture(false, ["0security-linux-arm64", "0-linux-arm64"]);
  try {
    const installed = spawnSync("bash", ["install.sh"], { env: { ...env, INSTALL_FOXGUARD: "1" }, encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.match(installed.stderr, /lists no foxguard-linux-arm64/);
    assert.equal(existsSync(join(home, ".0", "bin", "foxguard")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
