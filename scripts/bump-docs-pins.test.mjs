import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { bump, digestPins, findStale, findStaleDigests, rewrite } from "./bump-docs-pins.mjs";

const fixture = (version, doc) => {
  const root = mkdtempSync(join(tmpdir(), "pins-"));
  mkdirSync(join(root, "packages/cli"), { recursive: true });
  mkdirSync(join(root, "docs/src/content/docs"), { recursive: true });
  writeFileSync(join(root, "packages/cli/package.json"), JSON.stringify({ version }));
  writeFileSync(join(root, "docs/src/content/docs/a.md"), doc);
  writeFileSync(join(root, "docs/src/content/docs/changelog.md"), "ghcr.io/0sec-labs/0security:v0.1.0\n");
  return root;
};

test("rewrite moves image, minor-tag, compose and action pins and leaves latest alone", () => {
  const text = "0sec-labs/0security:v0.36.0\n0sec-labs/0security:0.36\nZERO_IMAGE_TAG=v0.30.1\n  version: v0.36.0 # Pin the CLI release\n0sec-labs/0security:latest\nversion: 1.2.3\n";
  assert.equal(rewrite(text, "0.37.0"), "0sec-labs/0security:v0.37.0\n0sec-labs/0security:0.37\nZERO_IMAGE_TAG=v0.37.0\n  version: v0.37.0 # Pin the CLI release\n0sec-labs/0security:latest\nversion: 1.2.3\n");
});

test("findStale reports lagging pins and bump clears them; the changelog is exempt", () => {
  const root = fixture("0.37.0", "ghcr.io/0sec-labs/0security:v0.36.0\n");
  assert.equal(findStale(root).length, 1);
  assert.deepEqual(bump(root, "0.37.0"), ["docs/src/content/docs/a.md"]);
  assert.deepEqual(findStale(root), []);
  assert.match(readFileSync(join(root, "docs/src/content/docs/a.md"), "utf8"), /v0\.37\.0/);
});

test("bump rewrites pinned script digests from the working tree; findStaleDigests compares with the file at the tag", () => {
  const root = fixture("0.37.0", "VERSION=0.37.0 # Pin the CLI\n  fetch install.sh " + "a".repeat(64) + "\n");
  writeFileSync(join(root, "install.sh"), "echo hi\n");
  const digest = createHash("sha256").update("echo hi\n").digest("hex");
  assert.equal(digestPins(readFileSync(join(root, "docs/src/content/docs/a.md"), "utf8"))[0].version, "0.37.0");
  assert.equal(findStaleDigests(root).length, 1);
  bump(root, "0.37.0");
  assert.match(readFileSync(join(root, "docs/src/content/docs/a.md"), "utf8"), new RegExp(`fetch install.sh ${digest}`));
  assert.deepEqual(findStaleDigests(root), []);
  // A pin for a tag that is neither this release nor in git cannot be checked, which counts as a failure.
  writeFileSync(join(root, "docs/src/content/docs/a.md"), "VERSION=0.30.0\nfetch install.sh " + digest + "\n");
  assert.match(findStaleDigests(root)[0], /tag v0\.30\.0 not available/);
});
