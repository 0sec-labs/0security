import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { hasUpload, readUpload } from "../src/uploads.js";

function uploads() {
  const root = mkdtempSync(join(tmpdir(), "uploads-"));
  writeFileSync(join(root, "a.txt"), "hello");
  mkdirSync(join(root, "sub"));
  writeFileSync(join(root, "sub", "b.txt"), "nested");
  return root;
}

test("reads a file in the uploads folder", () => {
  assert.equal(readUpload(uploads(), "a.txt"), "hello");
});

test("reads a file in a sub-folder", () => {
  assert.equal(readUpload(uploads(), "sub/b.txt"), "nested");
});

test("a missing file throws", () => {
  assert.throws(() => readUpload(uploads(), "missing.txt"));
});

test("hasUpload reports presence", () => {
  const root = uploads();
  assert.equal(hasUpload(root, "a.txt"), true);
  assert.equal(hasUpload(root, "nope.txt"), false);
});
