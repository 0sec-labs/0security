import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { countLines } from "../src/lines.js";

function sample(name, text) {
  const dir = mkdtempSync(join(tmpdir(), "lines-"));
  const file = join(dir, name);
  writeFileSync(file, text);
  return file;
}

test("counts the lines of a file", () => {
  assert.equal(countLines(sample("a.txt", "one\ntwo\nthree\n")), 3);
});

test("counts an empty file as zero", () => {
  assert.equal(countLines(sample("empty.txt", "")), 0);
});

test("counts a two-line file", () => {
  assert.equal(countLines(sample("tail.txt", "x\ny\n")), 2);
});
