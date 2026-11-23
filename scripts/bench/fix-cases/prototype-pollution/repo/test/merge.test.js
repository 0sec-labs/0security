import assert from "node:assert/strict";
import test from "node:test";
import { merge, withDefaults } from "../src/merge.js";

test("merges nested objects", () => {
  assert.deepEqual(merge({ a: { b: 1, c: 2 } }, { a: { c: 3, d: 4 } }), { a: { b: 1, c: 3, d: 4 } });
});

test("arrays are replaced, not merged", () => {
  assert.deepEqual(merge({ a: [1, 2] }, { a: [3] }), { a: [3] });
});

test("applies defaults", () => {
  assert.deepEqual(withDefaults({ nested: { verbose: true } }), { retries: 3, nested: { verbose: true } });
});

test("keys that look like normal names still merge", () => {
  assert.equal(merge({}, { constructorName: "x", protoType: { y: 1 } }).protoType.y, 1);
});
