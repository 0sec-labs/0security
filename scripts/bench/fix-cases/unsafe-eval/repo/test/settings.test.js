import assert from "node:assert/strict";
import test from "node:test";
import { parseSettings, theme } from "../src/settings.js";

test("parses a JSON settings document", () => {
  const s = parseSettings('{"theme": "dark", "tabs": [1, 2, 3], "editor": {"wrap": true}}');
  assert.equal(theme(s), "dark");
  assert.deepEqual(s.tabs, [1, 2, 3]);
  assert.equal(s.editor.wrap, true);
});

test("theme defaults to light", () => {
  assert.equal(theme(parseSettings("{}")), "light");
});

test("invalid JSON throws", () => {
  assert.throws(() => parseSettings("{not json"));
});
