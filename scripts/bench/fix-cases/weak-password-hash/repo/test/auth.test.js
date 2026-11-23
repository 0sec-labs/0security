import assert from "node:assert/strict";
import test from "node:test";
import { hashPassword, verifyPassword } from "../src/auth.js";

test("a password verifies against its own hash", () => {
  const stored = hashPassword("correct horse battery staple");
  assert.equal(verifyPassword("correct horse battery staple", stored), true);
});

test("a wrong password does not verify", () => {
  const stored = hashPassword("correct horse battery staple");
  assert.equal(verifyPassword("wrong", stored), false);
});

test("the stored value is a non-empty string", () => {
  assert.equal(typeof hashPassword("x"), "string");
  assert.ok(hashPassword("x").length > 0);
});
