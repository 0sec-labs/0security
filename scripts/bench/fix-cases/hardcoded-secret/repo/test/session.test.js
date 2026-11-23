import assert from "node:assert/strict";
import test from "node:test";

// The deployment provides the signing key in the environment.
process.env.SESSION_SECRET = "test-only-secret-for-unit-tests";
const { signSession, verifySession } = await import("../src/session.js");

test("a signed session verifies", () => {
  assert.equal(verifySession(signSession("user-1")), "user-1");
});

test("a tampered session does not verify", () => {
  const token = signSession("user-1");
  assert.equal(verifySession(`user-2${token.slice(token.indexOf("."))}`), null);
});

test("a malformed token does not verify", () => {
  assert.equal(verifySession("nodot"), null);
});
