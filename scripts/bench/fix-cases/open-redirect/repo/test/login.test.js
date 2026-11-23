import assert from "node:assert/strict";
import test from "node:test";
import { loginResponse, redirectAfterLogin } from "../src/login.js";

test("goes to the home page without a next parameter", () => {
  assert.equal(redirectAfterLogin(undefined), "/");
  assert.equal(redirectAfterLogin(""), "/");
});

test("keeps a local path", () => {
  assert.equal(redirectAfterLogin("/dashboard"), "/dashboard");
  assert.equal(redirectAfterLogin("/settings/profile?tab=keys"), "/settings/profile?tab=keys");
});

test("builds a 302 with a Location header", () => {
  const res = loginResponse("/reports");
  assert.equal(res.status, 302);
  assert.equal(res.headers.Location, "/reports");
});
