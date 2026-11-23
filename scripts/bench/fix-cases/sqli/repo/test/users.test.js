import assert from "node:assert/strict";
import test from "node:test";
import { openDb } from "../src/db.js";
import { countUsers, findUsersByName } from "../src/users.js";

test("finds a user by exact name", () => {
  const rows = findUsersByName(openDb(), "alice");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].email, "alice@example.test");
});

test("returns nothing for an unknown name", () => {
  assert.deepEqual(findUsersByName(openDb(), "nobody"), []);
});

test("a name is matched exactly, not by prefix", () => {
  assert.deepEqual(findUsersByName(openDb(), "ali"), []);
});

test("counts users", () => {
  assert.equal(countUsers(openDb()), 3);
});
