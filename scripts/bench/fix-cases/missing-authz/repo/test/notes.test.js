import assert from "node:assert/strict";
import test from "node:test";
import { NoteStore } from "../src/notes.js";

const alice = { id: "alice", role: "user" };
const admin = { id: "root", role: "admin" };

test("an owner reads their own note", () => {
  const store = new NoteStore();
  const id = store.create(alice, "buy milk");
  assert.equal(store.get(alice, id).text, "buy milk");
});

test("an owner deletes their own note", () => {
  const store = new NoteStore();
  const id = store.create(alice, "x");
  store.remove(alice, id);
  assert.throws(() => store.get(alice, id));
});

test("an admin can read any note", () => {
  const store = new NoteStore();
  const id = store.create(alice, "private");
  assert.equal(store.get(admin, id).text, "private");
});

test("list returns only your notes", () => {
  const store = new NoteStore();
  store.create(alice, "a");
  store.create(admin, "b");
  assert.deepEqual(store.list(alice).map(n => n.text), ["a"]);
});

test("a missing note throws", () => {
  assert.throws(() => new NoteStore().get(alice, 99));
});
