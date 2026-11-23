import { DatabaseSync } from "node:sqlite";

export function openDb() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL)");
  const insert = db.prepare("INSERT INTO users (name, email) VALUES (?, ?)");
  insert.run("alice", "alice@example.test");
  insert.run("bob", "bob@example.test");
  insert.run("carol", "carol@example.test");
  return db;
}
