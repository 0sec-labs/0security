// Look up users for the admin search box.
export function findUsersByName(db, name) {
  return db.prepare("SELECT id, name, email FROM users WHERE name = ?").all(String(name));
}

export function countUsers(db) {
  return db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
}
