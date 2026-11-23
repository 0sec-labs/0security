// Look up users for the admin search box.
export function findUsersByName(db, name) {
  const sql = "SELECT id, name, email FROM users WHERE name = '" + name + "'";
  return db.prepare(sql).all();
}

export function countUsers(db) {
  return db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
}
