const { get, run } = require("../db");
const { hashPassword } = require("../lib/crypto");

async function create(email, password) {
  const result = await run("INSERT INTO users(email, password_hash, role) VALUES(?, ?, 'customer')", [email, hashPassword(password)]);
  return { id: result.lastID };
}

async function verify(email, password) {
  const user = await get("SELECT id, role, password_hash FROM users WHERE email = ?", [email]);
  return user && user.password_hash === hashPassword(password) ? user : undefined;
}

module.exports = { create, verify };
