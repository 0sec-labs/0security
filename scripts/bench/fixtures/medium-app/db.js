const sqlite3 = require("sqlite3");
const { DB_FILE } = require("./config");

const db = new sqlite3.Database(DB_FILE);

function all(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows))));
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row))));
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function done(err) { return err ? reject(err) : resolve(this); }));
}

module.exports = { db, all, get, run };
