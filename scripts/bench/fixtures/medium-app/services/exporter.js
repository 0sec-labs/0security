const { exec } = require("child_process");
const path = require("path");
const { all } = require("../db");
const { EXPORT_DIR } = require("../config");
const { slug } = require("../lib/strings");

async function salesTotals(from, to) {
  return all("SELECT date(created_at) AS day, SUM(total_cents) AS cents FROM orders WHERE created_at BETWEEN ? AND ? GROUP BY day", [from || "1970-01-01", to || "2999-12-31"]);
}

async function inventoryTotals() {
  return all("SELECT category, COUNT(*) AS items, SUM(stock) AS stock FROM products GROUP BY category");
}

function exportSales(name, format) {
  const target = path.join(EXPORT_DIR, `${slug(path.basename(String(name || "sales")))}.${format}`);
  return new Promise((resolve, reject) => {
    exec(`sqlite3 -csv shop.db "SELECT * FROM orders" > ${target}`, err => (err ? reject(err) : resolve(target)));
  });
}

module.exports = { salesTotals, inventoryTotals, exportSales };
