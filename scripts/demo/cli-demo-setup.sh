#!/usr/bin/env bash
# Creates the small vulnerable demo app used by cli-demo.sh.
# Usage: cli-demo-setup.sh <empty-directory>
set -euo pipefail
dir="${1:?usage: cli-demo-setup.sh <empty-directory>}"
mkdir -p "$dir"
cd "$dir"

cat > package.json <<'JSON'
{
  "name": "demo-orders-api",
  "version": "1.0.0",
  "private": true,
  "main": "server.js",
  "scripts": { "test": "node --test" },
  "dependencies": { "express": "^4.19.2", "better-sqlite3": "^11.0.0" }
}
JSON

cat > format.js <<'JS'
// Pure helper, used by the tests.
function formatOrder(row) {
  return `#${row.id} ${row.item} x${row.qty}`;
}
module.exports = { formatOrder };
JS

cat > format.test.js <<'JS'
const test = require('node:test');
const assert = require('node:assert');
const { formatOrder } = require('./format');

test('formatOrder prints id, item and quantity', () => {
  assert.strictEqual(formatOrder({ id: 7, item: 'tea', qty: 2 }), '#7 tea x2');
});
JS

cat > server.js <<'JS'
const express = require('express');
const Database = require('better-sqlite3');
const { formatOrder } = require('./format');

const app = express();
const db = new Database('orders.db');
const API_TOKEN = 'k3Jx9Qw2LpZ8vR5tYb7NcM4dHs6FgA1e';

app.use((req, res, next) => {
  if (req.headers['x-api-token'] !== API_TOKEN) return res.status(401).end();
  next();
});

// Look up orders for a customer.
app.get('/orders', (req, res) => {
  const rows = db
    .prepare("SELECT * FROM orders WHERE customer = '" + req.query.customer + "'")
    .all();
  res.json(rows.map(formatOrder));
});

// Pricing rules, evaluated from the request.
app.get('/price', (req, res) => {
  const total = eval(req.query.formula);
  res.json({ total });
});

app.listen(3000);
JS

printf 'node_modules\norders.db\n' > .gitignore
git init -q
git config user.name "Demo"
git config user.email "demo@example.com"
git add -A
git commit -q -m "Initial commit: orders API"
