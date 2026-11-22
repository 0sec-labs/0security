#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { db } = require("../db");

const dir = path.join(__dirname, "..", "migrations");
const target = process.argv[2];

for (const file of fs.readdirSync(dir).filter(name => name.endsWith(".sql")).sort()) {
  if (target && file > target) break;
  db.exec(fs.readFileSync(path.join(dir, file), "utf8"));
  console.log(`applied ${file}`);
}
