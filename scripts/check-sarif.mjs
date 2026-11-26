#!/usr/bin/env node
// Check a SARIF file against what viewers and GitHub code scanning need, offline.
//   node scripts/check-sarif.mjs <file.sarif>...
// Exit 1 when a file breaks the SARIF 2.1.0 spec; warnings alone exit 0. Needs the engine built.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const engine = join(dirname(fileURLToPath(import.meta.url)), "../packages/engine/dist/report-formatters/sarif-consumer-check.js");
const files = process.argv.slice(2);
if (!files.length) { console.error("usage: node scripts/check-sarif.mjs <file.sarif>..."); process.exit(2); }
const { checkSarifForConsumers } = await import(pathToFileURL(engine).href).catch(() => { console.error(`${engine} not found: run pnpm --filter @0/engine build`); process.exit(2); });
// Messages quote strings from the file under test: show control and bidirectional-text characters as escapes so a crafted file cannot rewrite the terminal.
const safe = (text) => String(text).replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
let failed = false;
for (const file of files) {
  const report = checkSarifForConsumers(JSON.parse(readFileSync(file, "utf8")));
  console.log(`${safe(file)}: ${report.results} results, ${report.rules} rules, ${report.errors.length} errors, ${report.warnings.length} warnings`);
  for (const e of report.errors) console.log(`  error: ${safe(e)}`);
  for (const w of report.warnings.slice(0, 20)) console.log(`  warning: ${safe(w)}`);
  if (report.warnings.length > 20) console.log(`  ... ${report.warnings.length - 20} more warnings`);
  if (report.errors.length) failed = true;
}
process.exit(failed ? 1 : 0);
