#!/usr/bin/env node
// Native-process qualification: real HTTP access controls and online SQLite backup/restore.
// Uses disposable synthetic findings; no model calls, cloud deployment, mock server or license bypass.
// After building engine, enterprise, CLI and web: node scripts/qualification-enterprise-local.mjs [--receipt] [receipt.json]
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, writeFile, copyFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DatabaseSync, backup } from "node:sqlite";

const args = process.argv.slice(2);
const receiptFile = args[0] === "--receipt" ? args[1] : args[0];
if (args[0] === "--receipt" ? args.length !== 2 || !receiptFile : args.length > 1 || receiptFile?.startsWith("-")) {
  throw new Error("Usage: node scripts/qualification-enterprise-local.mjs [--receipt] [receipt.json]");
}
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { osecDB } = await import(pathToFileURL(join(repo, "packages/engine/dist/storage/index.js")));
const directory = await mkdtemp(join(tmpdir(), "zero-enterprise-local-"));
const workspace = join(directory, "workspace");
await mkdir(workspace);
const registry = join(directory, "engines.json");
await writeFile(registry, JSON.stringify({ schemaVersion: 1, engines: [] }));
const database = join(directory, "source.db");
const backupPath = join(directory, "backup.db");
const restoredPath = join(directory, "restored.db");
const scanId = randomUUID();
const findingId = randomUUID();
const token = randomUUID() + randomUUID();
const env = { ...process.env, ZERO_ACCESS_TOKEN: token, ZERO_QUALIFICATION_ENGINE_KEY: randomUUID(), ZERO_ALLOWED_HOSTS: "localhost,127.0.0.1", DO_NOT_TRACK: "1", ZERO_DISABLE_MEMORY: "1", ZERO_TEAM_CONFIG: "" };
const receipt = { schemaVersion: 1, startedAt: new Date().toISOString(), runtime: process.version, checks: [], scope: "Native local process, synthetic retained finding, real SQLite backup. No model, container, cloud, Bitbucket or real IdP qualification." };
let child;
const wait = ms => new Promise(resolveWait => setTimeout(resolveWait, ms));
async function stop() {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGINT");
  const deadline = Date.now() + 8000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) await wait(50);
  if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); await new Promise(done => child.once("exit", done)); }
}
async function start(path) {
  let output = "";
  child = spawn(process.execPath, [join(repo, "packages/cli/dist/index.js"), "--server-mode", "--host", "127.0.0.1", "--port", "0", "--db-path", path, "--engine-workspace", workspace, "--engine-token-env", "ZERO_QUALIFICATION_ENGINE_KEY", "--engines-config", registry, "--asset-dir", join(repo, "packages/web/dist"), "--no-open", "--ready-json"], { cwd: workspace, env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", bytes => { output = (output + bytes.toString()).slice(-32000); });
  child.stderr.on("data", bytes => { output = (output + bytes.toString()).slice(-32000); });
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Qualification server exited before readiness: ${output.replaceAll(token, "[redacted]")}`);
    const match = /ZERO_DASHBOARD_READY (\{[^\n]+\})/.exec(output);
    if (match) { assert.ok(!output.includes(token), "access token leaked to stdout"); return new URL(JSON.parse(match[1]).url); }
    await wait(50);
  }
  throw new Error("Qualification server readiness timed out.");
}
async function runSmoke(port) {
  await new Promise((done, reject) => {
    const smoke = spawn(process.execPath, [join(repo, "scripts/smoke-server-mode.mjs"), "--port", port, "--host-name", "localhost", "--wait-seconds", "10"], { env, stdio: ["ignore", "inherit", "inherit"] });
    smoke.once("error", reject);
    smoke.once("exit", code => code === 0 ? done() : reject(new Error(`Server HTTP smoke exited ${code}.`)));
  });
}
function retainedFinding(path) {
  const db = new osecDB(path);
  try { assert.ok(db.getFindings(scanId).some(row => row.id === findingId), "retained finding missing after restore"); }
  finally { db.close(); }
}
async function retainedFindingOverHttp(url) {
  const origin = url.origin;
  const login = await fetch(`${origin}/_access/login`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json", Connection: "close" }, body: JSON.stringify({ token }), signal: AbortSignal.timeout(10000) });
  assert.equal(login.status, 200);
  const cookie = login.headers.getSetCookie()[0].split(";")[0];
  const page = await (await fetch(origin, { headers: { Cookie: cookie, Connection: "close" }, signal: AbortSignal.timeout(10000) })).text();
  const control = /name="0-control-token" content="([^"]+)"/.exec(page)?.[1];
  assert.ok(control);
  const response = await fetch(`${origin}/api/scans/${scanId}/export?format=json`, { headers: { Cookie: cookie, Origin: origin, "X-0-Control-Token": control, Connection: "close" }, signal: AbortSignal.timeout(10000) });
  assert.equal(response.status, 200);
  assert.ok((await response.text()).includes(findingId), "restored finding missing from authenticated HTTP report export");
}
try {
  const db = new osecDB(database);
  try {
    db.createScan({ target: "disposable-qualification", depth: "quick", format: "json" }, scanId);
    db.saveFinding(scanId, { id: findingId, templateId: "qualification", title: "Synthetic restore qualification finding", description: "Known disposable data for retention checks.", severity: "high", category: "path-traversal", status: "verified", timestamp: Date.now(), evidence: { request: "synthetic", response: "synthetic" } });
  } finally { db.close(); }
  const source = await start(database);
  await runSmoke(source.port);
  receipt.checks.push("native-server-http-auth-csrf-host-health");
  const live = new DatabaseSync(database, { readOnly: true });
  try { await backup(live, backupPath); } finally { live.close(); }
  const snapshot = new DatabaseSync(backupPath, { readOnly: true });
  try { assert.equal(snapshot.prepare("PRAGMA integrity_check").get().integrity_check, "ok"); }
  finally { snapshot.close(); }
  retainedFinding(backupPath);
  receipt.checks.push("online-backup-while-server-running-integrity-and-finding-retained");
  await stop();
  await copyFile(backupPath, restoredPath);
  const restored = await start(restoredPath);
  await runSmoke(restored.port);
  retainedFinding(restoredPath);
  await retainedFindingOverHttp(restored);
  receipt.checks.push("restored-database-native-server-restart-auth-and-finding-retained");
  receipt.checks.push("authenticated-http-report-export-retains-restored-finding");
  receipt.completedAt = new Date().toISOString();
  receipt.outcome = "passed";
  if (receiptFile) await writeFile(resolve(receiptFile), JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
  console.log(JSON.stringify(receipt));
} finally { await stop(); await rm(directory, { recursive: true, force: true }); }
