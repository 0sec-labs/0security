/**
 * `0 findings rollup`: counts findings across repositories from export files and findings databases you name.
 * It reads local files only and sends nothing anywhere. Finding evidence never enters an export.
 */
import { closeSync, openSync, readFileSync, readSync, statSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { Option, type Command } from "commander";
import { effectiveTriageStatus } from "@0/engine/shared";
import { osecDB } from "@0/engine/storage";
import { findingDatabasePaths } from "../finding-focus.js";
import { finishWithError, UsageError } from "./output.js";
import { applyOwners, buildExport, parseExport, renderHtml, renderText, type RollupRow } from "./findings-rollup-core.js";

import { HISTORY_SCHEMA, buildRollupReport, labelSnapshot, labelsSchema, latestSnapshotRows, parseHistory, rollupCsv, trendText, type RollupSnapshot } from "./findings-rollup-history.js";

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const MAX_DB_ROWS = 100_000;
const SQLITE_MAGIC = "SQLite format 3\u0000";

export interface FindingsRollupOptions { export?: string; owners?: string; repository?: string; format?: string; output?: string; labels?: string; history?: string }
export interface FindingsRollupDeps {
  now(): Date;
  /** Databases to read when no input is named. */
  defaultDatabases(): string[];
  out(text: string): void;
  err(text: string): void;
  writeFile(path: string, text: string): void;
}
const defaults: FindingsRollupDeps = {
  now: () => new Date(),
  defaultDatabases: () => findingDatabasePaths(),
  out: text => process.stdout.write(`${text}\n`),
  err: text => process.stderr.write(`${text}\n`),
  writeFile: (path, text) => writeFileSync(path, text, { mode: 0o600 }),
};

function isDatabase(path: string): boolean {
  const fd = openSync(path, "r");
  try { const buffer = Buffer.alloc(16); readSync(fd, buffer, 0, 16, 0); return buffer.toString("latin1") === SQLITE_MAGIC; } finally { closeSync(fd); }
}

/** A scan target that is a local path becomes its folder name, so an export does not carry your directory layout. */
function repositoryName(target: string): string {
  const trimmed = target.trim();
  if (/^(\/|~|[A-Za-z]:[\\/]|\.)/.test(trimmed)) return basename(trimmed.replace(/[\\/]+$/, "")) || trimmed;
  return trimmed || "unknown";
}

export function rowsFromDatabase(path: string, repository?: string): RollupRow[] {
  const db = new osecDB(path);
  try {
    const targets = new Map<string, string>();
    const targetOf = (scanId: string): string => {
      let name = targets.get(scanId);
      if (name === undefined) { name = repository ?? repositoryName(db.getScan(scanId)?.target ?? ""); targets.set(scanId, name); }
      return name;
    };
    const findings = db.listFindings({ limit: MAX_DB_ROWS + 1 });
    if (findings.length > MAX_DB_ROWS) throw new UsageError(`Database exceeds ${MAX_DB_ROWS} findings; refusing to label a truncated result as a complete snapshot.`);
    return findings.map((f): RollupRow => {
      const at = new Date(f.timestamp).toISOString();
      return {
        repository: targetOf(f.scanId), fingerprint: f.fingerprint || f.id, title: f.title.slice(0, 300), severity: f.severity.toLowerCase(), category: f.category,
        status: f.status, triage: effectiveTriageStatus(f), owner: f.workflowAssignee?.trim() ? f.workflowAssignee.trim().slice(0, 100) : null, firstSeen: at, lastSeen: at,
      };
    });
  } finally { db.close(); }
}

function readInput(path: string, repository: string | undefined, now: Date): RollupSnapshot[] {
  const full = resolve(path);
  let stat;
  try { stat = statSync(full); } catch { throw new UsageError(`${path} does not exist.`); }
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new UsageError(`${path} must be a file of at most 100 MB.`);
  if (isDatabase(full)) return [{ ...buildExport(rowsFromDatabase(full, repository), now, repository ? [repository] : undefined), source: basename(path) }];
  const text = readFileSync(full, "utf8");
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new UsageError(`${path} is not JSON.`); }
  if (value && typeof value === "object" && (value as { schema?: string }).schema === HISTORY_SCHEMA) return parseHistory(value);
  return [{ ...parseExport(text, path), source: basename(path) }];
}

function readOwners(path: string): Record<string, string> {
  let value: unknown;
  try { value = JSON.parse(readFileSync(resolve(path), "utf8")); } catch { throw new UsageError(`--owners must name a JSON file that maps repository names to owners, such as {"api": "payments"}.`); }
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.values(value).some(v => typeof v !== "string")) throw new UsageError(`--owners must be a JSON object of repository name to owner name.`);
  return value as Record<string, string>;
}

export function runFindingsRollup(inputs: string[], options: FindingsRollupOptions, deps: FindingsRollupDeps = defaults): void {
  if (options.format !== undefined && !["text", "json", "html", "csv"].includes(options.format)) throw new UsageError("--format must be text, json, html or csv.");
  if (options.repository !== undefined && (!options.repository.trim() || options.repository.length > 200)) throw new UsageError("--repository must be 1 to 200 characters.");
  const owners = options.owners ? readOwners(options.owners) : undefined;
  let labels = {};
  if (options.labels) {
    try { labels = labelsSchema.parse(JSON.parse(readFileSync(resolve(options.labels), "utf8"))); }
    catch { throw new UsageError('--labels must name a JSON object mapping repositories to {"team":"name","tier":"name"}.'); }
  }
  const sources = inputs.length ? inputs : deps.defaultDatabases();
  const now = deps.now();
  let snapshots: RollupSnapshot[] = [];
  for (const source of sources) {
    try { snapshots.push(...readInput(source, options.repository, now)); } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new Error(`Could not read ${source}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (snapshots.length > 10_000 || snapshots.reduce((n, snapshot) => n + snapshot.findings.length, 0) > 200_000) throw new UsageError("Rollup history exceeds 10000 snapshots or 200000 finding rows.");
  snapshots = snapshots.map(snapshot => labelSnapshot({ ...snapshot, findings: owners ? applyOwners(snapshot.findings, owners) : snapshot.findings }, labels));
  const current = latestSnapshotRows(snapshots);
  if (options.export) {
    deps.writeFile(resolve(options.export), `${JSON.stringify(buildExport(current.rows, now, current.repositories), null, 2)}\n`);
    deps.err(`Wrote ${current.rows.length} finding${current.rows.length === 1 ? "" : "s"} to ${options.export}`);
  }
  if (options.history) {
    deps.writeFile(resolve(options.history), `${JSON.stringify({ schema: HISTORY_SCHEMA, snapshots }, null, 2)}\n`);
    deps.err(`Wrote ${snapshots.length} dated snapshots to ${options.history}`);
  }
  const report = buildRollupReport(snapshots, now);
  const format = options.format ?? "text";
  const escape = (value: string) => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
  const body = format === "json" ? `${JSON.stringify(report, null, 2)}\n` : format === "csv" ? rollupCsv(report)
    : format === "html" ? renderHtml(report).replace("</body>", `<h2>Snapshot trend</h2><pre style="white-space:pre-wrap">${escape(trendText(report))}</pre></body>`) : `${renderText(report)}\n${trendText(report)}\n`;
  if (options.output) { deps.writeFile(resolve(options.output), body); deps.err(`Wrote ${options.output}`); } else deps.out(body.replace(/\n$/, ""));
}

export function registerFindingsRollupCommand(parent: Command, deps: FindingsRollupDeps = defaults): void {
  parent.command("rollup [inputs...]")
    .description("Count open findings across repositories by severity, category, age and owner, from export files and findings databases")
    .option("--export <file>", "Also write these findings as a rollup export file that another rollup can read")
    .option("--history <file>", "Write a reusable dated snapshot archive, preserving the input timestamps and provenance")
    .option("--labels <file>", "JSON repository-to-team/tier map; fills missing labels without overwriting historical labels")
    .option("--owners <file>", "JSON file mapping repository names to owners, used when a finding has no assignee")
    .option("--repository <name>", "Repository name for findings read from a database (default: the scan target's folder name)")
    .addOption(new Option("--format <format>", "Output: text, json, html or csv").choices(["text", "json", "html", "csv"]))
    .option("-o, --output <file>", "Write the rollup to a file instead of stdout")
    .addHelpText("after", "\nWith no inputs it reads the findings databases on this machine. An input is a rollup export, a dated history archive (JSON) or a findings database (SQLite). Each export is a complete repository snapshot. Latest exportedAt wins per repository; historical snapshots remain separate trend points.")
    .action((inputs: string[], options: FindingsRollupOptions) => {
      try { runFindingsRollup(inputs, options, deps); } catch (error) { finishWithError(error, deps, options.format === "json"); }
    });
}
