/**
 * `0 findings rollup`: counts findings across repositories from export files and findings databases you name.
 * It reads local files only and sends nothing anywhere. Finding evidence never enters an export.
 */
import { closeSync, openSync, readFileSync, readSync, statSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { Option, type Command } from "commander";
import { effectiveTriageStatus, looksLikeSarif, parseSarif, redactEvidence } from "@0/engine/shared";
import { parse as parseYaml } from "yaml";
import { osecDB } from "@0/engine/storage";
import { findingDatabasePaths } from "../finding-focus.js";
import { finishWithError, UsageError } from "./output.js";
import { findingPath } from "../business-context.js";
import { contextOptionsOf, labelFor, loadContextFor, type LoadedContext } from "../business-context-load.js";
import { applyLabels, applyOwners, buildExport, priorityOf, parseExport, renderHtml, renderText, type LabelRule, type RollupExport, type RollupRow, type WorkRow } from "./findings-rollup-core.js";

import { HISTORY_SCHEMA, buildRollupReport, latestSnapshotRows, parseHistory, rollupCsv, trendText, type RollupSnapshot } from "./findings-rollup-history.js";

type WorkSnapshot = Omit<RollupSnapshot, "findings"> & { findings: WorkRow[] };

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const MAX_DB_ROWS = 100_000;
const MAX_LABEL_BYTES = 1024 * 1024;
const MAX_LABEL_RULES = 2000;
const SQLITE_MAGIC = "SQLite format 3\u0000";

export interface FindingsRollupOptions { export?: string; owners?: string; labels?: string; context?: string; ranking?: LoadedContext; since?: string; repository?: string; format?: string; output?: string; history?: string }
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

export function rowsFromDatabase(path: string, repository?: string): WorkRow[] {
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
    return findings.map((f): WorkRow => {
      const at = new Date(f.timestamp).toISOString();
      return {
        repository: targetOf(f.scanId), fingerprint: f.fingerprint || f.id, title: f.title.slice(0, 300), severity: f.severity.toLowerCase(), category: f.category,
        status: f.status, triage: effectiveTriageStatus(f), owner: f.workflowAssignee?.trim() ? f.workflowAssignee.trim().slice(0, 100) : null, firstSeen: at, lastSeen: at,
        ...(findingPath((f as { reviewAnnotation?: unknown }).reviewAnnotation) ? { path: findingPath((f as { reviewAnnotation?: unknown }).reviewAnnotation)!.slice(0, 500) } : {}),
      };
    });
  } finally { db.close(); }
}

/** A repository name from a SARIF provenance URI: host and path, with credentials, scheme and `.git` removed. */
export function repositoryFromUri(uri: string): string {
  const bare = redactEvidence(uri).replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^[^/@]*@/, "").replace(/[?#].*$/, "").replace(/\.git\/?$/i, "").replace(/\/+$/, "");
  return bare.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 200);
}

/** Findings from a SARIF file, read with the importer's limits and credential scrubbing. Nothing is written to a database. */
export function rowsFromSarif(text: string, file: string, modified: Date, repository?: string): WorkRow[] {
  const parsed = parseSarif(text);
  const name = repository?.trim() || (parsed.repository ? repositoryFromUri(parsed.repository) : "") || basename(file).replace(/\.(sarif|json)$/i, "") || "unknown";
  const at = modified.toISOString();
  return parsed.findings.map((f): WorkRow => ({
    repository: name.slice(0, 200), fingerprint: f.fingerprint, title: f.title.slice(0, 300), severity: f.severity, category: f.category,
    status: "discovered", triage: "new", owner: null, firstSeen: at, lastSeen: at, ...(f.path ? { path: f.path.slice(0, 500) } : {}),
  }));
}

function readInput(path: string, repository: string | undefined, now: Date): WorkSnapshot[] {
  const full = resolve(path);
  let stat;
  try { stat = statSync(full); } catch { throw new UsageError(`${path} does not exist.`); }
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new UsageError(`${path} must be a file of at most 100 MB.`);
  // The rows keep their file path in memory so a business context can match it; an export never carries it.
  if (isDatabase(full)) { const rows = rowsFromDatabase(full, repository); return [{ ...buildExport(rows, now, repository ? [repository] : undefined), findings: rows, source: basename(path) }]; }
  const text = readFileSync(full, "utf8");
  if (looksLikeSarif(text)) {
    try {
      const findings = rowsFromSarif(text, full, stat.mtime, repository);
      const provenance = parseSarif(text).repository;
      const name = repository?.trim() || (provenance ? repositoryFromUri(provenance) : "") || basename(full).replace(/\.(sarif|json)$/i, "") || "unknown";
      return [{ schema: "0.findings-rollup.v1", exportedAt: stat.mtime.toISOString(), findings, repositories: [name.slice(0, 200)], source: basename(path) }];
    } catch (error) { throw new UsageError(`${path}: ${error instanceof Error ? error.message : String(error)}`); }
  }
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new UsageError(`${path} is not JSON.`); }
  if (value && typeof value === "object" && (value as { schema?: string }).schema === HISTORY_SCHEMA) return parseHistory(value);
  return [{ ...parseExport(text, path), source: basename(path) }];
}

function readEarlier(path: string): RollupExport {
  const full = resolve(path);
  let stat;
  try { stat = statSync(full); } catch { throw new UsageError(`--since file ${path} does not exist.`); }
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new UsageError(`--since must name a rollup export of at most 100 MB.`);
  try { return parseExport(readFileSync(full, "utf8"), path); } catch (error) { throw new UsageError(`--since: ${error instanceof Error ? error.message : String(error)}`); }
}

/** Reads a labels file: JSON or YAML, repository name or glob (or `path:` and a glob) to a team and a tier. Only the file you name is read. */
export function readLabels(path: string): LabelRule[] {
  const usage = `--labels must name a JSON or YAML file that maps a repository name or glob to a team and tier, such as {"api": {"team": "payments", "tier": "1"}}. Prefix a key with path: to match files inside a repository.`;
  let value: unknown;
  try {
    const full = resolve(path);
    if (statSync(full).size > MAX_LABEL_BYTES) throw new Error("too large");
    value = parseYaml(readFileSync(full, "utf8"), { maxAliasCount: 0 });
  } catch { throw new UsageError(usage); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new UsageError(usage);
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_LABEL_RULES) throw new UsageError(`--labels has more than ${MAX_LABEL_RULES} entries.`);
  const rules: LabelRule[] = [];
  for (const [key, label] of entries) {
    const isPath = key.startsWith("path:");
    const pattern = (isPath ? key.slice(5) : key).trim();
    if (!pattern || pattern.length > 200 || !label || typeof label !== "object" || Array.isArray(label)) throw new UsageError(usage);
    const { team, tier, ...rest } = label as Record<string, unknown>;
    const name = (v: unknown, max: number): string | undefined | null => v === undefined || v === null ? undefined : (typeof v === "string" || typeof v === "number") && String(v).trim() && String(v).length <= max ? String(v).trim() : null;
    const t = name(team, 100); const k = name(tier, 40);
    if (t === null || k === null || Object.keys(rest).length || (t === undefined && k === undefined)) throw new UsageError(`--labels entry "${key.slice(0, 60)}" needs a team, a tier or both, each a short string.`);
    rules.push({ pattern, path: isPath, ...(t ? { team: t } : {}), ...(k ? { tier: k } : {}) });
  }
  return rules;
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
  const labels = options.labels ? readLabels(options.labels) : undefined;
  const earlier = options.since ? readEarlier(options.since) : undefined;
  const sources = inputs.length ? inputs : deps.defaultDatabases();
  const now = deps.now();
  let snapshots: WorkSnapshot[] = [];
  for (const source of sources) {
    try { snapshots.push(...readInput(source, options.repository, now)); } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new Error(`Could not read ${source}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (snapshots.length > 10_000 || snapshots.reduce((n, snapshot) => n + snapshot.findings.length, 0) > 200_000) throw new UsageError("Rollup history exceeds 10000 snapshots or 200000 finding rows.");
  snapshots = snapshots.map(snapshot => {
    let findings = owners ? applyOwners(snapshot.findings, owners) : snapshot.findings;
    if (labels) findings = applyLabels(findings, labels);
    return { ...snapshot, findings };
  });
  const current = latestSnapshotRows(snapshots);
  if (options.export) {
    deps.writeFile(resolve(options.export), `${JSON.stringify(buildExport(current.rows, now, current.repositories), null, 2)}\n`);
    deps.err(`Wrote ${current.rows.length} finding${current.rows.length === 1 ? "" : "s"} to ${options.export}`);
  }
  if (options.history) {
    const archived = snapshots.map(snapshot => ({ ...buildExport(snapshot.findings, new Date(snapshot.exportedAt), snapshot.repositories), source: snapshot.source }));
    deps.writeFile(resolve(options.history), `${JSON.stringify({ schema: HISTORY_SCHEMA, snapshots: archived }, null, 2)}\n`);
    deps.err(`Wrote ${snapshots.length} dated snapshots to ${options.history}`);
  }
  const report = buildRollupReport(snapshots, now, earlier);
  // Each row names its repository, so rules for specific repositories match on that name.
  const loaded = options.ranking;
  if (loaded) report.priority = priorityOf(current.rows, row => labelFor(loaded, row, row.repository));
  const format = options.format ?? "text";
  const escape = (value: string) => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
  const body = format === "json" ? `${JSON.stringify(report, null, 2)}\n` : format === "csv" ? rollupCsv(report)
    : format === "html" ? renderHtml(report).replace("</body>", `<h2>Snapshot trend</h2><pre style="white-space:pre-wrap">${escape(trendText(report))}</pre></body>`) : `${renderText(report)}\n${trendText(report)}\n`;
  if (options.output) { deps.writeFile(resolve(options.output), body); deps.err(`Wrote ${options.output}`); } else deps.out(body.replace(/\n$/, ""));
}

export function registerFindingsRollupCommand(parent: Command, deps: FindingsRollupDeps = defaults): void {
  parent.command("rollup [inputs...]")
    .description("Count open findings across repositories by severity, category, age, owner, team and tier, from export files, SARIF files and findings databases")
    .option("--export <file>", "Also write these findings as a rollup export file that another rollup can read")
    .option("--history <file>", "Write a reusable dated snapshot archive, preserving the input timestamps and provenance")
    .option("--owners <file>", "JSON file mapping repository names to owners, used when a finding has no assignee")
    .option("--labels <file>", "JSON or YAML file mapping repository names or globs (or path: globs) to a team and tier, shown as extra breakdowns")
    .option("--since <file>", "An earlier rollup export to compare with: shows findings opened and fixed since then")
    .option("--repository <name>", "Repository name for findings read from a database or a SARIF file (default: the scan target's folder name, or the SARIF's repository). Rules for a repository in the context file match this name")
    .option("--context <file>", "Business context file (JSON): also list the open findings to look at first, ordered with it. Defaults to the file set with `0security config set findingsContext`")
    .addOption(new Option("--format <format>", "Output: text, json, html or csv").choices(["text", "json", "html", "csv"]))
    .option("-o, --output <file>", "Write the rollup to a file instead of stdout")
    .addHelpText("after", "\nWith no inputs it reads the findings databases on this machine. An input is a rollup export, a dated history archive (JSON), a SARIF file or a findings database (SQLite). Latest exportedAt wins per repository; snapshots stay separate in snapshotTrend, while --since supplies the trend comparison.")
    .action(async (inputs: string[], raw: FindingsRollupOptions, command: Command) => {
      // `findings` declares --context and --repository too, and Commander may bind them to the parent.
      const options = { ...raw, ...contextOptionsOf(raw, command) };
      try { runFindingsRollup(inputs, { ...options, ranking: await loadContextFor(options.context !== undefined ? { context: options.context } : {}) }, deps); } catch (error) { finishWithError(error, deps, options.format === "json"); }
    });
}
