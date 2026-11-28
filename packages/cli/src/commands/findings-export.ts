import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Command } from "commander";
import { UNTRUSTED_GIT_BASE_CONFIG, exportReport, isReportExportFormat } from "@0/engine";
import { VERSION } from "@0/engine/shared";
import { osecDB, resolveOsecRunStorage } from "@0/engine/storage";
import { findingDatabasePaths } from "../finding-focus.js";
import { emptyFindingSnapshot, mergeFindingSnapshots, retainedFindingSnapshot, retainedScanSnapshot } from "../web/report-artifacts.js";
import { finishWithError, UsageError } from "./output.js";
import { buildSheet, checkSheetFolder, commandLineOf, writeSheet } from "../evaluation-sheet.js";
import { compareFindingsByBusinessContext } from "@0/engine/shared";
import { CONTEXT_FLAG_HELP, contextOptionsOf, loadContextFor, REPOSITORY_FLAG_HELP, withBusinessContext, type LoadDeps } from "../business-context-load.js";

export interface FindingsExportDeps {
  out(text: string): void;
  err(text: string): void;
  writeBytes(path: string, bytes: Uint8Array): void;
  writeStdout(bytes: Uint8Array): void;
  /** Where settings and the git remote come from; tests replace it. */
  contextLoad?: LoadDeps;
  /** The commit of the folder given with --source (`--format sheet`); tests replace it. */
  gitHead?(folder: string): string | undefined;
  now?(): Date;
  /** The command line the sheet records; default: this process's arguments. */
  commandLine?(): string;
}
const defaults: FindingsExportDeps = {
  out: text => process.stdout.write(`${text}\n`),
  err: text => process.stderr.write(`${text}\n`),
  writeBytes: (path, bytes) => writeFileSync(path, bytes, { mode: 0o600 }),
  writeStdout: bytes => { process.stdout.write(bytes); },
  gitHead(folder) {
    try { return execFileSync("git", ["-C", folder, ...UNTRUSTED_GIT_BASE_CONFIG, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 15000 }).trim() || undefined; } catch { return undefined; }
  },
};
interface ExportOptions { severity?: string; category?: string; status?: string; triage?: string; limit?: string; scan?: string; format: string; output?: string; dbPath?: string; json?: boolean; context?: string; repository?: string; source?: string; overwriteSheet?: boolean }

export async function runFindingsExport(ids: string[], options: ExportOptions, deps: FindingsExportDeps = defaults): Promise<void> {
  try {
    const format = options.format === "md" ? "markdown" : options.format;
    const sheet = format === "sheet";
    if (!sheet && !isReportExportFormat(format)) throw new UsageError("--format must be one of: json, md, sarif, html, pdf, defectdojo, sheet.");
    if (sheet && !options.output) throw new UsageError("--format sheet writes a folder; supply -o <folder>.");
    if ((options.source || options.overwriteSheet) && !sheet) throw new UsageError("--source and --overwrite-sheet go with --format sheet.");
    if (sheet) checkSheetFolder(options.output!, Boolean(options.overwriteSheet));
    if (ids.length && options.scan) throw new UsageError("Use finding IDs or --scan, not both.");
    if (format === "pdf" && !options.output) throw new UsageError("PDF is binary; supply -o <file>.");
    // Read the context before any database is opened: a bad file changes nothing.
    const loaded = await loadContextFor(options, deps.contextLoad);
    const dbPath = options.dbPath ?? (options.scan ? resolveOsecRunStorage({ runId: options.scan, resume: true }).dbPath : undefined);
    let report;
    if (options.scan) report = retainedScanSnapshot(options.scan, dbPath);
    else {
      // Accept full IDs or unambiguous prefixes, like the other findings commands. Scans keep one
      // database per run, so look through all of them unless one was named.
      const paths = dbPath ? [dbPath] : findingDatabasePaths();
      const snapshots: Array<ReturnType<typeof retainedFindingSnapshot>> = [];
      const unresolved = new Set(ids);
      const filters = { limit: 5000, ...(options.severity ? { severity: options.severity } : {}), ...(options.category ? { category: options.category } : {}), ...(options.status ? { status: options.status } : {}), ...(options.triage ? { triageStatus: options.triage } : {}) };
      for (const path of paths) {
        const db = new osecDB(path);
        let resolved: string[] = [];
        try {
          const rows = db.listFindings(ids.length ? { limit: 5000 } : filters);
          if (!ids.length) resolved = rows.map(row => row.id);
          else for (const id of ids) {
            const matches = rows.filter(row => row.id === id || row.id.startsWith(id));
            const exact = matches.find(row => row.id === id);
            if (!exact && matches.length > 1) throw new UsageError(`Finding prefix '${id}' is ambiguous.`);
            const hit = exact ?? matches[0];
            if (hit) { resolved.push(hit.id); unresolved.delete(id); }
          }
        } catch (error) { if (error instanceof UsageError) throw error; /* An unreadable run database holds nothing to export. */ } finally { db.close(); }
        if (resolved.length) snapshots.push(retainedFindingSnapshot(resolved, path));
      }
      if (unresolved.size) throw new Error(`Finding '${[...unresolved][0]}' not found.`);
      // No IDs: every finding in the database (`0 findings list --format sarif`).
      if (!snapshots.length && ids.length) throw new Error("No findings to export.");
      report = !snapshots.length ? emptyFindingSnapshot() : snapshots.length === 1 ? snapshots[0]! : mergeFindingSnapshots(snapshots);
    }
    // Order by what matters to you and say why, in every format. Severity is never changed.
    if (loaded) report = { ...report, findings: withBusinessContext(report.findings, loaded).sort(compareFindingsByBusinessContext) };
    if (sheet) {
      // From the stored findings alone: no model, no network. What the database does not keep is written as not recorded.
      const source = options.source ? resolve(options.source) : undefined;
      const commit = source ? deps.gitHead?.(source) : undefined;
      const run = {
        source: "stored" as const, generatedAt: (deps.now?.() ?? new Date()).toISOString(), command: deps.commandLine?.() ?? commandLineOf(process.argv.slice(2)), cliVersion: VERSION,
        ...(options.scan ? { target: report.target, scanId: options.scan, ...(report.startedAt ? { startedAt: report.startedAt } : {}), ...(report.completedAt ? { completedAt: report.completedAt } : {}), ...(report.durationMs ? { durationMs: report.durationMs } : {}) } : {}),
        ...(commit ? { commit } : {}),
      };
      const built = buildSheet(report.findings, run, source ? [source] : []);
      const folder = writeSheet(options.output!, built, Boolean(options.overwriteSheet));
      deps.err(options.json ? JSON.stringify({ ok: true, path: folder, findings: built.findings.length, findingsSha256: built.findingsSha256, format }) : `Wrote the evaluation sheet (${built.findings.length} finding${built.findings.length === 1 ? "" : "s"}, list hash ${built.findingsSha256.slice(0, 16)}) to ${folder}. It is for human judgement, not an accuracy result.`);
      return;
    }
    if (!isReportExportFormat(format)) throw new UsageError("--format must be one of: json, md, sarif, html, pdf, defectdojo, sheet.");
    const artifact = await exportReport(report, format, options.scan ? `0-scan-${options.scan}` : "0-findings");
    if (options.output) {
      deps.writeBytes(options.output, artifact.body);
      deps.err(options.json ? JSON.stringify({ ok: true, path: options.output, bytes: artifact.body.byteLength, format }) : `Wrote ${options.output} (${artifact.body.byteLength} bytes)`);
    } else deps.writeStdout(artifact.body);
  } catch (error) { finishWithError(error, deps, options.json); }
}

export function registerFindingsExportCommand(parent: Command, deps: FindingsExportDeps = defaults): void {
  parent.command("export [ids...]")
    .description("Export findings, a whole scan or, with no IDs, every finding as json, md, sarif, html, pdf or defectdojo, or as a sheet (a folder) to judge them by hand")
    .option("--scan <id>", "Export every finding of this scan instead of selected IDs")
    .option("--format <format>", "json, md, sarif, html, pdf, defectdojo or sheet (a folder with review.csv, findings, run facts and a README; needs -o <folder>)", "json")
    .option("-o, --output <file>", "Write to a file instead of stdout; for --format sheet, the folder")
    .option("--source <folder>", "With --format sheet: the repository folder, for its commit and relative paths")
    .option("--overwrite-sheet", "With --format sheet: replace the sheet files in a folder that already has files (other files are left alone)")
    .option("--severity <severity>", "With no IDs: only this severity")
    .option("--category <category>", "With no IDs: only this category")
    .option("--status <status>", "With no IDs: only this status")
    .option("--triage <triage>", "With no IDs: only this triage state")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--context <file>", CONTEXT_FLAG_HELP)
    .option("--repository <name>", REPOSITORY_FLAG_HELP)
    .option("--json", "Print the result of writing a file as JSON")
    .action(async (ids: string[], options: ExportOptions, command: Command) => {
      // `findings` declares --db-path and --scan too; Commander may bind them to the parent.
      const merged = { ...command.parent?.opts(), ...command.opts() } as ExportOptions;
      await runFindingsExport(ids, { ...options, ...contextOptionsOf(options, command), scan: options.scan ?? merged.scan, dbPath: options.dbPath ?? merged.dbPath }, deps);
    });
}
