// `0 config get audit` — the local append-only log of privileged actions, as on the web Settings > Audit log page.
import { chmodSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import type { Command } from "commander";
import { VERSION } from "@0/engine/shared";
import { AUDIT_EXPORT_FORMATS, auditCheckpointHashAt, checkAuditChainFile, formatAuditChainFile, formatAuditEvent, listAudit, parseAuditTime, planAuditPrune, pruneAuditLog, queryAuditChainRows, queryAuditEvents, resolveOsecDbPath, verifyAuditLog, type AuditEvent, type AuditExportFormat, type AuditRangeQuery } from "@0/engine/storage";
import { auditProofRefusal, auditPruneRefusal } from "../enterprise-bridge.js";
import { printJson, renderTable, sinks, UsageError, type ConsoleCommandDeps, type JsonOption } from "./console-support.js";

export interface AuditLogOptions extends JsonOption { q?: string; limit?: string; before?: string }

function positive(name: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new UsageError(`--${name} must be a positive integer.`);
  return parsed;
}

export function runAuditLog(options: AuditLogOptions, deps: ConsoleCommandDeps = {}): void {
  const io = sinks(deps);
  try {
    const limit = positive("limit", options.limit);
    const before = positive("before", options.before);
    const page = listAudit({ ...(limit ? { limit } : {}), ...(before ? { before } : {}), q: options.q ?? "" }, { dbPath: resolveOsecDbPath(deps.dbPath) });
    if (options.json) printJson(io, page);
    else if (!page.events.length) io.out("No audit events.");
    else {
      io.out(renderTable(["ID", "TIME", "ACTOR", "ACTION", "SUBJECT", "OUTCOME"], page.events.map((e: AuditEvent) => [String(e.id), e.ts, e.actor, e.action, e.subject, e.outcome])));
      if (page.nextBefore) io.out(`More: --before ${page.nextBefore}`);
    }
    io.exit(0);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not read the audit log.";
    io.err(options.json ? JSON.stringify({ error: message }) : `error: ${message}`);
    io.exit(error instanceof UsageError ? 2 : 1);
  }
}

export interface AuditExportOptions {
  format?: string; since?: string; until?: string; limit?: string; type?: string[]; output?: string; follow?: boolean;
  /** Rows with their hashes and a trailer, checkable offline with `config audit-verify --file`. Needs the audit-chain license. */
  withProof?: boolean;
}

/** The paid-feature checks. Defaults to the license-gated enterprise code; tests pass their own. */
export interface AuditLicenseDeps { license?: { proofRefusal(): string | null; pruneRefusal(): string | null } }
export interface AuditExportDeps extends ConsoleCommandDeps, AuditLicenseDeps {
  /** Stops --follow (tests). Defaults to Ctrl+C. */
  signal?: AbortSignal;
  /** Milliseconds between polls with --follow. */
  pollMs?: number;
  now?: () => Date;
}

const sleepUnlessAborted = (ms: number, signal: AbortSignal): Promise<void> => new Promise(resolve => {
  if (signal.aborted) return resolve();
  const timer = setTimeout(() => { signal.removeEventListener("abort", done); resolve(); }, ms);
  const done = () => { clearTimeout(timer); resolve(); };
  signal.addEventListener("abort", done, { once: true });
});

/** Writes the audit log as NDJSON, CEF or RFC 5424 syslog lines, oldest first. Exit 0 ok, 1 failure, 2 usage. */
export async function runAuditExport(options: AuditExportOptions, deps: AuditExportDeps = {}): Promise<void> {
  const io = sinks(deps);
  let fd: number | undefined;
  try {
    const format = (options.format ?? "ndjson").toLowerCase();
    if (!(AUDIT_EXPORT_FORMATS as readonly string[]).includes(format)) throw new UsageError(`--format must be one of ${AUDIT_EXPORT_FORMATS.join(", ")}.`);
    const now = deps.now?.() ?? new Date();
    const range: AuditRangeQuery = {};
    try {
      if (options.since) range.since = parseAuditTime(options.since, now);
      if (options.until) range.until = parseAuditTime(options.until, now);
    } catch (error) { throw new UsageError(error instanceof Error ? error.message : "Invalid time."); }
    if (range.since && range.until && range.since >= range.until) throw new UsageError("--since must be earlier than --until.");
    const limit = positive("limit", options.limit);
    if (limit) range.limit = limit;
    const types = (options.type ?? []).flatMap(value => value.split(",")).map(value => value.trim()).filter(Boolean);
    if (types.length) range.types = types;
    if (options.follow && (range.until || limit)) throw new UsageError("--follow cannot be combined with --until or --limit.");

    if (options.withProof) {
      const refusal = (deps.license?.proofRefusal ?? auditProofRefusal)();
      if (refusal) throw new UsageError(refusal);
      if (format !== "ndjson") throw new UsageError("--with-proof writes NDJSON only. Leave out --format.");
      if (options.follow || types.length) throw new UsageError("--with-proof cannot be combined with --follow or --type: the proof needs an unbroken run of events.");
      const rows = queryAuditChainRows({ ...(range.since ? { since: range.since } : {}), ...(range.until ? { until: range.until } : {}), ...(range.limit ? { limit: range.limit } : {}) }, { dbPath: resolveOsecDbPath(deps.dbPath) });
      for (let i = 1; i < rows.length; i++) if (rows[i]!.id !== rows[i - 1]!.id + 1) throw new UsageError("The events in that time range are not one unbroken run, so no proof can be made. Use a wider range.");
      const text = formatAuditChainFile(rows, now.toISOString());
      if (options.output) {
        fd = openSync(options.output, "w", 0o600);
        try { chmodSync(options.output, 0o600); } catch { /* not supported on this file system */ }
        writeSync(fd, text);
      } else io.out(text.trimEnd());
      const trailer = JSON.parse(text.trimEnd().split("\n").at(-1)!) as { rows: number; headHash: string | null };
      io.err(`${options.output ? `Wrote ${trailer.rows} chained event${trailer.rows === 1 ? "" : "s"} with proof to ${options.output}. ` : ""}Head hash: ${trailer.headHash ?? "none"}. Check the file with: 0security config audit-verify --file <file>`);
      io.exit(0);
      return;
    }
    if (options.output) {
      fd = openSync(options.output, "w", 0o600);
      try { chmodSync(options.output, 0o600); } catch { /* not supported on this file system */ }
    }
    const ctx = { host: hostname(), version: VERSION };
    const target = { dbPath: resolveOsecDbPath(deps.dbPath) };
    let written = 0;
    const emit = (events: AuditEvent[]) => {
      for (const event of events) {
        const line = formatAuditEvent(event, format as AuditExportFormat, ctx);
        if (fd !== undefined) writeSync(fd, `${line}
`); else io.out(line);
        written += 1;
      }
    };
    const first = queryAuditEvents(range, target);
    emit(first);
    if (options.follow) {
      const controller = new AbortController();
      const stop = () => controller.abort();
      const signal = deps.signal ?? controller.signal;
      if (!deps.signal) process.once("SIGINT", stop);
      let last = first.at(-1)?.id ?? queryAuditEvents({ limit: 1 }, target).at(-1)?.id ?? 0;
      try {
        while (!signal.aborted) {
          await sleepUnlessAborted(deps.pollMs ?? 1000, signal);
          if (signal.aborted) break;
          const more = queryAuditEvents({ ...range, afterId: last }, target);
          if (more.length) { emit(more); last = more.at(-1)!.id; }
        }
      } finally { process.removeListener("SIGINT", stop); }
    }
    if (fd !== undefined) io.err(`Wrote ${written} event${written === 1 ? "" : "s"} to ${options.output}.`);
    io.exit(0);
  } catch (error) {
    io.err(`error: ${error instanceof Error ? error.message : "Could not export the audit log."}`);
    io.exit(error instanceof UsageError ? 2 : 1);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* already closed */ }
  }
}

/** Checks the audit log hash chain offline. Free: no license. Exit 0 intact, 1 broken or unreadable, 2 usage. */
export function runAuditVerify(options: JsonOption & { file?: string }, deps: ConsoleCommandDeps = {}): void {
  if (options.file) { runAuditVerifyFile(options.file, options, deps); return; }
  const io = sinks(deps);
  try {
    const report = verifyAuditLog({ dbPath: resolveOsecDbPath(deps.dbPath) });
    if (options.json) printJson(io, report);
    else if (report.ok) {
      const parts = [`${report.rows} chained event${report.rows === 1 ? "" : "s"}`];
      if (report.firstId !== null) parts.push(`ids ${report.firstId} to ${report.lastId}`);
      if (report.rotatedRows) parts.push(`${report.rotatedRows} older event${report.rotatedRows === 1 ? "" : "s"} rotated out and covered by ${report.checkpoints} checkpoint${report.checkpoints === 1 ? "" : "s"}`);
      io.out(`Audit log chain intact: ${parts.join(", ")}.`);
      if (report.unchainedRows) io.out(`${report.unchainedRows} older event${report.unchainedRows === 1 ? " was" : "s were"} written before the chain existed and cannot be verified.`);
      if (report.headHash) io.out(`Head hash: ${report.headHash}`);
      io.out("This shows the log is consistent. Keep a copy of the head hash elsewhere (for example in your SIEM) to detect a rewritten log.");
    } else {
      const brk = report.firstBreak!;
      io.out(`Audit log chain BROKEN${brk.id === null ? "" : ` at event ${brk.id}`}: ${brk.reason}.`);
      io.out("Events from that point on cannot be trusted.");
    }
    io.exit(report.ok ? 0 : 1);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not read the audit log.";
    io.err(options.json ? JSON.stringify({ error: message }) : `error: ${message}`);
    io.exit(1);
  }
}

/** Checks an export with proof or a retention archive offline. Exit 0 intact, 1 broken or unreadable. */
function runAuditVerifyFile(file: string, options: JsonOption, deps: ConsoleCommandDeps): void {
  const io = sinks(deps);
  try {
    let text: string;
    try { text = readFileSync(file, "utf8"); } catch { throw new UsageError(`Cannot read '${file}'.`); }
    const report = checkAuditChainFile(text);
    let liveMatch: boolean | null = null;
    if (report.ok && report.lastId !== null) {
      const known = auditCheckpointHashAt(report.lastId, { dbPath: resolveOsecDbPath(deps.dbPath) });
      liveMatch = known === null ? null : known === report.headHash;
    }
    if (options.json) printJson(io, { ...report, linkedToLiveLog: liveMatch });
    else if (report.ok) {
      io.out(`Chain file intact: ${report.rows} chained event${report.rows === 1 ? "" : "s"}${report.firstId !== null ? `, ids ${report.firstId} to ${report.lastId}` : ""}.`);
      if (report.legacyRows) io.out(`${report.legacyRows} older event${report.legacyRows === 1 ? " was" : "s were"} written before the chain existed and cannot be verified.`);
      if (report.headHash) io.out(`Head hash: ${report.headHash}`);
      if (liveMatch === true) io.out(`The live log's rotation checkpoint at id ${report.lastId} has this head hash: the live log continues from this file.`);
      else if (liveMatch === false) io.out(`The live log has a rotation checkpoint at id ${report.lastId} with a different hash: this file is not what the log continued from.`);
      io.out("The file proves its own rows are consistent. It does not prove nothing was cut off the end: compare the head hash with a copy you kept elsewhere.");
    } else {
      const brk = report.firstBreak!;
      io.out(`Chain file BROKEN${brk.id === null ? "" : ` at event ${brk.id}`}: ${brk.reason}.`);
    }
    io.exit(report.ok && liveMatch !== false ? 0 : 1);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not read the file.";
    io.err(options.json ? JSON.stringify({ error: message }) : `error: ${message}`);
    io.exit(error instanceof UsageError ? 2 : 1);
  }
}

export interface AuditPruneOptions { olderThan?: string; archive?: string; yes?: boolean }
export interface AuditPruneDeps extends ConsoleCommandDeps, AuditLicenseDeps { now?: () => Date }

/**
 * Export-then-prune: writes the old events to an archive file, checks the archive, then removes them and leaves a chain
 * checkpoint so the rest of the log still verifies. Needs the retention license. Without --yes it only reports.
 */
export function runAuditPrune(options: AuditPruneOptions, deps: AuditPruneDeps = {}): void {
  const io = sinks(deps);
  try {
    const refusal = (deps.license?.pruneRefusal ?? auditPruneRefusal)();
    if (refusal) throw new UsageError(refusal);
    if (!options.olderThan) throw new UsageError("--older-than <time> is required: a duration such as 365d, or a date.");
    if (!options.archive) throw new UsageError("--archive <file> is required: old events are written there before they are removed.");
    let cutoff: string;
    try { cutoff = parseAuditTime(options.olderThan, deps.now?.() ?? new Date()); } catch (error) { throw new UsageError(error instanceof Error ? error.message : "Invalid time."); }
    const target = { dbPath: resolveOsecDbPath(deps.dbPath) };
    const plan = planAuditPrune(cutoff, target);
    if (!plan.length) { io.out(`No events older than ${cutoff}. Nothing to do.`); io.exit(0); return; }
    const span = `${plan.length} event${plan.length === 1 ? "" : "s"} (ids ${plan[0]!.id} to ${plan.at(-1)!.id}) older than ${cutoff}`;
    if (!options.yes) {
      io.out(`Would write ${span} to ${options.archive} and remove them from the log. Run again with --yes to do it.`);
      io.exit(0);
      return;
    }
    if (existsSync(options.archive)) throw new UsageError(`'${options.archive}' already exists. Choose a new file name: an archive is never overwritten.`);
    const created = (deps.now?.() ?? new Date()).toISOString();
    const result = pruneAuditLog(cutoff, rows => {
      const text = formatAuditChainFile(rows, created);
      const fd = openSync(options.archive!, "wx", 0o600);
      try { writeSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
      // Read it back before anything is removed: a bad archive must not cost the events.
      const check = checkAuditChainFile(readFileSync(options.archive!, "utf8"));
      if (!check.ok) throw new Error(`The archive did not verify (${check.firstBreak?.reason ?? "unknown"}). Nothing was removed.`);
    }, target);
    io.out(`Archived ${result.pruned} event${result.pruned === 1 ? "" : "s"} to ${options.archive} and removed them from the log.`);
    if (result.throughHash) io.out(`Archive head hash: ${result.throughHash}. The log now continues from a rotation checkpoint at id ${result.throughId}.`);
    io.out("Keep the archive: it is the only copy of those events. Check it any time with: 0security config audit-verify --file <archive>");
    io.exit(0);
  } catch (error) {
    io.err(`error: ${error instanceof Error ? error.message : "Could not prune the audit log."}`);
    io.exit(error instanceof UsageError ? 2 : 1);
  }
}

export function registerAuditLogCommand(program: Command, deps: ConsoleCommandDeps = {}): void {
  program.command("audit-log").description("Show the local log of privileged actions (connections, settings, extensions)")
    .option("--q <text>", "Only events whose action, subject or actor contains this text")
    .option("--limit <n>", "Maximum events to show")
    .option("--before <id>", "Only events older than this id (pagination)")
    .option("--json", "Print JSON")
    .action((o: AuditLogOptions) => runAuditLog(o, deps));
  program.command("audit-export").description("Write the audit log as NDJSON, CEF or syslog lines for a SIEM")
    .option("--format <format>", "ndjson (default), cef or syslog")
    .option("--since <time>", "Only events at or after this time: a duration (24h, 7d) or a date")
    .option("--until <time>", "Only events before this time")
    .option("--limit <n>", "Keep only the newest n matching events")
    .option("--type <action...>", "Only these actions or action prefixes, for example extension (repeatable, or comma separated)")
    .option("-o, --output <file>", "Write to this file with owner-only permissions instead of stdout")
    .option("--follow", "Keep running and print new events as they are written (Ctrl+C stops)")
    .option("--with-proof", "Write NDJSON rows with their chain hashes and a trailer, checkable with audit-verify --file (needs an enterprise license)")
    .action((o: AuditExportOptions) => runAuditExport(o, deps));
  program.command("audit-verify").description("Check offline that the audit log was not edited, reordered or cut (hash chain)")
    .option("--file <file>", "Check an export made with --with-proof, or a retention archive, instead of the live log")
    .option("--json", "Print JSON")
    .action((o: JsonOption & { file?: string }) => runAuditVerify(o, deps));
  program.command("audit-prune").description("Archive audit events older than a date to a file, then remove them (retention)")
    .option("--older-than <time>", "Events older than this: a duration (365d) or a date")
    .option("--archive <file>", "New file that receives the old events before they are removed")
    .option("--yes", "Do it. Without it the command only reports what it would remove")
    .action((o: AuditPruneOptions) => runAuditPrune(o, deps));
}
