// `0 config get audit` — the local append-only log of privileged actions, as on the web Settings > Audit log page.
import { chmodSync, closeSync, openSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import type { Command } from "commander";
import { VERSION } from "@0/engine/shared";
import { AUDIT_EXPORT_FORMATS, formatAuditEvent, listAudit, parseAuditTime, queryAuditEvents, resolveOsecDbPath, verifyAuditLog, type AuditEvent, type AuditExportFormat, type AuditRangeQuery } from "@0/engine/storage";
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
}
export interface AuditExportDeps extends ConsoleCommandDeps {
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
export function runAuditVerify(options: JsonOption, deps: ConsoleCommandDeps = {}): void {
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
    .action((o: AuditExportOptions) => runAuditExport(o, deps));
  program.command("audit-verify").description("Check offline that the audit log was not edited, reordered or cut (hash chain)")
    .option("--json", "Print JSON")
    .action((o: JsonOption) => runAuditVerify(o, deps));
}
