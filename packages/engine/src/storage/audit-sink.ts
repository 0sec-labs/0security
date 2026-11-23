/**
 * Optional push of the audit log to a SIEM collector, for server mode.
 *
 * Off unless the operator sets ZERO_AUDIT_SINK_URL in the process environment. Nothing in a repository, a project
 * file or the database can set it. The sink polls the local audit log for new rows (so it also sees events written
 * by other 0 processes on the same database), formats them with the export formatter and sends them in batches.
 * It never blocks or fails the code that writes the log: it runs on its own timer, swallows its errors, and counts
 * what it had to drop.
 *
 * ZERO_ENTERPRISE does not block it. The destination is one the operator named, like the team sign-in issuer. See
 * data-flow.md and scripts/egress-inventory.json (`audit-siem-sink`).
 */
import net from "node:net";
import tls from "node:tls";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { AUDIT_EXPORT_FORMATS, formatAuditEvent, type AuditExportFormat } from "./audit-format.js";
import { latestAuditId, queryAuditEvents } from "./audit-log.js";

export const AUDIT_SINK_URL_ENV = "ZERO_AUDIT_SINK_URL";
export const AUDIT_SINK_FORMAT_ENV = "ZERO_AUDIT_SINK_FORMAT";
export const AUDIT_SINK_TOKEN_ENV = "ZERO_AUDIT_SINK_TOKEN";

export class AuditSinkConfigError extends Error {}

export interface AuditSinkConfig {
  transport: "https" | "http-loopback" | "syslog-tls" | "syslog-tcp-loopback";
  url: URL;
  host: string;
  port: number;
  format: AuditExportFormat;
  token?: string;
  /** Safe to print: scheme, host and port only. */
  label: string;
}

const isLoopback = (host: string): boolean => {
  const name = host.replace(/^\[|\]$/g, "").toLowerCase();
  return name === "localhost" || name === "::1" || /^127(?:\.\d{1,3}){3}$/.test(name);
};

/** Reads the sink settings from the environment. Returns null when the sink is off; throws AuditSinkConfigError when the setting is refused. */
export function parseAuditSinkConfig(env: NodeJS.ProcessEnv = process.env): AuditSinkConfig | null {
  const raw = env[AUDIT_SINK_URL_ENV]?.trim();
  if (!raw) return null;
  let url: URL;
  try { url = new URL(raw); } catch {
    throw new AuditSinkConfigError(`${AUDIT_SINK_URL_ENV} is not a URL. Use https://host/path or syslog+tls://host:port.`);
  }
  if (url.username || url.password) throw new AuditSinkConfigError(`${AUDIT_SINK_URL_ENV} must not contain a user name or password. Put a bearer token in ${AUDIT_SINK_TOKEN_ENV}.`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!host) throw new AuditSinkConfigError(`${AUDIT_SINK_URL_ENV} has no host or does not start with a scheme. Use https://host/path or syslog+tls://host:port.`);
  const requested = env[AUDIT_SINK_FORMAT_ENV]?.trim().toLowerCase();
  if (requested && !(AUDIT_EXPORT_FORMATS as readonly string[]).includes(requested)) {
    throw new AuditSinkConfigError(`${AUDIT_SINK_FORMAT_ENV} must be one of ${AUDIT_EXPORT_FORMATS.join(", ")}.`);
  }
  const token = env[AUDIT_SINK_TOKEN_ENV]?.trim() || undefined;
  const protocol = url.protocol;
  if (protocol === "https:" || protocol === "http:") {
    if (protocol === "http:" && !isLoopback(host)) throw new AuditSinkConfigError(`${AUDIT_SINK_URL_ENV} refuses plain http except to this machine. Use https://.`);
    const port = Number(url.port) || (protocol === "https:" ? 443 : 80);
    return { transport: protocol === "https:" ? "https" : "http-loopback", url, host, port, format: (requested as AuditExportFormat | undefined) ?? "ndjson", ...(token ? { token } : {}), label: `${protocol}//${url.host}` };
  }
  if (protocol === "syslog+tls:" || protocol === "syslog+tcp:") {
    if (requested && requested !== "syslog") throw new AuditSinkConfigError(`A syslog sink sends syslog lines. Leave ${AUDIT_SINK_FORMAT_ENV} unset or set it to syslog.`);
    if (protocol === "syslog+tcp:" && !isLoopback(host)) throw new AuditSinkConfigError(`${AUDIT_SINK_URL_ENV} refuses plain TCP syslog except to this machine. Use syslog+tls://host:port.`);
    const port = Number(url.port) || (protocol === "syslog+tls:" ? 6514 : 514);
    return { transport: protocol === "syslog+tls:" ? "syslog-tls" : "syslog-tcp-loopback", url, host, port, format: "syslog", label: `${protocol}//${url.host || `${host}:${port}`}` };
  }
  if (protocol === "syslog:" || protocol === "udp:" || protocol === "syslog+udp:") {
    throw new AuditSinkConfigError("UDP syslog is not supported: it is unauthenticated and drops events silently. Use syslog+tls://host:port.");
  }
  throw new AuditSinkConfigError(`${AUDIT_SINK_URL_ENV} has an unsupported scheme. Use https://host/path or syslog+tls://host:port.`);
}

export interface AuditSinkStatus {
  label: string;
  sent: number;
  dropped: number;
  lastError?: string;
  lastSuccessAt?: string;
}

export type AuditSinkSend = (lines: string[]) => Promise<void>;

export interface AuditSinkOptions {
  config: AuditSinkConfig;
  /** The database to read. Called on every poll, so a database switch is followed. */
  getDbPath: () => string | undefined;
  version?: string;
  host?: string;
  intervalMs?: number;
  batchSize?: number;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  timeoutMs?: number;
  /** Receives the status line when events were dropped, and when the sink stops. Defaults to stderr. */
  onStatus?: (line: string) => void;
  /** Replaces the network send (tests). */
  send?: AuditSinkSend;
}

export interface AuditSink {
  status(): AuditSinkStatus;
  statusLine(): string;
  /** Polls once now and resolves when the batches it read were sent or dropped. */
  poll(): Promise<void>;
  /** Stops polling, makes one last attempt at what is waiting, reports the status line. */
  stop(): Promise<void>;
}

const redirectsRefused = (status: number): boolean => status >= 300 && status < 400;
class PermanentSendError extends Error {}

function sendHttp(config: AuditSinkConfig, timeoutMs: number): AuditSinkSend {
  const request = config.transport === "https" ? httpsRequest : httpRequest;
  return lines => new Promise<void>((resolve, reject) => {
    const body = Buffer.from(`${lines.join("\n")}\n`, "utf8");
    const req = request(config.url, {
      method: "POST",
      timeout: timeoutMs,
      headers: {
        "content-type": config.format === "ndjson" ? "application/x-ndjson" : "text/plain; charset=utf-8",
        "content-length": body.length,
        "user-agent": "0security-audit-sink",
        "x-audit-schema": "0.audit.v1",
        ...(config.token ? { authorization: `Bearer ${config.token}` } : {}),
      },
    }, res => {
      res.resume();
      res.on("end", () => {
        const status = res.statusCode ?? 0;
        if (status >= 200 && status < 300) resolve();
        else if (status === 408 || status === 429 || status >= 500) reject(new Error(`collector answered HTTP ${status}`));
        else reject(new PermanentSendError(redirectsRefused(status) ? `collector answered HTTP ${status}; redirects are not followed` : `collector answered HTTP ${status}`));
      });
    });
    req.on("timeout", () => req.destroy(new Error("collector timed out")));
    req.on("error", reject);
    req.end(body);
  });
}

function sendSyslog(config: AuditSinkConfig, timeoutMs: number): AuditSinkSend {
  return lines => new Promise<void>((resolve, reject) => {
    const payload = `${lines.join("\n")}\n`;
    let settled = false;
    const done = (error?: Error) => { if (settled) return; settled = true; socket.destroy(); if (error) reject(error); else resolve(); };
    const socket = config.transport === "syslog-tls"
      ? tls.connect({ host: config.host, port: config.port, servername: net.isIP(config.host) ? undefined : config.host })
      : net.connect({ host: config.host, port: config.port });
    socket.setTimeout(timeoutMs, () => done(new Error("collector timed out")));
    socket.on("error", error => done(error));
    socket.on("close", () => done(new Error("collector closed the connection before the batch was written")));
    socket.once(config.transport === "syslog-tls" ? "secureConnect" : "connect", () => {
      socket.write(payload, "utf8", error => { if (error) done(error); else socket.end(() => done()); });
    });
  });
}

const sleep = (ms: number, signal: AbortSignal): Promise<void> => new Promise(resolve => {
  if (signal.aborted) { resolve(); return; }
  const timer = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
  const onAbort = () => { clearTimeout(timer); resolve(); };
  signal.addEventListener("abort", onAbort, { once: true });
});

export function createAuditSink(options: AuditSinkOptions): AuditSink {
  const { config } = options;
  const intervalMs = options.intervalMs ?? 2000;
  const batchSize = options.batchSize ?? 100;
  const maxAttempts = Math.max(1, options.maxAttempts ?? 5);
  const baseDelayMs = options.baseDelayMs ?? 1000;
  const maxDelayMs = options.maxDelayMs ?? 30_000;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const send = options.send ?? (config.transport === "https" || config.transport === "http-loopback" ? sendHttp(config, timeoutMs) : sendSyslog(config, timeoutMs));
  const onStatus = options.onStatus ?? (line => { try { process.stderr.write(`${line}\n`); } catch { /* nothing to report to */ } });
  const abort = new AbortController();
  let stopped = false;
  let running: Promise<void> | undefined;
  let activePath: string | undefined;
  let cursor = 0;
  const state: AuditSinkStatus = { label: config.label, sent: 0, dropped: 0 };
  let reportedDropped = 0;
  let lastReportAt = 0;

  const statusLine = (): string => {
    const parts = [`audit sink ${state.label}: sent ${state.sent}`, `dropped ${state.dropped}`];
    if (state.dropped && state.lastError) parts.push(`last error: ${state.lastError}`);
    return parts.join(", ");
  };
  const reportDrops = (force = false) => {
    if (state.dropped === reportedDropped) return;
    const now = Date.now();
    if (!force && now - lastReportAt < 60_000) return;
    reportedDropped = state.dropped; lastReportAt = now;
    try { onStatus(statusLine()); } catch { /* reporting must not throw */ }
  };

  async function deliver(lines: string[], attempts: number): Promise<boolean> {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try { await send(lines); state.lastSuccessAt = new Date().toISOString(); return true; }
      catch (error) {
        state.lastError = (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").slice(0, 200);
        if (error instanceof PermanentSendError || attempt === attempts || stopped) return false;
        const delay = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
        await sleep(delay / 2 + Math.random() * (delay / 2), abort.signal);
        if (abort.signal.aborted) return false;
      }
    }
    return false;
  }

  async function drain(attempts: number): Promise<void> {
    const path = options.getDbPath();
    if (!path) return;
    const target = { dbPath: path };
    if (path !== activePath) { activePath = path; cursor = latestAuditId(target); } // follow a database switch without replaying history
    else if (latestAuditId(target) < cursor) cursor = 0; // the log was reset: start over with its new events
    for (;;) {
      let events;
      try { events = queryAuditEvents({ afterId: cursor, limit: batchSize }, target); } catch { return; }
      if (!events.length) return;
      const lines = events.map(event => formatAuditEvent(event, config.format, { host: options.host ?? "-", ...(options.version ? { version: options.version } : {}) }));
      if (await deliver(lines, attempts)) state.sent += events.length;
      else {
        state.dropped += events.length;
        reportDrops();
        if (stopped) return;
      }
      cursor = events.at(-1)!.id;
      if (events.length < batchSize || stopped) return;
    }
  }

  const poll = (): Promise<void> => {
    running ??= drain(maxAttempts).catch(() => { /* never surface */ }).finally(() => { running = undefined; });
    return running;
  };

  // Start after the newest existing event: history is the export command's job.
  const startPath = options.getDbPath();
  if (startPath) { activePath = startPath; cursor = latestAuditId({ dbPath: startPath }); }
  const timer = setInterval(() => { void poll(); }, intervalMs);
  timer.unref?.();

  return {
    status: () => ({ ...state }),
    statusLine,
    poll,
    async stop() {
      if (stopped) return;
      clearInterval(timer);
      // Let a batch in flight finish its current attempt; no more waiting between retries.
      stopped = true; abort.abort();
      await running;
      running = drain(1).catch(() => { /* never surface */ }).finally(() => { running = undefined; });
      await Promise.race([running, new Promise(resolve => { const t = setTimeout(resolve, timeoutMs); t.unref?.(); })]);
      reportDrops(true);
      try { onStatus(statusLine()); } catch { /* ignore */ }
    },
  };
}

/** Starts the sink when ZERO_AUDIT_SINK_URL is set. Throws AuditSinkConfigError for a refused setting, so a server does not start with a SIEM feed the operator believes is on. */
export function startAuditSinkFromEnv(options: Omit<AuditSinkOptions, "config"> & { env?: NodeJS.ProcessEnv }): AuditSink | null {
  const { env, ...rest } = options;
  const config = parseAuditSinkConfig(env ?? process.env);
  return config ? createAuditSink({ ...rest, config }) : null;
}
