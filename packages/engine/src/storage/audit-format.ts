import { createHash } from "node:crypto";
import { redactAuditDetail, scrubAuditText, type AuditEvent, type AuditOutcome } from "./audit-log.js";

export const AUDIT_EXPORT_FORMATS = ["ndjson", "cef", "syslog"] as const;
export type AuditExportFormat = (typeof AUDIT_EXPORT_FORMATS)[number];
export const AUDIT_EXPORT_SCHEMA = "0.audit.v1";

/** Fields of one exported event. Documented in docs: Send the audit log to a SIEM. */
export interface AuditExportEvent {
  schema: typeof AUDIT_EXPORT_SCHEMA;
  /** Stable across exports and sinks: a hash of the sequence number and the event's own fields. Use it to deduplicate. */
  eventId: string;
  /** Position in the local log. Grows by one per event, restarts only if the database is reset. */
  seq: number;
  /** ISO 8601 UTC with milliseconds. */
  ts: string;
  actor: string;
  action: string;
  subject: string;
  outcome: AuditOutcome;
  detail: Record<string, unknown>;
}

export interface AuditFormatContext {
  /** Host name for syslog and CEF. Defaults to "-" (unknown). */
  host?: string;
  /** Product version for the CEF header and the syslog PROCID-free header. */
  version?: string;
}

const isoTime = (value: string): string => {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? value : new Date(parsed).toISOString();
};

/**
 * Builds the exported shape from a stored event. The text fields and the detail go through the log's own redaction
 * again, so a row written by an older version, or edited in the database file, cannot carry a secret-looking value out.
 */
export function toExportEvent(event: AuditEvent): AuditExportEvent {
  const actor = scrubAuditText(event.actor);
  const action = scrubAuditText(event.action);
  const subject = scrubAuditText(event.subject);
  const ts = isoTime(event.ts);
  const outcome: AuditOutcome = event.outcome === "denied" || event.outcome === "error" ? event.outcome : "ok";
  const eventId = createHash("sha256").update([event.id, ts, actor, action, subject, outcome].join("\n")).digest("hex").slice(0, 32);
  return { schema: AUDIT_EXPORT_SCHEMA, eventId, seq: event.id, ts, actor, action, subject, outcome, detail: redactAuditDetail(event.detail) };
}

const SYSLOG_SEVERITY: Record<AuditOutcome, number> = { ok: 6, denied: 4, error: 3 };
const SYSLOG_FACILITY_AUTHPRIV = 10;
const CEF_SEVERITY: Record<AuditOutcome, number> = { ok: 3, denied: 6, error: 7 };
/** Documentation enterprise number from RFC 5612. 0 has no registered number. */
export const SYSLOG_SD_ID = "audit@32473";

// eslint-disable-next-line no-control-regex
const CONTROL = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]", "g");
const printable = (value: string): string => value.replace(CONTROL, " ");

const sdValue = (value: string): string => printable(value).replace(/[\\"\]]/g, "\\$&");
const headerToken = (value: string, max: number): string => {
  const cleaned = value.replace(/[^!-~]/g, "_").slice(0, max);
  return cleaned || "-";
};

function toSyslog(event: AuditExportEvent, ctx: AuditFormatContext): string {
  const pri = SYSLOG_FACILITY_AUTHPRIV * 8 + SYSLOG_SEVERITY[event.outcome];
  const sd = `[${SYSLOG_SD_ID} eventId="${event.eventId}" seq="${event.seq}" actor="${sdValue(event.actor)}" action="${sdValue(event.action)}" subject="${sdValue(event.subject)}" outcome="${event.outcome}"]`;
  // The message is the full event as one JSON line, so a collector can parse it without knowing the structured data.
  return `<${pri}>1 ${event.ts} ${headerToken(ctx.host ?? "-", 255)} 0 - ${headerToken(event.action, 32)} ${sd} ${JSON.stringify(event)}`;
}

const cefHeader = (value: string): string => printable(value).replace(/[\\|]/g, "\\$&");
const cefExt = (value: string): string => value.replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/\r?\n|\r/g, "\\n").replace(CONTROL, " ");

function toCef(event: AuditExportEvent, ctx: AuditFormatContext): string {
  const header = ["CEF:0", "0security", "0", cefHeader(ctx.version ?? "0"), cefHeader(event.action), cefHeader(event.action), String(CEF_SEVERITY[event.outcome])].join("|");
  const time = Date.parse(event.ts);
  const ext = [
    ["externalId", event.eventId],
    ...(Number.isNaN(time) ? [] : [["rt", String(time)]]),
    ["suser", event.actor],
    ["act", event.action],
    ["outcome", event.outcome],
    ["cs1Label", "subject"], ["cs1", event.subject],
    ["cs2Label", "detail"], ["cs2", JSON.stringify(event.detail)],
    ["cn1Label", "seq"], ["cn1", String(event.seq)],
    ...(ctx.host && ctx.host !== "-" ? [["dvchost", ctx.host]] : []),
  ] as Array<[string, string]>;
  return `${header}|${ext.map(([key, value]) => `${key}=${cefExt(value)}`).join(" ")}`;
}

/** One line per event, no trailing newline. */
export function formatAuditEvent(event: AuditEvent, format: AuditExportFormat, ctx: AuditFormatContext = {}): string {
  const exported = toExportEvent(event);
  if (format === "cef") return toCef(exported, ctx);
  if (format === "syslog") return toSyslog(exported, ctx);
  return JSON.stringify(exported);
}

const DURATION = /^(\d+)\s*(s|m|h|d|w)$/i;
const UNIT_MS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 };

/** Accepts a duration back from now (30m, 24h, 7d, 2w) or a date or date-time Date.parse understands. Returns ISO UTC. */
export function parseAuditTime(input: string, now: Date = new Date()): string {
  const text = input.trim();
  const duration = DURATION.exec(text);
  if (duration) return new Date(now.getTime() - Number(duration[1]) * UNIT_MS[duration[2]!.toLowerCase()]!).toISOString();
  // A bare date has no zone: treat it as UTC midnight so the result does not depend on the machine.
  const parsed = /^\d{4}-\d{2}-\d{2}$/.test(text) ? Date.parse(`${text}T00:00:00.000Z`) : Date.parse(text);
  if (Number.isNaN(parsed)) throw new Error(`Cannot read "${input}" as a time. Use a duration such as 24h or 7d, or a date such as 2026-01-31 or 2026-01-31T08:00:00Z.`);
  return new Date(parsed).toISOString();
}
