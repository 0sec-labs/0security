import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AUDIT_EXPORT_FORMATS, formatAuditEvent, parseAuditTime, toExportEvent } from "./audit-format.js";
import { closeAuditLog, queryAuditEvents, recordAudit, type AuditEvent } from "./audit-log.js";

const dirs: string[] = [];
const fresh = () => { const dir = mkdtempSync(join(tmpdir(), "zero-audit-fmt-")); dirs.push(dir); return { dbPath: join(dir, "audit.db") }; };
afterEach(() => { closeAuditLog(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

// Built at runtime so no provider-shaped key sits in the repository.
const fakeKey = ["sk", "-", "planted", "0123456789abcdefghij"].join("");
const fakeToken = ["gh", "p_", "0123456789abcdefghijklmn"].join("");

const sample: AuditEvent = {
  id: 42, ts: "2026-03-04T05:06:07.089Z", actor: "operator (browser)", action: "extension.install", subject: "acme/tool",
  outcome: "ok", detail: { name: "tool", version: "abc123def456", approved: true },
};
const ctx = { host: "console-1", version: "1.2.3" };

describe("audit export formats", () => {
  it("lists the three formats", () => { expect(AUDIT_EXPORT_FORMATS).toEqual(["ndjson", "cef", "syslog"]); });

  it("gives a stable event id for the same event and a different one when anything changes", () => {
    const a = toExportEvent(sample);
    expect(toExportEvent({ ...sample }).eventId).toBe(a.eventId);
    expect(a.eventId).toMatch(/^[0-9a-f]{32}$/);
    expect(toExportEvent({ ...sample, id: 43 }).eventId).not.toBe(a.eventId);
    expect(toExportEvent({ ...sample, subject: "acme/other" }).eventId).not.toBe(a.eventId);
  });

  it("writes NDJSON", () => {
    const line = formatAuditEvent(sample, "ndjson", ctx);
    expect(JSON.parse(line)).toEqual({ schema: "0.audit.v1", eventId: toExportEvent(sample).eventId, seq: 42, ts: "2026-03-04T05:06:07.089Z", actor: "operator (browser)", action: "extension.install", subject: "acme/tool", outcome: "ok", detail: { name: "tool", version: "abc123def456", approved: true } });
    expect(line).not.toContain("\n");
  });

  it("writes CEF", () => {
    const id = toExportEvent(sample).eventId;
    expect(formatAuditEvent(sample, "cef", ctx)).toBe(
      `CEF:0|0security|0|1.2.3|extension.install|extension.install|3|externalId=${id} rt=1772600767089 suser=operator (browser) act=extension.install outcome=ok cs1Label=subject cs1=acme/tool cs2Label=detail cs2={"name":"tool","version":"abc123def456","approved":true} cn1Label=seq cn1=42 dvchost=console-1`,
    );
  });

  it("writes RFC 5424 syslog", () => {
    const id = toExportEvent(sample).eventId;
    const line = formatAuditEvent(sample, "syslog", ctx);
    expect(line.startsWith(`<86>1 2026-03-04T05:06:07.089Z console-1 0 - extension.install [audit@32473 eventId="${id}" seq="42" actor="operator (browser)" action="extension.install" subject="acme/tool" outcome="ok"] {`)).toBe(true);
    expect(JSON.parse(line.slice(line.indexOf("] {") + 2))).toMatchObject({ seq: 42, action: "extension.install" });
  });

  it("maps outcomes to syslog and CEF severity", () => {
    expect(formatAuditEvent({ ...sample, outcome: "denied" }, "syslog", ctx)).toMatch(/^<84>1 /);
    expect(formatAuditEvent({ ...sample, outcome: "error" }, "syslog", ctx)).toMatch(/^<83>1 /);
    expect(formatAuditEvent({ ...sample, outcome: "denied" }, "cef", ctx)).toMatch(/^CEF:0\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|6\|/);
    expect(formatAuditEvent({ ...sample, outcome: "error" }, "cef", ctx)).toMatch(/\|7\|/);
  });

  it("escapes the characters that break each format and keeps one line per event", () => {
    const nasty: AuditEvent = { ...sample, action: "a|b", subject: "x=1\\2\nINJECT] \"q\"", actor: "me\r\nfake" };
    for (const format of AUDIT_EXPORT_FORMATS) expect(formatAuditEvent(nasty, format, ctx)).not.toMatch(/[\r\n]/);
    expect(formatAuditEvent(nasty, "cef", ctx)).toContain("|a\\|b|a\\|b|");
    expect(formatAuditEvent(nasty, "cef", ctx)).toContain("cs1=x\\=1\\\\2\\nINJECT]");
    const syslog = formatAuditEvent(nasty, "syslog", ctx);
    expect(syslog).toContain('subject="x=1\\\\2 INJECT\\] \\"q\\""');
    expect(syslog).toContain(" a|b [audit@32473");
  });

  it("never lets a secret-looking value reach any format, even from a row that skipped the writer's redaction", () => {
    const planted: AuditEvent = {
      ...sample, actor: `op ${fakeToken}`, action: "settings.change", subject: `token=${fakeKey}`,
      detail: { key: "providerApiKey", old: fakeKey, new: fakeKey, reason: `Bearer ${fakeToken}`, apiKey: fakeKey, evidence: "body", prompt: "write a poem", env: { A: fakeKey } },
    };
    for (const format of AUDIT_EXPORT_FORMATS) {
      const line = formatAuditEvent(planted, format, ctx);
      expect(line).not.toContain(fakeKey);
      expect(line).not.toContain(fakeToken);
      expect(line).not.toMatch(/0123456789abcdefghij/);
      expect(line).not.toContain("write a poem");
      expect(line).not.toContain("evidence");
    }
  });

  it("exports a planted value from the real log without it, and drops fields the log does not store", () => {
    const target = fresh();
    recordAudit({ actor: "operator (browser)", action: "extension.install", subject: "acme/tool", detail: { name: "tool", reason: `token=${fakeKey}`, source: fakeToken, headers: { Authorization: `Bearer ${fakeKey}` }, prompt: "secret prompt text", body: "evidence body text" } }, target);
    const events = queryAuditEvents({}, target);
    expect(events).toHaveLength(1);
    for (const format of AUDIT_EXPORT_FORMATS) {
      const line = formatAuditEvent(events[0]!, format, ctx);
      expect(line).not.toContain(fakeKey);
      expect(line).not.toContain(fakeToken);
      expect(line).not.toContain("secret prompt text");
      expect(line).not.toContain("evidence body text");
      expect(line).toContain("[redacted]");
    }
  });

  it("writes ISO timestamps for stored times in other forms", () => {
    expect(toExportEvent({ ...sample, ts: "2026-03-04T06:06:07+01:00" }).ts).toBe("2026-03-04T05:06:07.000Z");
    expect(toExportEvent({ ...sample, ts: "not a time" }).ts).toBe("not a time");
  });
});

describe("parseAuditTime", () => {
  const now = new Date("2026-03-04T12:00:00.000Z");
  it("reads durations back from now", () => {
    expect(parseAuditTime("30m", now)).toBe("2026-03-04T11:30:00.000Z");
    expect(parseAuditTime("24h", now)).toBe("2026-03-03T12:00:00.000Z");
    expect(parseAuditTime("7d", now)).toBe("2026-02-25T12:00:00.000Z");
    expect(parseAuditTime("2w", now)).toBe("2026-02-18T12:00:00.000Z");
  });
  it("reads dates as UTC and date-times with their zone", () => {
    expect(parseAuditTime("2026-01-31", now)).toBe("2026-01-31T00:00:00.000Z");
    expect(parseAuditTime("2026-01-31T08:00:00+02:00", now)).toBe("2026-01-31T06:00:00.000Z");
  });
  it("rejects anything else", () => { expect(() => parseAuditTime("yesterday-ish", now)).toThrow(/Cannot read/); });
});

describe("queryAuditEvents", () => {
  const seed = (target: { dbPath: string }) => {
    const times = ["2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z", "2026-01-03T00:00:00.000Z", "2026-01-04T00:00:00.000Z"];
    const actions = ["extension.install", "extension.remove", "settings.change", "extensionless.thing"];
    actions.forEach((action, index) => recordAudit({ actor: "system", action, subject: `s${index}`, ts: times[index]! }, target));
  };
  it("returns oldest first and filters by time", () => {
    const target = fresh(); seed(target);
    expect(queryAuditEvents({}, target).map(e => e.subject)).toEqual(["s0", "s1", "s2", "s3"]);
    expect(queryAuditEvents({ since: "2026-01-02T00:00:00.000Z", until: "2026-01-04T00:00:00.000Z" }, target).map(e => e.subject)).toEqual(["s1", "s2"]);
  });
  it("filters by exact action or dotted prefix, not by loose substring", () => {
    const target = fresh(); seed(target);
    expect(queryAuditEvents({ types: ["extension"] }, target).map(e => e.subject)).toEqual(["s0", "s1"]);
    expect(queryAuditEvents({ types: ["extension.remove", "settings.change"] }, target).map(e => e.subject)).toEqual(["s1", "s2"]);
    expect(queryAuditEvents({ types: ["ext%"] }, target)).toEqual([]);
  });
  it("keeps the newest events under a limit, or the oldest when resuming after an id", () => {
    const target = fresh(); seed(target);
    expect(queryAuditEvents({ limit: 2 }, target).map(e => e.subject)).toEqual(["s2", "s3"]);
    expect(queryAuditEvents({ afterId: 1, limit: 2 }, target).map(e => e.subject)).toEqual(["s1", "s2"]);
  });
});
