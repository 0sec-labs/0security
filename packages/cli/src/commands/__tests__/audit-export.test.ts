import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeAuditLog, recordAudit } from "@0/engine/storage";
import { runAuditExport } from "../audit-log.js";

const dirs: string[] = [];
const workdir = () => { const dir = mkdtempSync(join(tmpdir(), "zero-audit-export-")); dirs.push(dir); return dir; };
afterEach(() => { closeAuditLog(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const fakeKey = ["sk", "-", "exportplanted", "0123456789abcdef"].join("");

function setup() {
  const dir = workdir();
  const dbPath = join(dir, "audit.db");
  const at = (day: number) => `2026-02-0${day}T10:00:00.000Z`;
  recordAudit({ actor: "cli", action: "findings.import.github", subject: "acme/app", ts: at(1), detail: { repo: "acme/app", count: 3 } }, { dbPath });
  recordAudit({ actor: "operator (browser)", action: "extension.install", subject: "acme/tool", ts: at(2), detail: { name: "tool", reason: `token=${fakeKey}`, prompt: "secret prompt" } }, { dbPath });
  recordAudit({ actor: "engine", action: "access.browser_only", subject: "/x", outcome: "denied", ts: at(3), detail: { code: "browser_only" } }, { dbPath });
  return { dir, dbPath };
}

async function run(options: Parameters<typeof runAuditExport>[0], dbPath: string, extra: Partial<Parameters<typeof runAuditExport>[1]> = {}) {
  const out: string[] = []; const err: string[] = []; let code = -1;
  await runAuditExport(options, { dbPath, out: line => out.push(line), err: line => err.push(line), setExitCode: value => { code = value; }, now: () => new Date("2026-02-10T10:00:00.000Z"), ...extra });
  return { out, err, code };
}

describe("0 config audit-log export", () => {
  it("prints NDJSON oldest first by default", async () => {
    const { dbPath } = setup();
    const { out, code } = await run({}, dbPath);
    expect(code).toBe(0);
    expect(out.map(line => JSON.parse(line).action)).toEqual(["findings.import.github", "extension.install", "access.browser_only"]);
    expect(JSON.parse(out[0]!)).toMatchObject({ schema: "0.audit.v1", seq: 1, ts: "2026-02-01T10:00:00.000Z", outcome: "ok" });
  });

  it("prints CEF and syslog", async () => {
    const { dbPath } = setup();
    const cef = await run({ format: "cef" }, dbPath);
    expect(cef.out).toHaveLength(3);
    expect(cef.out.every(line => line.startsWith("CEF:0|0security|0|"))).toBe(true);
    const syslog = await run({ format: "SYSLOG" }, dbPath);
    expect(syslog.out.every(line => /^<\d+>1 2026-02-0\dT10:00:00\.000Z /.test(line))).toBe(true);
    expect(syslog.out[2]).toMatch(/^<84>1 /);
  });

  it("filters by since, until, type and limit", async () => {
    const { dbPath } = setup();
    expect((await run({ since: "2026-02-02", until: "2026-02-03" }, dbPath)).out.map(l => JSON.parse(l).seq)).toEqual([2]);
    expect((await run({ since: "8d" }, dbPath)).out.map(l => JSON.parse(l).seq)).toEqual([2, 3]);
    expect((await run({ type: ["extension", "access"] }, dbPath)).out.map(l => JSON.parse(l).seq)).toEqual([2, 3]);
    expect((await run({ type: ["extension,findings"] }, dbPath)).out.map(l => JSON.parse(l).seq)).toEqual([1, 2]);
    expect((await run({ limit: "2" }, dbPath)).out.map(l => JSON.parse(l).seq)).toEqual([2, 3]);
  });

  it("keeps secret-looking values and fields the log does not store out of every format", async () => {
    const { dbPath } = setup();
    for (const format of ["ndjson", "cef", "syslog"]) {
      const text = (await run({ format }, dbPath)).out.join("\n");
      expect(text).not.toContain(fakeKey);
      expect(text).not.toContain("secret prompt");
      expect(text).toContain("[redacted]");
    }
  });

  it("writes -o files with owner-only permissions, even over an existing wider file", async () => {
    const { dir, dbPath } = setup();
    const file = join(dir, "export.ndjson");
    writeFileSync(file, "old", { mode: 0o644 });
    const { out, err, code } = await run({ output: file }, dbPath);
    expect(code).toBe(0);
    expect(out).toEqual([]);
    expect(err).toEqual([`Wrote 3 events to ${file}.`]);
    if (process.platform !== "win32") expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readFileSync(file, "utf8").trim().split("\n")).toHaveLength(3);
    expect(readFileSync(file, "utf8")).not.toContain("old");
  });

  it("rejects bad input with exit code 2", async () => {
    const { dbPath } = setup();
    for (const options of [{ format: "xml" }, { since: "soon" }, { limit: "0" }, { since: "2026-02-03", until: "2026-02-02" }, { follow: true, limit: "5" }]) {
      const result = await run(options, dbPath);
      expect(result.code).toBe(2);
      expect(result.err[0]).toMatch(/^error: /);
      expect(result.out).toEqual([]);
    }
  });

  it("with --follow, prints what exists and then new events until stopped", async () => {
    const { dbPath } = setup();
    const controller = new AbortController();
    const running = run({ follow: true, format: "ndjson" }, dbPath, { signal: controller.signal, pollMs: 10 });
    await new Promise(resolve => setTimeout(resolve, 60));
    recordAudit({ actor: "system", action: "late.event", subject: "s" }, { dbPath });
    await new Promise(resolve => setTimeout(resolve, 120));
    controller.abort();
    const { out, code } = await running;
    expect(code).toBe(0);
    expect(out.map(line => JSON.parse(line).action)).toEqual(["findings.import.github", "extension.install", "access.browser_only", "late.event"]);
  });
});
