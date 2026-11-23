import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { createServer as createTcpServer, type Server as TcpServer } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeAuditLog, recordAudit } from "./audit-log.js";
import { createAuditSink, parseAuditSinkConfig, startAuditSinkFromEnv, AuditSinkConfigError, type AuditSink } from "./audit-sink.js";

const dirs: string[] = [];
const sinks: AuditSink[] = [];
const servers: Array<HttpServer | TcpServer> = [];
const fresh = () => { const dir = mkdtempSync(join(tmpdir(), "zero-audit-sink-")); dirs.push(dir); return { dbPath: join(dir, "audit.db") }; };
afterEach(async () => {
  for (const sink of sinks.splice(0)) await sink.stop();
  for (const server of servers.splice(0)) await new Promise<void>(resolve => { server.close(() => resolve()); (server as HttpServer).closeAllConnections?.(); });
  closeAuditLog();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const url = (value: string, extra: NodeJS.ProcessEnv = {}) => ({ ZERO_AUDIT_SINK_URL: value, ...extra });

describe("parseAuditSinkConfig", () => {
  it("is off when the variable is unset or empty", () => {
    expect(parseAuditSinkConfig({})).toBeNull();
    expect(parseAuditSinkConfig(url("  "))).toBeNull();
  });
  it("accepts https and syslog over TLS", () => {
    expect(parseAuditSinkConfig(url("https://siem.example.net/ingest?x=1"))).toMatchObject({ transport: "https", port: 443, format: "ndjson", label: "https://siem.example.net" });
    expect(parseAuditSinkConfig(url("syslog+tls://logs.example.net"))).toMatchObject({ transport: "syslog-tls", port: 6514, format: "syslog" });
    expect(parseAuditSinkConfig(url("syslog+tls://logs.example.net:7000"))).toMatchObject({ port: 7000 });
    expect(parseAuditSinkConfig(url("https://siem.example.net/in", { ZERO_AUDIT_SINK_FORMAT: "cef", ZERO_AUDIT_SINK_TOKEN: "t" }))).toMatchObject({ format: "cef", token: "t" });
  });
  it("accepts plain http and plain TCP only to this machine", () => {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      expect(parseAuditSinkConfig(url(`http://${host}:8080/x`))).toMatchObject({ transport: "http-loopback" });
      expect(parseAuditSinkConfig(url(`syslog+tcp://${host}:5140`))).toMatchObject({ transport: "syslog-tcp-loopback" });
    }
  });
  it("refuses insecure or unclear settings", () => {
    const refused = (value: string, pattern: RegExp, extra: NodeJS.ProcessEnv = {}) => {
      expect(() => parseAuditSinkConfig(url(value, extra))).toThrow(AuditSinkConfigError);
      expect(() => parseAuditSinkConfig(url(value, extra))).toThrow(pattern);
    };
    refused("http://siem.example.net/in", /plain http/);
    refused("http://127.0.0.1.example.net/in", /plain http/);
    refused("syslog+tcp://logs.example.net:514", /plain TCP/);
    refused("syslog://logs.example.net:514", /UDP/);
    refused("udp://logs.example.net:514", /UDP/);
    refused("syslog+udp://logs.example.net:514", /UDP/);
    refused("logs.example.net:6514", /no host|unsupported scheme/);
    refused("ftp://logs.example.net", /unsupported scheme/);
    refused("https://user:pass@siem.example.net/in", /user name or password/);
    refused("https://siem.example.net/in", /must be one of/, { ZERO_AUDIT_SINK_FORMAT: "xml" });
    refused("syslog+tls://logs.example.net", /syslog lines/, { ZERO_AUDIT_SINK_FORMAT: "cef" });
  });
  it("makes a server refuse to start the sink on a refused setting", () => {
    expect(() => startAuditSinkFromEnv({ getDbPath: () => undefined, env: url("syslog://logs.example.net") })).toThrow(AuditSinkConfigError);
    expect(startAuditSinkFromEnv({ getDbPath: () => undefined, env: {} })).toBeNull();
  });
});

interface Received { method?: string; headers: IncomingMessage["headers"]; body: string }
async function fakeCollector(handler: (request: Received, attempt: number) => number) {
  const received: Received[] = [];
  let attempt = 0;
  const server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", chunk => chunks.push(chunk as Buffer));
    req.on("end", () => {
      const entry = { method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") };
      received.push(entry);
      attempt += 1;
      res.statusCode = handler(entry, attempt);
      res.end();
    });
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as { port: number }).port;
  return { received, port };
}

const fast = { intervalMs: 3_600_000, baseDelayMs: 1, maxDelayMs: 5, timeoutMs: 2000 };
const start = (env: NodeJS.ProcessEnv, target: { dbPath: string }, extra: Partial<Parameters<typeof createAuditSink>[0]> = {}) => {
  const config = parseAuditSinkConfig(env)!;
  const sink = createAuditSink({ config, getDbPath: () => target.dbPath, host: "h", version: "9", onStatus: () => {}, ...fast, ...extra });
  sinks.push(sink);
  return sink;
};

describe("audit sink over HTTP", () => {
  it("sends new events in batches as NDJSON with the bearer token, and not the history", async () => {
    const target = fresh();
    recordAudit({ actor: "system", action: "before.start" }, target);
    const { received, port } = await fakeCollector(() => 200);
    const sink = start(url(`http://127.0.0.1:${port}/ingest`, { ZERO_AUDIT_SINK_TOKEN: "collector-token" }), target, { batchSize: 2 });
    for (let i = 0; i < 5; i++) recordAudit({ actor: "system", action: `new.${i}`, subject: `s${i}` }, target);
    await sink.poll();
    expect(received.map(r => r.body.trim().split("\n").length)).toEqual([2, 2, 1]);
    const lines = received.flatMap(r => r.body.trim().split("\n")).map(line => JSON.parse(line) as { action: string; schema: string });
    expect(lines.map(l => l.action)).toEqual(["new.0", "new.1", "new.2", "new.3", "new.4"]);
    expect(lines[0]!.schema).toBe("0.audit.v1");
    expect(received[0]!.method).toBe("POST");
    expect(received[0]!.headers["content-type"]).toBe("application/x-ndjson");
    expect(received[0]!.headers.authorization).toBe("Bearer collector-token");
    expect(sink.status()).toMatchObject({ sent: 5, dropped: 0 });
    await sink.poll();
    expect(received).toHaveLength(3);
  });

  it("retries a failing collector with backoff and delivers once it recovers", async () => {
    const target = fresh();
    const { received, port } = await fakeCollector((_r, attempt) => (attempt < 3 ? 503 : 200));
    const sink = start(url(`http://127.0.0.1:${port}/`), target);
    recordAudit({ actor: "system", action: "retry.me" }, target);
    await sink.poll();
    expect(received).toHaveLength(3);
    expect(sink.status()).toMatchObject({ sent: 1, dropped: 0 });
    expect(sink.status().lastSuccessAt).toBeTruthy();
  });

  it("drops and counts a batch after the retries run out, then keeps going, and reports a status line", async () => {
    const target = fresh();
    const reports: string[] = [];
    const { received, port } = await fakeCollector((_r, attempt) => (attempt <= 3 ? 500 : 200));
    const sink = start(url(`http://127.0.0.1:${port}/`), target, { maxAttempts: 3, onStatus: line => reports.push(line) });
    recordAudit({ actor: "system", action: "lost" }, target);
    await sink.poll();
    expect(received).toHaveLength(3);
    expect(sink.status()).toMatchObject({ sent: 0, dropped: 1 });
    expect(reports[0]).toBe("audit sink http://127.0.0.1:" + port + ": sent 0, dropped 1, last error: collector answered HTTP 500");
    recordAudit({ actor: "system", action: "kept" }, target);
    await sink.poll();
    expect(sink.status()).toMatchObject({ sent: 1, dropped: 1 });
  });

  it("does not retry a refusal such as 401, and never echoes the token or path in the status line", async () => {
    const target = fresh();
    const { received, port } = await fakeCollector(() => 401);
    const sink = start(url(`http://127.0.0.1:${port}/secret-path?key=abc`, { ZERO_AUDIT_SINK_TOKEN: "collector-token" }), target);
    recordAudit({ actor: "system", action: "x" }, target);
    await sink.poll();
    expect(received).toHaveLength(1);
    expect(sink.statusLine()).not.toMatch(/collector-token|secret-path|key=abc/);
  });

  it("does not delay or fail the code that writes the log when the collector is down", async () => {
    const target = fresh();
    const sink = start(url("http://127.0.0.1:9/never"), target, { maxAttempts: 2 });
    const started = Date.now();
    for (let i = 0; i < 50; i++) recordAudit({ actor: "system", action: `a.${i}` }, target);
    // The writes are synchronous and never wait for the sink; the ceiling only catches a hang, so it is generous for loaded CI machines.
    expect(Date.now() - started).toBeLessThan(10_000);
    await sink.poll();
    expect(sink.status()).toMatchObject({ sent: 0, dropped: 50 });
  }, 30_000);

  it("follows a switch to another database without replaying its history", async () => {
    const first = fresh(); const second = fresh();
    let active = first.dbPath;
    const { received, port } = await fakeCollector(() => 200);
    const config = parseAuditSinkConfig(url(`http://127.0.0.1:${port}/`))!;
    const sink = createAuditSink({ config, getDbPath: () => active, onStatus: () => {}, ...fast });
    sinks.push(sink);
    recordAudit({ actor: "system", action: "old.db" }, second);
    active = second.dbPath;
    await sink.poll();
    expect(received).toHaveLength(0);
    recordAudit({ actor: "system", action: "new.db" }, second);
    await sink.poll();
    expect(received.map(r => JSON.parse(r.body.trim()).action)).toEqual(["new.db"]);
  });

  it("sends the redacted event only", async () => {
    const target = fresh();
    const fake = ["sk", "-", "sinkplanted", "0123456789abcdef"].join("");
    const { received, port } = await fakeCollector(() => 200);
    const sink = start(url(`http://127.0.0.1:${port}/`), target);
    recordAudit({ actor: "system", action: "settings.change", subject: "k", detail: { key: "k", reason: `token=${fake}`, prompt: "hidden prompt" } }, target);
    await sink.poll();
    expect(received[0]!.body).not.toContain(fake);
    expect(received[0]!.body).not.toContain("hidden prompt");
  });
});

describe("audit sink over TCP syslog", () => {
  it("writes newline-terminated RFC 5424 lines to a listener", async () => {
    const target = fresh();
    const chunks: string[] = [];
    const server = createTcpServer(socket => { socket.on("data", data => chunks.push(data.toString("utf8"))); });
    servers.push(server);
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as { port: number }).port;
    const sink = start(url(`syslog+tcp://127.0.0.1:${port}`), target);
    recordAudit({ actor: "operator (browser)", action: "settings.change", subject: "theme", detail: { key: "theme" } }, target);
    recordAudit({ actor: "engine", action: "access.browser_only", outcome: "denied" }, target);
    await sink.poll();
    await new Promise(resolve => setTimeout(resolve, 50));
    const lines = chunks.join("").split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^<86>1 \d{4}-\d{2}-\d{2}T[\d:.]+Z h 0 - settings\.change \[audit@32473 /);
    expect(lines[1]).toMatch(/^<84>1 /);
    expect(sink.status()).toMatchObject({ sent: 2, dropped: 0 });
  });

  it("counts a refused connection as dropped", async () => {
    const target = fresh();
    const sink = start(url("syslog+tcp://127.0.0.1:9"), target, { maxAttempts: 2 });
    recordAudit({ actor: "system", action: "x" }, target);
    await sink.poll();
    expect(sink.status()).toMatchObject({ sent: 0, dropped: 1 });
  });
});
