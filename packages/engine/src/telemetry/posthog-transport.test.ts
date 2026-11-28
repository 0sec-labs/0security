import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hostname, userInfo } from "node:os";
import { eventBus } from "../events/bus.js";
import {
  analyticsPipeline,
  ANALYTICS_SENT_LOG_FILENAME,
  ANALYTICS_LAST_VERSION_FILENAME,
  FINDING_CLASSES,
  POSTHOG_LIFECYCLE_PROPERTY_KEYS,
  POSTHOG_PROPERTY_KEYS,
  POSTHOG_TIMEOUT_MS,
  classifyFindingClass,
} from "./analytics-pipeline.js";
import { VERSION } from "../shared/index.js";
import { DEFAULT_POSTHOG_HOST, normalizePostHogHost, resolvePostHogDestination } from "./posthog-destination.js";

const FAKE_KEY = "phc_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000";
const FAKE_HOST = "http://127.0.0.1:9";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const dirs: string[] = [];
let home: string;
let posts: Array<{ url: string; body: string }>;

function fakeFetch(behaviour: "ok" | "fail" | "hang" = "ok"): typeof fetch {
  return ((url: string | URL | Request, init?: RequestInit) => {
    posts.push({ url: String(url), body: String(init?.body ?? "") });
    if (behaviour === "fail") return Promise.reject(new Error("ECONNREFUSED internal.example"));
    if (behaviour === "hang") {
      return new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    }
    return Promise.resolve(new Response("{}", { status: 200 }));
  }) as unknown as typeof fetch;
}

function logPath(): string {
  return join(home, ".0", ANALYTICS_SENT_LOG_FILENAME);
}

function emitUsage(): void {
  eventBus.emit("tool_call_started", { tool: "http_request", turn: 0, args_preview: "GET https://victim.example/admin", ts: Date.now() });
  eventBus.emit("tool_call_started", { tool: "mcp__acme-internal__lookup", turn: 0, args_preview: "x", ts: Date.now() });
  eventBus.emit("tool_call_started", { tool: "my_secret_plugin_for_client_acme", turn: 0, args_preview: "x", ts: Date.now() });
  eventBus.emit("tool_call_completed", {
    tool: "shell", turn: 0, duration_ms: 5, status: "error",
    error: "spawn failed: ETIMEDOUT contacting 10.1.2.3 /Users/alice/secret.txt", ts: Date.now(),
  });
  eventBus.emit("finding_ingested", { severity: "high", category: "ssrf-at-victim.example", title: "Admin panel at victim.example", evidence: "password=hunter2" });
  eventBus.emit("cost_update", { cost_usd: 0.25 });
  eventBus.emit("agent_turn_completed", { turn: 0, duration_ms: 1200, reason: "finished" });
}

function allEvents(): Array<{ event: string; distinct_id: string; timestamp: string; properties: Record<string, unknown> }> {
  return posts.flatMap((p) => (JSON.parse(p.body) as { batch: never[] }).batch);
}

beforeEach(() => {
  analyticsPipeline.__resetForTests();
  posts = [];
  home = mkdtempSync(join(tmpdir(), "0-posthog-"));
  dirs.push(home);
  for (const name of ["ZERO_ANALYTICS_LEVEL", "ZERO_OFFLINE", "ZERO_NO_TELEMETRY", "DO_NOT_TRACK", "ZERO_ANALYTICS_POSTHOG_HOST"]) {
    vi.stubEnv(name, undefined);
  }
  vi.stubEnv("ZERO_ANALYTICS_POSTHOG_KEY", FAKE_KEY);
  vi.stubEnv("ZERO_ANALYTICS_POSTHOG_HOST", FAKE_HOST);
  analyticsPipeline.configure({ homeDir: home, fetchImpl: fakeFetch(), surface: "web", releaseChannel: "beta", knownToolNames: ["http_request", "shell"] });
});

afterEach(() => {
  analyticsPipeline.__resetForTests();
  vi.unstubAllEnvs();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("PostHog destination resolution", () => {
  it("uses the built-in key with the EU host when there is no override", () => {
    expect(resolvePostHogDestination({}, FAKE_KEY)).toEqual({ key: FAKE_KEY, host: DEFAULT_POSTHOG_HOST });
    expect(DEFAULT_POSTHOG_HOST).toBe("https://eu.i.posthog.com");
  });
  it("source and PR builds (no built-in key, no override) have no destination", () => {
    expect(resolvePostHogDestination({}, undefined)).toBeNull();
  });
  it("an override wins over the built-in key; an EMPTY override disables the path", () => {
    const other = "phc_OTHEROTHEROTHEROTHEROTHER0000";
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_KEY: other }, FAKE_KEY)?.key).toBe(other);
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_KEY: "" }, FAKE_KEY)).toBeNull();
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_KEY: "   " }, FAKE_KEY)).toBeNull();
  });
  it("rejects malformed keys and non-https / non-loopback hosts", () => {
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_KEY: "not-a-key" }, FAKE_KEY)).toBeNull();
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_HOST: "http://example.com" }, FAKE_KEY)).toBeNull();
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_HOST: "https://u:p@example.com" }, FAKE_KEY)).toBeNull();
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_HOST: "ftp://example.com" }, FAKE_KEY)).toBeNull();
    expect(normalizePostHogHost("https://ph.example.test/path/")).toBe("https://ph.example.test");
    expect(normalizePostHogHost("http://localhost:8123")).toBe("http://localhost:8123");
    expect(resolvePostHogDestination({ ZERO_ANALYTICS_POSTHOG_HOST: "https://ph.example.test" }, FAKE_KEY)).toEqual({ key: FAKE_KEY, host: "https://ph.example.test" });
  });
});

describe("anonymous usage to PostHog", () => {
  it("sends exactly the allowlisted property set, with anonymity flags and a random install id", async () => {
    analyticsPipeline.setLevel("usage");
    emitUsage();
    await analyticsPipeline.flushNow();

    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe(`${FAKE_HOST}/batch/`);
    const body = JSON.parse(posts[0].body) as { api_key: string; batch: unknown[] };
    expect(Object.keys(body).sort()).toEqual(["api_key", "batch"]);
    expect(body.api_key).toBe(FAKE_KEY);
    const [event] = allEvents();
    expect(Object.keys(event).sort()).toEqual(["distinct_id", "event", "properties", "timestamp"]);
    expect(event.event).toBe("usage");
    expect(Object.keys(event.properties).sort()).toEqual([...POSTHOG_PROPERTY_KEYS].sort());
    expect(event.properties).toMatchObject({
      tool_counts: { http_request: 1, mcp: 1, other: 1 },
      error_counts: { timeout: 1 },
      finding_severity_counts: { high: 1 },
      turn_count: 1, duration_ms: 1200, cost_usd: 0.25,
      surface: "web", channel: "beta", runtime: "node",
      $lib: "0security", $geoip_disable: true, $process_person_profile: false, $ip: null,
    });
    expect(typeof event.properties.version).toBe("string");
    expect(typeof event.properties.os).toBe("string");
    expect(typeof event.properties.arch).toBe("string");
    expect(Number.isNaN(Date.parse(event.timestamp))).toBe(false);

    // distinct_id is the persisted random install id: a UUID, no host or user data.
    const installId = readFileSync(join(home, ".0", "analytics-id"), "utf8").trim();
    expect(event.distinct_id).toBe(installId);
    expect(installId).toMatch(UUID);
    expect(installId.includes(hostname())).toBe(false);
    expect(installId.includes(userInfo().username)).toBe(false);
  });

  it("never serializes planted targets, urls, paths, finding text, messages or secrets", async () => {
    analyticsPipeline.setLevel("usage");
    emitUsage();
    // A hostile direct record: secrets in labels and extra unlisted fields.
    analyticsPipeline.__enqueueForTests({
      kind: "usage",
      featureCounts: { "sk-ABCDEFGHIJKLMNOPQRSTUVWX": 1, "https://victim.example/a?token=zzz": 1 },
      findingCounts: { "xss at victim.example": 1 },
      errorCategories: { "ECONNREFUSED 10.9.9.9": 1, "/Users/alice/.ssh/id_rsa": 1 },
      turnCount: 1, durationMs: 1,
      targetUrl: "https://victim.example", message: "hello secret message", path: "/Users/alice/x",
    });
    await analyticsPipeline.flushNow();
    const wire = posts.map((p) => p.body).join("\n");
    for (const planted of ["victim.example", "hunter2", "10.1.2.3", "10.9.9.9", "/Users/alice", "acme", "my_secret_plugin", "sk-ABCDEF", "hello secret", "targetUrl", "token=zzz", "Admin panel", "args_preview", "ssrf-at-victim", "spawn failed"]) {
      expect(wire, planted).not.toContain(planted);
    }
    for (const event of allEvents()) expect(Object.keys(event.properties).every((k) => (POSTHOG_PROPERTY_KEYS as readonly string[]).includes(k))).toBe(true);
  });

  it("sends deltas, not running totals, across successive snapshots", async () => {
    analyticsPipeline.setLevel("usage");
    eventBus.emit("tool_call_started", { tool: "shell", turn: 0, args_preview: "", ts: 1 });
    await analyticsPipeline.flushNow();
    eventBus.emit("tool_call_started", { tool: "shell", turn: 0, args_preview: "", ts: 2 });
    await analyticsPipeline.flushNow();
    expect(allEvents().map((e) => e.properties.tool_counts)).toEqual([{ shell: 1 }, { shell: 1 }]);
    // A flush with nothing new sends nothing.
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(2);
  });

  it("writes the transparency log without the api key", async () => {
    analyticsPipeline.setLevel("usage");
    emitUsage();
    await analyticsPipeline.flushNow();
    const log = readFileSync(logPath(), "utf8");
    expect(log).toContain('"event":"usage"');
    expect(log).not.toContain(FAKE_KEY);
  });

  it.each(["DO_NOT_TRACK", "ZERO_ENTERPRISE"])("%s wins: nothing sent, nothing queued, no install id", async (name) => {
    analyticsPipeline.setLevel("usage");
    vi.stubEnv(name, "1");
    emitUsage();
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { shell: 1 }, turnCount: 1, durationMs: 1 });
    expect(analyticsPipeline.__pendingCountForTests()).toBe(0);
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(0);
    expect(existsSync(logPath())).toBe(false);
    expect(existsSync(join(home, ".0", "analytics-id"))).toBe(false);
  });

  it.each(["ZERO_NO_TELEMETRY", "ZERO_OFFLINE"])("%s is not an analytics switch: usage still goes to PostHog", async (name) => {
    analyticsPipeline.setLevel("usage");
    vi.stubEnv(name, "1");
    emitUsage();
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe(`${FAKE_HOST}/batch/`);
  });

  it("a late opt-out drops already-queued records before they are sent", async () => {
    analyticsPipeline.setLevel("usage");
    emitUsage();
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { shell: 1 }, turnCount: 1, durationMs: 1 });
    expect(analyticsPipeline.__pendingCountForTests()).toBe(1);
    vi.stubEnv("DO_NOT_TRACK", "1");
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(0);
  });

  it("level off sends nothing and queues nothing", async () => {
    analyticsPipeline.setLevel("off");
    emitUsage();
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { shell: 1 }, turnCount: 1, durationMs: 1 });
    expect(analyticsPipeline.__pendingCountForTests()).toBe(0);
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(0);
  });

  it("no key (source or PR build) and an empty override send nothing and queue nothing", async () => {
    analyticsPipeline.setLevel("usage");
    for (const key of [undefined, ""]) {
      vi.stubEnv("ZERO_ANALYTICS_POSTHOG_KEY", key);
      emitUsage();
      analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { shell: 1 }, turnCount: 1, durationMs: 1 });
      expect(analyticsPipeline.__pendingCountForTests()).toBe(0);
      await analyticsPipeline.flushNow();
    }
    expect(posts).toHaveLength(0);
  });

  it("failure and timeout are silent and never throw", async () => {
    analyticsPipeline.configure({ fetchImpl: fakeFetch("fail") });
    analyticsPipeline.setLevel("usage");
    emitUsage();
    await expect(analyticsPipeline.flushNow()).resolves.toBeUndefined();
    expect(posts).toHaveLength(1);

    vi.useFakeTimers();
    try {
      analyticsPipeline.configure({ fetchImpl: fakeFetch("hang") });
      analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { shell: 1 }, turnCount: 1, durationMs: 1 });
      const flushed = analyticsPipeline.flushNow();
      await vi.advanceTimersByTimeAsync(POSTHOG_TIMEOUT_MS + 10);
      await expect(flushed).resolves.toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
    expect(POSTHOG_TIMEOUT_MS).toBeLessThanOrEqual(3000);
  });

  it("flushes the pending batch on demand (what the beforeExit hook calls)", async () => {
    analyticsPipeline.setLevel("usage");
    emitUsage();
    expect(posts).toHaveLength(0); // debounced, not yet sent
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(1);
  });
});

describe("finding classes on the usage event", () => {
  it("collapses categories onto the fixed class list and never sends category text", async () => {
    analyticsPipeline.setLevel("usage");
    eventBus.emit("finding_ingested", { severity: "high", category: "SQL Injection in /srv/acme/login.php" });
    eventBus.emit("finding_ingested", { severity: "low", category: "reflected-xss" });
    eventBus.emit("finding_ingested", { severity: "low", category: "weird-acme-internal-thing" });
    await analyticsPipeline.flushNow();
    const [event] = allEvents();
    expect(event.properties.finding_class_counts).toEqual({ "sql-injection": 1, xss: 1, other: 1 });
    expect(posts[0].body).not.toContain("acme");
    expect(posts[0].body).not.toContain("login.php");
    for (const name of Object.keys(event.properties.finding_class_counts as object)) expect(FINDING_CLASSES as readonly string[]).toContain(name);
  });
  it("does not match class words inside unrelated words", () => {
    for (const raw of ["random", "random number display", "session", "session list", "header", "page header", "author", "authors page", "authority", "authored by", "dependable", "secretary", "keyboard"]) {
      expect(classifyFindingClass(raw), raw).toBe("other");
    }
  });
  it("still matches the specific class phrases", () => {
    const cases: Array<[string, string]> = [
      ["Weak random number generator", "crypto"], ["Insecure randomness", "crypto"], ["insecure random", "crypto"],
      ["Session fixation", "auth"], ["Broken authentication", "auth"], ["missing authorization check", "auth"], ["auth bypass", "auth"], ["CSRF", "auth"],
      ["Missing security headers", "misconfiguration"], ["CORS wildcard", "misconfiguration"],
      ["Hardcoded API key", "secrets"], ["Hardcoded password", "secrets"], ["SQL injection", "sql-injection"], ["Stored XSS", "xss"],
      ["outdated dependency", "dependency"], ["Cryptographic failure", "crypto"],
    ];
    for (const [raw, expected] of cases) expect(classifyFindingClass(raw), raw).toBe(expected);
  });
  it("classifyFindingClass only ever returns a member of the fixed list", () => {
    for (const raw of ["ssrf", "Remote Code Execution", "path traversal", "hardcoded secret", "jwt none alg", "weak tls cipher", "unsafe deserialization", "vulnerable dependency", "cors misconfig", "???", ""]) {
      expect(FINDING_CLASSES as readonly string[]).toContain(classifyFindingClass(raw));
    }
  });
});

describe("lifecycle events (PostHog only)", () => {
  const LIFECYCLE = ["first_run", "command_invoked", "update", "error_exit"];

  afterEach(() => analyticsPipeline.setLifecycleSuppressed(false));

  it("a suppressed run queues no lifecycle event and mints no install id", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.setLifecycleSuppressed(true);
    analyticsPipeline.recordStartup({ command: "scan" });
    analyticsPipeline.recordLifecycle({ event: "error_exit", category: "crash" });
    expect(analyticsPipeline.hasPending()).toBe(false);
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(0);
    expect(existsSync(join(home, ".0", "analytics-id"))).toBe(false);
    expect(existsSync(join(home, ".0", ANALYTICS_LAST_VERSION_FILENAME))).toBe(false);
  });

  it("labels every event with ci from the CI variable, and sends it either way", async () => {
    const saved = process.env["CI"];
    try {
      for (const [value, expected] of [["1", true], ["true", true], ["0", false], ["false", false], [undefined, false]] as const) {
        posts.length = 0;
        analyticsPipeline.__resetForTests();
        analyticsPipeline.configure({ homeDir: home, fetchImpl: fakeFetch(), knownCommandNames: ["scan"] });
        if (value === undefined) delete process.env["CI"]; else process.env["CI"] = value;
        analyticsPipeline.setLevel("usage");
        analyticsPipeline.recordStartup({ command: "scan" });
        await analyticsPipeline.flushNow();
        const events = allEvents();
        expect(events.length).toBeGreaterThan(0);
        for (const event of events) expect(event.properties.ci).toBe(expected);
      }
    } finally {
      if (saved === undefined) delete process.env["CI"]; else process.env["CI"] = saved;
    }
  });

  it("a fresh install sends first_run then command_invoked, each with only its allowlisted properties", async () => {
    analyticsPipeline.configure({ knownCommandNames: ["scan", "scan web"] });
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordStartup({ command: "scan" });
    await analyticsPipeline.flushNow();
    const events = allEvents();
    expect(events.map((e) => e.event)).toEqual(["first_run", "command_invoked"]);
    for (const event of events) {
      const allowed = POSTHOG_LIFECYCLE_PROPERTY_KEYS[event.event as keyof typeof POSTHOG_LIFECYCLE_PROPERTY_KEYS];
      expect(Object.keys(event.properties).every((k) => allowed.includes(k))).toBe(true);
      expect(event.properties).toMatchObject({ surface: "web", channel: "beta", $geoip_disable: true, $process_person_profile: false, $ip: null, $lib: "0security" });
      expect(event.distinct_id).toBe(readFileSync(join(home, ".0", "analytics-id"), "utf8").trim());
    }
    expect(events[1].properties.command).toBe("scan");
    expect(events[0].properties.command).toBeUndefined();
  });

  it("first_run is sent only when this process minted the install id", async () => {
    mkdirSync(join(home, ".0"), { recursive: true });
    writeFileSync(join(home, ".0", "analytics-id"), "0b0f2b8e-3f6a-4c1d-9a55-2f4d6f1d7a10\n");
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordStartup({ command: "web" });
    await analyticsPipeline.flushNow();
    expect(allEvents().map((e) => e.event)).toEqual(["command_invoked"]);
  });

  it("a command outside the configured list collapses to other", async () => {
    analyticsPipeline.configure({ knownCommandNames: ["scan"] });
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordLifecycle({ event: "command_invoked", command: "scan --target https://victim.example/admin" });
    analyticsPipeline.recordLifecycle({ event: "command_invoked", command: undefined });
    await analyticsPipeline.flushNow();
    expect(allEvents().map((e) => e.properties.command)).toEqual(["other", "other"]);
    expect(posts[0].body).not.toContain("victim.example");
  });

  it("update is sent only when the version changed, and only for semver-shaped versions", async () => {
    mkdirSync(join(home, ".0"), { recursive: true });
    writeFileSync(join(home, ".0", "analytics-id"), "0b0f2b8e-3f6a-4c1d-9a55-2f4d6f1d7a10\n");
    writeFileSync(join(home, ".0", ANALYTICS_LAST_VERSION_FILENAME), "0.0.1\n");
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordStartup({ command: "web" });
    await analyticsPipeline.flushNow();
    const update = allEvents().find((e) => e.event === "update");
    if (VERSION === "0.0.1") {
      expect(update).toBeUndefined();
    } else {
      expect(update?.properties).toMatchObject({ from_version: "0.0.1", to_version: VERSION });
      expect(readFileSync(join(home, ".0", ANALYTICS_LAST_VERSION_FILENAME), "utf8").trim()).toBe(VERSION);
    }
    // Same version again: no update.
    posts.length = 0;
    analyticsPipeline.recordStartup({ command: "web" });
    await analyticsPipeline.flushNow();
    expect(allEvents().some((e) => e.event === "update")).toBe(false);
    // A malformed version never produces an update event.
    posts.length = 0;
    analyticsPipeline.recordLifecycle({ event: "update", fromVersion: "1.0.0", toVersion: "/Users/alice" });
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(0);
  });

  it("no stored last version (existing install before this feature) sends no update", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordStartup({ command: "web" });
    await analyticsPipeline.flushNow();
    expect(allEvents().some((e) => e.event === "update")).toBe(false);
  });

  it("error_exit carries a finite category only, never the error text", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordLifecycle({ event: "error_exit", error: new Error("connect ETIMEDOUT 10.1.2.3 /Users/alice/secret.txt password=hunter2") });
    analyticsPipeline.recordLifecycle({ event: "error_exit", error: new Error("something odd at victim.example") });
    analyticsPipeline.recordLifecycle({ event: "error_exit", category: "crash" });
    analyticsPipeline.recordLifecycle({ event: "error_exit", category: "free text category" });
    await analyticsPipeline.flushNow();
    expect(allEvents().map((e) => e.properties.error_category)).toEqual(["timeout", "other", "crash", "other"]);
    const body = posts.map((p) => p.body).join("");
    for (const planted of ["10.1.2.3", "alice", "hunter2", "victim.example", "free text"]) expect(body).not.toContain(planted);
  });

  for (const [name, value] of [["DO_NOT_TRACK", "1"]] as const) {
    it(`${name} sends nothing, queues nothing and mints no install id`, async () => {
      vi.stubEnv(name, value);
      analyticsPipeline.setLevel("usage");
      analyticsPipeline.recordStartup({ command: "web" });
      analyticsPipeline.recordLifecycle({ event: "error_exit", category: "crash" });
      expect(analyticsPipeline.__pendingCountForTests()).toBe(0);
      await analyticsPipeline.flushNow();
      expect(posts).toHaveLength(0);
      expect(existsSync(join(home, ".0", "analytics-id"))).toBe(false);
      expect(existsSync(join(home, ".0", ANALYTICS_LAST_VERSION_FILENAME))).toBe(false);
    });
  }

  it("level off, and a missing PostHog destination, queue nothing and mint no install id", async () => {
    analyticsPipeline.setLevel("off");
    analyticsPipeline.recordStartup({ command: "web" });
    expect(analyticsPipeline.__pendingCountForTests()).toBe(0);
    vi.stubEnv("ZERO_ANALYTICS_POSTHOG_KEY", "");
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordStartup({ command: "web" });
    expect(analyticsPipeline.__pendingCountForTests()).toBe(0);
    await analyticsPipeline.flushNow();
    expect(posts).toHaveLength(0);
    expect(existsSync(join(home, ".0", "analytics-id"))).toBe(false);
  });

  it("lifecycle events appear in the transparency log without the api key", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.recordStartup({ command: "web" });
    await analyticsPipeline.flushNow();
    const log = readFileSync(logPath(), "utf8");
    expect(log).toContain("command_invoked");
    expect(log).not.toContain(FAKE_KEY);
  });
});
