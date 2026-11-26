import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { syncBuiltinESMExports } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ENTERPRISE_ENV, EnterpriseEgressError, assertEgressAllowed, enterpriseMode } from "./enterprise.js";
import { analyticsPipeline } from "../telemetry/analytics-pipeline.js";
import { eventBus } from "../events/bus.js";
import { analyticsOptedOut, resolveAnalyticsLevel } from "../telemetry/analytics-level.js";
import { discoverAndRegisterPricing } from "../shared/pricing-discovery.js";
import { checkBomAgainstOsv } from "../sbom/osv.js";
import { GitSource } from "../plugins/extensions/adapters/git-source.js";
import { features as featureFlags } from "../agent/features.js";
import { ToolExecutor } from "../agent/tools.js";
import { resolveSmolvmRuntime } from "../runtime/smolvm-provision.js";

/**
 * Egress test for ZERO_ENTERPRISE=1. Every outbound primitive (fetch, node:http(s), net sockets) is patched to
 * record the destination; the only destination allowed is a local stub model server. Each engine call site from
 * scripts/egress-inventory.json that the switch blocks runs here, and the test fails on any other connection.
 */

interface Attempt { via: string; target: string }
let attempts: Attempt[];
let stubPort: number;
let stub: http.Server;
const restore: Array<() => void> = [];

const hostOf = (input: unknown): string => {
  if (typeof input === "string") { try { const url = new URL(input); return url.host; } catch { return input; } }
  if (input instanceof URL) return input.host;
  if (input && typeof input === "object" && "url" in input) return hostOf((input as { url: string }).url);
  if (input && typeof input === "object") { const o = input as { host?: string; hostname?: string; port?: number | string }; return `${o.hostname ?? o.host ?? "unknown"}${o.port ? `:${o.port}` : ""}`; }
  return String(input);
};

function patch<T extends object, K extends keyof T>(target: T, key: K, replacement: T[K]): void {
  const original = target[key];
  target[key] = replacement;
  restore.push(() => { target[key] = original; });
}

function installEgressGuard(): void {
  const realFetch = globalThis.fetch;
  patch(globalThis, "fetch", (async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = hostOf(input);
    attempts.push({ via: "fetch", target });
    if (target === `127.0.0.1:${stubPort}`) return realFetch(input, init);
    throw new Error(`egress blocked by test: ${target}`);
  }) as typeof fetch);
  for (const mod of [http, https] as const) {
    for (const name of ["request", "get"] as const) {
      patch(mod as never, name as never, ((...args: unknown[]) => {
        const first = args[0];
        const target = hostOf(first);
        attempts.push({ via: `${mod === http ? "http" : "https"}.${name}`, target });
        throw new Error(`egress blocked by test: ${target}`);
      }) as never);
    }
  }
  const proto = net.Socket.prototype as unknown as { connect: (...args: unknown[]) => unknown };
  const realConnect = proto.connect;
  patch(proto, "connect", function (this: net.Socket, ...args: unknown[]) {
    // net.connect passes its already-normalized `[options, callback]` tuple.
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const options = typeof first === "object" && first !== null ? first as { port?: number; host?: string; path?: string } : { port: Number(first), host: typeof args[1] === "string" ? args[1] : "localhost" };
    const target = options.path ? `unix:${options.path}` : `${options.host ?? "localhost"}:${options.port}`;
    if (!isStub(options)) attempts.push({ via: "net.connect", target });
    return realConnect.apply(this, args);
  } as never);
  syncBuiltinESMExports();
  restore.push(() => syncBuiltinESMExports());
}

const isStub = (o: { port?: number; host?: string }) => o.port === stubPort && (o.host === "127.0.0.1" || o.host === "localhost" || o.host === undefined);
const stubModelRequests: string[] = [];
beforeEach(async () => {
  attempts = [];
  stubModelRequests.length = 0;
  stub = http.createServer((req, res) => { stubModelRequests.push(req.url ?? ""); res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ data: [] })); });
  await new Promise<void>(resolve => stub.listen(0, "127.0.0.1", resolve));
  stubPort = (stub.address() as net.AddressInfo).port;
  installEgressGuard();
});
afterEach(async () => {
  while (restore.length) restore.pop()!();
  vi.unstubAllEnvs();
  analyticsPipeline.__resetForTests();
  await new Promise<void>(resolve => stub.close(() => resolve()));
});

const enterprise = () => {
  for (const name of ["ZERO_OFFLINE", "DO_NOT_TRACK", "ZERO_ANALYTICS_LEVEL"]) vi.stubEnv(name, undefined);
  vi.stubEnv(ENTERPRISE_ENV, "1");
};

describe("the egress guard itself", () => {
  it("records a connection to anything but the stub and lets the stub through", async () => {
    await expect(fetch("https://example.invalid/x")).rejects.toThrow(/egress blocked/);
    await fetch(`http://127.0.0.1:${stubPort}/v1/models`);
    expect(attempts.filter(a => a.target !== `127.0.0.1:${stubPort}`)).toEqual([{ via: "fetch", target: "example.invalid" }]);
    expect(stubModelRequests).toEqual(["/v1/models"]);
  });
  it("sees node:http requests and raw sockets", () => {
    expect(() => http.request("http://example.invalid/")).toThrow();
    expect(() => https.get("https://example.invalid/")).toThrow();
    expect(attempts.map(a => a.via)).toEqual(["http.request", "https.get"]);
  });
  it("control: without the switch the analytics pipeline does try to leave", async () => {
    for (const name of ["ZERO_OFFLINE", "DO_NOT_TRACK", "ZERO_ANALYTICS_LEVEL", ENTERPRISE_ENV]) vi.stubEnv(name, undefined);
    vi.stubEnv("ZERO_ANALYTICS_POSTHOG_KEY", "phc_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000");
    vi.stubEnv("ZERO_ANALYTICS_POSTHOG_HOST", "https://ph.example.test");
    const home = mkdtempSync(join(tmpdir(), "0-egress-"));
    try {
      analyticsPipeline.__resetForTests();
      analyticsPipeline.configure({ homeDir: home, surface: "cli", releaseChannel: "beta", knownToolNames: ["shell"] });
      analyticsPipeline.setLevel("usage");
      eventBus.emit("cost_update", { cost_usd: 0.1 });
      eventBus.emit("agent_turn_completed", { turn: 0, duration_ms: 5, reason: "finished" });
      await analyticsPipeline.flushNow();
      expect(attempts.some(a => a.target === "ph.example.test")).toBe(true);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

describe("ZERO_ENTERPRISE", () => {
  it("is read from the environment with the same truthiness as the other opt-outs", () => {
    expect(enterpriseMode({})).toBe(false);
    for (const value of ["", "0", "false", "no", " NO "]) expect(enterpriseMode({ [ENTERPRISE_ENV]: value })).toBe(false);
    for (const value of ["1", "true", "yes", "on"]) expect(enterpriseMode({ [ENTERPRISE_ENV]: value })).toBe(true);
  });
  it("does not control analytics: DO_NOT_TRACK is the only opt-out", () => {
    expect(analyticsOptedOut({ [ENTERPRISE_ENV]: "1" })).toBe(false);
    expect(analyticsOptedOut({ DO_NOT_TRACK: "1" })).toBe(true);
    expect(resolveAnalyticsLevel({ DO_NOT_TRACK: "1" })).toBe("off");
    expect(resolveAnalyticsLevel({})).toBe("usage");
  });
  it("assertEgressAllowed throws a typed error naming the destination", () => {
    expect(() => assertEgressAllowed("example.invalid", {})).not.toThrow();
    expect(() => assertEgressAllowed("example.invalid", { [ENTERPRISE_ENV]: "1" })).toThrow(EnterpriseEgressError);
  });

  it("usage analytics send nothing under DO_NOT_TRACK", async () => {
    enterprise();
    vi.stubEnv("DO_NOT_TRACK", "1");
    vi.stubEnv("ZERO_ANALYTICS_POSTHOG_KEY", "phc_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000");
    vi.stubEnv("ZERO_ANALYTICS_POSTHOG_HOST", "https://ph.example.test");
    const home = mkdtempSync(join(tmpdir(), "0-egress-"));
    try {
      analyticsPipeline.__resetForTests();
      analyticsPipeline.configure({ homeDir: home, surface: "cli", releaseChannel: "beta", knownToolNames: ["shell"] });
      analyticsPipeline.setLevel("usage");
      eventBus.emit("cost_update", { cost_usd: 0.1 });
      eventBus.emit("agent_turn_completed", { turn: 0, duration_ms: 5, reason: "finished" });
      await analyticsPipeline.flushNow();
    } finally { rmSync(home, { recursive: true, force: true }); }
    expect(attempts).toEqual([]);
  });

  it("pricing discovery does not fetch the public catalog", async () => {
    enterprise();
    await discoverAndRegisterPricing("vendor/unpriced-model-for-egress-test");
    expect(attempts).toEqual([]);
  });

  it("the OSV advisory lookup refuses and does not connect", async () => {
    enterprise();
    await expect(checkBomAgainstOsv({ components: [{ purl: "pkg:npm/left-pad@1.3.0" }] })).rejects.toThrow(/ZERO_ENTERPRISE/);
    expect(attempts).toEqual([]);
  });

  it("a remote extension source is refused, a local one is not", async () => {
    enterprise();
    const remote = await new GitSource("https://github.com/example-org/example-ext.git", "a".repeat(40), false).fetch();
    expect(remote.ok).toBe(false);
    expect(JSON.stringify(remote)).toMatch(/ZERO_ENTERPRISE/);
    expect(attempts).toEqual([]);
  });

  it("web_search is off and refuses when called", async () => {
    enterprise();
    expect(featureFlags.webSearch).toBe(false);
    const executor = new ToolExecutor({ webSearchEnabled: true } as never);
    const result = await (executor as unknown as { webSearch(args: Record<string, unknown>): Promise<{ success: boolean; error?: string }> }).webSearch({ query: "cve lookup" });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/ZERO_ENTERPRISE/);
    expect(attempts).toEqual([]);
  });

  it("the sandbox runtime download is refused", async () => {
    enterprise();
    const root = mkdtempSync(join(tmpdir(), "0-egress-"));
    try {
      await resolveSmolvmRuntime({ stateRoot: root }).catch(() => undefined);
    } finally { rmSync(root, { recursive: true, force: true }); }
    expect(attempts).toEqual([]);
  });

  it("the model endpoint on the local stub still works", async () => {
    enterprise();
    const response = await fetch(`http://127.0.0.1:${stubPort}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(response.ok).toBe(true);
    expect(stubModelRequests).toEqual(["/v1/chat/completions"]);
    expect(attempts.filter(a => a.target !== `127.0.0.1:${stubPort}`)).toEqual([]);
  });
});
