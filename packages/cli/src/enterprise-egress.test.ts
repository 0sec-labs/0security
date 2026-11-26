import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ENTERPRISE_ENV } from "@0/engine";
import { fetchLatestTag, performAutoUpdate, shouldRunCheck, updatesDisabledByEnvironment } from "./utils/update-check.js";
import { readUpdateStatus } from "./web/update-status.js";
import { syncModelCatalog } from "./state/model-catalog-sync.js";
import { FEEDBACK_OPT_OUT_ENV, submissionBlockedReason, submitFeedback } from "./state/feedback.js";
import { ghApi } from "./web/skills-catalog.js";
import { defaultRepositoryGh } from "./web/repositories.js";
import { runGh } from "./host/gh.js";
import { deployWorker, type WorkerRunner } from "./worker-deploy.js";

/**
 * CLI half of the ZERO_ENTERPRISE egress test (the engine half is packages/engine/src/policy/enterprise-egress.test.ts).
 * fetch, node:http(s), sockets and the network-capable binaries (gh, curl, git, ssh) are patched to record every
 * attempt; the only destination allowed is a local stub model server.
 */

interface Attempt { via: string; target: string }
let attempts: Attempt[];
let stub: http.Server;
let stubPort: number;
const restore: Array<() => void> = [];

function patch<T extends object, K extends keyof T>(target: T, key: K, replacement: T[K]): void {
  const original = target[key];
  target[key] = replacement;
  restore.push(() => { target[key] = original; });
}
const hostOf = (input: unknown): string => {
  if (typeof input === "string") { try { return new URL(input).host; } catch { return input; } }
  if (input instanceof URL) return input.host;
  if (input && typeof input === "object" && "url" in input) return hostOf((input as { url: string }).url);
  return String(input);
};

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
      patch(mod as never, name as never, ((first: unknown) => { attempts.push({ via: `http.${name}`, target: hostOf(first) }); throw new Error("egress blocked by test"); }) as never);
    }
  }
  for (const name of ["spawn", "execFile", "execFileSync", "spawnSync"] as const) {
    patch(childProcess as never, name as never, ((command: string, args?: unknown) => {
      if (/^(?:gh|curl|wget|ssh|scp|git)$/.test(String(command))) attempts.push({ via: `process.${name}`, target: `${command} ${Array.isArray(args) ? args.join(" ") : ""}`.trim() });
      throw new Error("process blocked by test");
    }) as never);
  }
  const proto = net.Socket.prototype as unknown as { connect: (...args: unknown[]) => unknown };
  const realConnect = proto.connect;
  patch(proto, "connect", function (this: net.Socket, ...args: unknown[]) {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const o = (typeof first === "object" && first !== null ? first : { port: Number(first), host: args[1] }) as { port?: number; host?: string; path?: string };
    const isStub = o.port === stubPort && (o.host === "127.0.0.1" || o.host === "localhost" || o.host === undefined);
    if (!isStub) attempts.push({ via: "net.connect", target: o.path ? `unix:${o.path}` : `${o.host}:${o.port}` });
    return realConnect.apply(this, args);
  } as never);
  syncBuiltinESMExports();
  restore.push(() => syncBuiltinESMExports());
}

const NETWORK_ENV = ["ZERO_OFFLINE", "DO_NOT_TRACK", "ZERO_NO_UPDATE_CHECK", "ZERO_UPDATE_ORIGIN", "CI", "ZERO_FEEDBACK_URL", "ZERO_SENTRY_DSN", "ZERO_CLOUD_TOKEN"];
const enterprise = () => { for (const name of NETWORK_ENV) vi.stubEnv(name, undefined); vi.stubEnv(ENTERPRISE_ENV, "1"); };

let home: string;
beforeEach(async () => {
  attempts = [];
  home = mkdtempSync(join(tmpdir(), "0-egress-cli-"));
  stub = http.createServer((_req, res) => { res.setHeader("content-type", "application/json"); res.end("{}"); });
  await new Promise<void>(resolve => stub.listen(0, "127.0.0.1", resolve));
  stubPort = (stub.address() as net.AddressInfo).port;
  installEgressGuard();
});
afterEach(async () => {
  while (restore.length) restore.pop()!();
  vi.unstubAllEnvs();
  rmSync(home, { recursive: true, force: true });
  await new Promise<void>(resolve => stub.close(() => resolve()));
});

describe("ZERO_ENTERPRISE, CLI call sites", () => {
  it("is not a feedback opt-out: DO_NOT_TRACK is the only telemetry switch", () => {
    expect(FEEDBACK_OPT_OUT_ENV).toEqual(["DO_NOT_TRACK"]);
  });

  it("update check: no lookup, no install, status stays empty", async () => {
    enterprise();
    expect(await fetchLatestTag()).toBeNull();
    expect(updatesDisabledByEnvironment(process.env)).toBe(true);
    expect(shouldRunCheck(process.env, true, "automatic")).toBe(false);
    const result = await performAutoUpdate({ version: "v99.0.0" });
    expect(result.success).toBe(false);
    const status = readUpdateStatus({ current: "0.1.0", policy: "automatic", env: process.env, stateDir: home });
    expect(status.available).toBe(false);
    expect(attempts).toEqual([]);
  });

  it("model catalog sync does not call models.dev", async () => {
    enterprise();
    expect(await syncModelCatalog({ force: true, homeDir: home } as never)).toBeNull();
    expect(attempts).toEqual([]);
  });

  it("feedback and crash reports are refused before any request under DO_NOT_TRACK", async () => {
    enterprise();
    vi.stubEnv("DO_NOT_TRACK", "1");
    vi.stubEnv("ZERO_FEEDBACK_URL", "https://feedback.example.test/v1");
    vi.stubEnv("ZERO_SENTRY_DSN", "https://abc@o1.ingest.example.test/1");
    expect(submissionBlockedReason()).toBe("opt-out");
    const result = await submitFeedback({ message: "hello", diagnostic: true } as never, process.env, { diagnosticConsent: { policy: "automatic" } } as never);
    expect(result.ok).toBe(false);
    expect(attempts).toEqual([]);
  });

  it("GitHub-backed reads (skills directory, repository list, gh runner) refuse", async () => {
    enterprise();
    await expect(ghApi("/repos/example/example")).rejects.toThrow(/ZERO_ENTERPRISE/);
    await expect(Promise.resolve().then(() => defaultRepositoryGh.run(["api", "user/repos"]))).rejects.toThrow(/ZERO_ENTERPRISE/);
    await expect(runGh(["api", "user"])).rejects.toThrow(/ZERO_ENTERPRISE/);
    expect(attempts).toEqual([]);
  });

  it("remote worker provisioning refuses before running anything on the remote computer", async () => {
    enterprise();
    const shell = vi.fn(() => "");
    const runner: WorkerRunner = { shell, copy: vi.fn(), tunnel: vi.fn(), label: "worker.example.test" };
    await expect(deployWorker({ ssh: "worker.example.test", repoRoot: home } as never, runner)).rejects.toThrow(/ZERO_ENTERPRISE/);
    expect(shell).not.toHaveBeenCalled();
    expect(attempts).toEqual([]);
  });

  it("control: without the switch the same lookups do reach the guarded fetch", async () => {
    for (const name of [...NETWORK_ENV, ENTERPRISE_ENV]) vi.stubEnv(name, undefined);
    await fetchLatestTag([{ url: "https://updates.example.test/latest", kind: "api" }] as never, 500);
    await syncModelCatalog({ force: true, homeDir: home } as never);
    expect(attempts.map(a => a.target)).toEqual(["updates.example.test", "models.dev"]);
  });

  it("the model endpoint on the local stub is still reachable", async () => {
    enterprise();
    const response = await fetch(`http://127.0.0.1:${stubPort}/v1/models`);
    expect(response.ok).toBe(true);
    expect(attempts.filter(a => a.target !== `127.0.0.1:${stubPort}`)).toEqual([]);
  });
});
