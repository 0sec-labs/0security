import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eventBus } from "../events/bus.js";
import {
  analyticsPipeline,
  ANALYTICS_SENT_LOG_FILENAME,
  redactRecordStrings,
} from "./analytics-pipeline.js";
import { REDACTED_SECRET } from "./redaction.js";

const FAKE_KEY = "phc_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000";
const FAKE_HOST = "http://127.0.0.1:9";

const dirs: string[] = [];
let captured: Array<{ url: string; body: string }>;
let home: string;

function capturingFetch(): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    captured.push({ url: String(url), body: String(init?.body ?? "") });
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
}

function logPath(): string {
  return join(home, ".0", ANALYTICS_SENT_LOG_FILENAME);
}

/** Every tool_counts map PostHog received, in order. */
function toolCounts(): Array<Record<string, number>> {
  return captured.flatMap((request) =>
    (JSON.parse(request.body) as { batch: Array<{ event: string; properties: { tool_counts?: Record<string, number> } }> }).batch
      .filter((event) => event.event === "usage")
      .map((event) => event.properties.tool_counts ?? {}));
}

beforeEach(() => {
  analyticsPipeline.__resetForTests();
  captured = [];
  home = mkdtempSync(join(tmpdir(), "0-analytics-pipeline-"));
  dirs.push(home);
  for (const name of ["ZERO_CLOUD_TOKEN", "ZERO_CLOUD_HOST", "ZERO_ANALYTICS_LEVEL", "ZERO_OFFLINE", "ZERO_NO_TELEMETRY", "DO_NOT_TRACK"]) {
    vi.stubEnv(name, undefined);
  }
  vi.stubEnv("ZERO_ANALYTICS_POSTHOG_KEY", FAKE_KEY);
  vi.stubEnv("ZERO_ANALYTICS_POSTHOG_HOST", FAKE_HOST);
  analyticsPipeline.configure({ homeDir: home, fetchImpl: capturingFetch(), knownToolNames: ["before_off", "while_off", "after_on", "safe_counter"] });
});

afterEach(() => {
  analyticsPipeline.__resetForTests();
  vi.unstubAllEnvs();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("consent gate", () => {
  it("drops everything when level=off, nothing transmitted or logged", async () => {
    analyticsPipeline.setLevel("off");
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { http_request: 3 }, turnCount: 1, durationMs: 1 });
    await analyticsPipeline.flushNow();
    expect(captured).toHaveLength(0);
    expect(existsSync(logPath())).toBe(false);
  });

  it("transmits to PostHog once the level is usage", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { before_off: 3 }, findingCounts: {}, errorCategories: {}, turnCount: 1, durationMs: 5 });
    await analyticsPipeline.flushNow();
    expect(captured).toHaveLength(1);
    expect(captured[0].url).toBe(`${FAKE_HOST}/batch/`);
    expect(toolCounts()).toEqual([{ before_off: 3 }]);
  });
});

describe("redaction on the choke path", () => {
  it("scrubs a secret-shaped KEY as well as values", () => {
    const out = redactRecordStrings({
      featureCounts: { "password=hunter2supersecret": 4 },
    }) as { featureCounts: Record<string, number> };
    const keys = Object.keys(out.featureCounts);
    expect(keys.some((k) => k.includes("hunter2supersecret"))).toBe(false);
    expect(keys.some((k) => k.includes(REDACTED_SECRET))).toBe(true);
  });

  it("never lets a planted secret reach the wire", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { "token sk-ABCDEFGHIJKLMNOPQRSTUVWX": 1 }, turnCount: 1, durationMs: 1 });
    await analyticsPipeline.flushNow();
    expect(captured.every((request) => !request.body.includes("sk-ABCDEFGHIJKLMNOPQRSTUVWX"))).toBe(true);
  });
});

describe("fail-soft transport", () => {
  it("never throws when transmission fails", async () => {
    analyticsPipeline.configure({ fetchImpl: (async () => { throw new Error("boom internal.example"); }) as unknown as typeof fetch });
    analyticsPipeline.setLevel("usage");
    eventBus.emit("tool_call_started", { tool: "safe_counter", turn: 0, ts: Date.now() });
    await expect(analyticsPipeline.flushNow()).resolves.toBeUndefined();
  });
});

describe("consent changes with pending records", () => {
  it("discards queued counters while off, without replay after re-enabling", async () => {
    analyticsPipeline.setLevel("usage");
    eventBus.emit("tool_call_started", { tool: "before_off", turn: 0, ts: Date.now() });
    analyticsPipeline.setLevel("off");
    eventBus.emit("tool_call_started", { tool: "while_off", turn: 0, ts: Date.now() });
    await analyticsPipeline.flushNow();
    expect(captured).toEqual([]);
    expect(existsSync(logPath())).toBe(false);
    analyticsPipeline.setLevel("usage");
    eventBus.emit("tool_call_started", { tool: "after_on", turn: 1, ts: Date.now() });
    await analyticsPipeline.flushNow();
    expect(toolCounts()).toEqual([{ after_on: 1 }]);
  });

  it("honors a saved-off environment bridge and clears earlier accumulated usage", async () => {
    analyticsPipeline.setLevel("usage");
    eventBus.emit("tool_call_started", { tool: "before_off", turn: 0, ts: Date.now() });
    vi.stubEnv("ZERO_ANALYTICS_LEVEL", "off");
    eventBus.emit("tool_call_started", { tool: "while_off", turn: 0, ts: Date.now() });
    await analyticsPipeline.flushNow();
    expect(captured).toEqual([]);
    vi.stubEnv("ZERO_ANALYTICS_LEVEL", undefined);
    eventBus.emit("tool_call_started", { tool: "after_on", turn: 1, ts: Date.now() });
    await analyticsPipeline.flushNow();
    expect(toolCounts()).toEqual([{ after_on: 1 }]);
  });

  it("DO_NOT_TRACK set mid-run stops everything still pending", async () => {
    analyticsPipeline.setLevel("usage");
    eventBus.emit("tool_call_started", { tool: "before_off", turn: 0, ts: Date.now() });
    vi.stubEnv("DO_NOT_TRACK", "1");
    await analyticsPipeline.flushNow();
    expect(captured).toEqual([]);
  });
});

describe("transparency log", () => {
  it("records only the post-redaction wire payload and never the api key", async () => {
    analyticsPipeline.setLevel("usage");
    analyticsPipeline.__enqueueForTests({ kind: "usage", featureCounts: { before_off: 1 }, turnCount: 1, durationMs: 1, note: "sk-ABCDEFGHIJKLMNOPQRSTUVWX" });
    await analyticsPipeline.flushNow();
    const { readFileSync } = await import("node:fs");
    const log = readFileSync(logPath(), "utf8");
    expect(log).toContain('"event":"usage"');
    expect(log).not.toContain("sk-ABCDEFGHIJKLMNOPQRSTUVWX");
    expect(log).not.toContain(FAKE_KEY);
  });
});
