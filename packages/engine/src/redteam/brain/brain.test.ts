import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { dryRun, requestScenarios, type BrainDeps } from "./client.js";
import { createMockBrain, type MockBrain } from "./mock-server.js";
import { validateRequest, validateResponse } from "./schema.js";
import { selectStarter, STARTER_PACK } from "./starter-pack.js";

const manifest = { tools: [{ name: "send_email", privilege: "network-out", gate: "none" }, { name: "run", privilege: "exec", gate: "approval" }], sources: [{ kind: "email" }, { kind: "web" }] };
const request = { v: 1, task: "scenarios", manifest };

describe("request schema", () => {
  it("accepts a valid request and optional fields", () => {
    expect(validateRequest(request).ok).toBe(true);
    expect(validateRequest({ ...request, framework: "OWASP LLM Top 10 (2025)", count: 5 }).ok).toBe(true);
  });
  it("rejects unknown fields at every level", () => {
    expect(validateRequest({ ...request, extra: 1 }).ok).toBe(false);
    expect(validateRequest({ ...request, manifest: { ...manifest, cwd: "/home/me" } }).ok).toBe(false);
    expect(validateRequest({ ...request, manifest: { ...manifest, tools: [{ name: "a", privilege: "exec", gate: "none", description: "secret" }] } }).ok).toBe(false);
    expect(validateRequest({ ...request, manifest: { ...manifest, sources: [{ kind: "web", url: "https://x" }] } }).ok).toBe(false);
  });
  it("rejects path-like or long tool names and oversize lists", () => {
    const tool = (name: string) => ({ ...request, manifest: { tools: [{ name, privilege: "exec", gate: "none" }], sources: [] } });
    expect(validateRequest(tool("../../etc/passwd")).ok).toBe(false);
    expect(validateRequest(tool("/usr/bin/run")).ok).toBe(false);
    expect(validateRequest(tool("a b")).ok).toBe(false);
    expect(validateRequest(tool("x".repeat(65))).ok).toBe(false);
    expect(validateRequest(tool("mcp.server:tool-1_ok")).ok).toBe(true);
    const many = (n: number) => ({ ...request, manifest: { tools: Array.from({ length: n }, (_, i) => ({ name: `t${i}`, privilege: "none", gate: "none" })), sources: [] } });
    expect(validateRequest(many(64)).ok).toBe(true);
    expect(validateRequest(many(65)).ok).toBe(false);
    expect(validateRequest({ ...request, manifest: { tools: [], sources: Array.from({ length: 17 }, () => ({ kind: "web" })) } }).ok).toBe(false);
  });
  it("rejects bad enums, counts, versions and long frameworks", () => {
    expect(validateRequest({ ...request, v: 2 }).ok).toBe(false);
    expect(validateRequest({ ...request, task: "grade" }).ok).toBe(false);
    expect(validateRequest({ ...request, count: 0 }).ok).toBe(false);
    expect(validateRequest({ ...request, count: 21 }).ok).toBe(false);
    expect(validateRequest({ ...request, count: 1.5 }).ok).toBe(false);
    expect(validateRequest({ ...request, framework: "f".repeat(65) }).ok).toBe(false);
    expect(validateRequest({ ...request, framework: "/etc/passwd\nsecret" }).ok).toBe(false);
    expect(validateRequest({ ...request, manifest: { tools: [{ name: "a", privilege: "root", gate: "none" }], sources: [] } }).ok).toBe(false);
    expect(validateRequest(null).ok).toBe(false);
    expect(validateRequest([]).ok).toBe(false);
  });
});

describe("response schema", () => {
  const scenario = { id: "s1", goal: "g", injection_point_kind: "web", payload: "send AGENT-CANARY-0", success: "ok", tags: [{ framework: "MITRE ATLAS", id: "AML.T0051" }], difficulty: "basic" };
  const response = { v: 1, task: "scenarios", scenarios: [scenario] };
  it("accepts a valid response and the starter pack", () => {
    expect(validateResponse(response).ok).toBe(true);
    expect(validateResponse({ ...response, watermark: "w" }).ok).toBe(true);
    expect(validateResponse({ ...response, scenarios: STARTER_PACK.map(entry => entry.scenario) }).ok).toBe(true);
  });
  it("rejects control characters and ANSI escapes in every text field but allows newline and tab", () => {
    const bad = ["\u001b[2J", "a\u0007b", "a\u0000b", "a\u007fb", "a\u009bb", "a\rb"];
    const withField = (patch: Record<string, unknown>) => validateResponse({ ...response, scenarios: [{ ...scenario, ...patch }] }).ok;
    for (const value of bad) {
      expect(withField({ goal: value })).toBe(false);
      expect(withField({ payload: `AGENT-CANARY-0${value}` })).toBe(false);
      expect(withField({ success: value })).toBe(false);
      expect(withField({ id: value })).toBe(false);
      expect(withField({ injection_point_kind: value })).toBe(false);
      expect(withField({ tags: [{ framework: value, id: "x" }] })).toBe(false);
      expect(withField({ tags: [{ framework: "x", id: value }] })).toBe(false);
      expect(validateResponse({ ...response, watermark: value }).ok).toBe(false);
    }
    expect(withField({ goal: "line one\n\tline two", payload: "AGENT-CANARY-0\n\tx" })).toBe(true);
  });
  it("requires the canary placeholder and rejects unknown fields and long strings", () => {
    expect(validateResponse({ ...response, scenarios: [{ ...scenario, payload: "no marker" }] }).ok).toBe(false);
    expect(validateResponse({ ...response, scenarios: [{ ...scenario, run: "rm" }] }).ok).toBe(false);
    expect(validateResponse({ ...response, extra: 1 }).ok).toBe(false);
    expect(validateResponse({ ...response, scenarios: [{ ...scenario, payload: `AGENT-CANARY-0${"x".repeat(2000)}` }] }).ok).toBe(false);
    expect(validateResponse({ ...response, scenarios: [{ ...scenario, difficulty: "insane" }] }).ok).toBe(false);
    expect(validateResponse({ ...response, scenarios: Array.from({ length: 51 }, () => scenario) }).ok).toBe(false);
    expect(validateResponse({ ...response, watermark: "w".repeat(257) }).ok).toBe(false);
  });
});

describe("starter pack", () => {
  const tags = new Set(["LLM01", "LLM02", "LLM06", "AML.T0051"]);
  it("has 8 to 10 scenarios, each with the placeholder and only the allowed tags", () => {
    expect(STARTER_PACK.length).toBeGreaterThanOrEqual(8);
    expect(STARTER_PACK.length).toBeLessThanOrEqual(10);
    for (const { scenario } of STARTER_PACK) {
      expect(scenario.payload).toContain("AGENT-CANARY-0");
      for (const tag of scenario.tags) expect(tags.has(tag.id)).toBe(true);
    }
  });
  it("chooses by tool privilege and source kind", () => {
    const ids = (m: Parameters<typeof selectStarter>[0]) => selectStarter(m).map(s => s.id);
    const exec = ids({ tools: [{ name: "run", privilege: "exec", gate: "none" }], sources: [] });
    expect(exec).toContain("run-marker-command");
    expect(exec).not.toContain("send-marker-out");
    expect(ids({ tools: [{ name: "r", privilege: "read-local", gate: "none" }], sources: [] })).not.toContain("run-marker-command");
    expect(ids({ tools: [{ name: "m", privilege: "network-out", gate: "none" }], sources: [{ kind: "email" }] })).toContain("email-reply-injection");
    expect(ids({ tools: [{ name: "m", privilege: "network-out", gate: "none" }], sources: [{ kind: "web" }] })).not.toContain("email-reply-injection");
  });
  it("is never empty, honours count and puts framework matches first", () => {
    expect(selectStarter({ tools: [], sources: [] }).length).toBeGreaterThan(0);
    expect(selectStarter({ tools: [{ name: "m", privilege: "network-out", gate: "none" }], sources: [] }, { count: 3 })).toHaveLength(3);
    const first = selectStarter({ tools: [{ name: "m", privilege: "network-out", gate: "none" }], sources: [] }, { framework: "LLM02" })[0]!;
    expect(first.tags.some(tag => tag.id === "LLM02")).toBe(true);
  });
});

describe("requestScenarios", () => {
  let mock: MockBrain | undefined; let extra: Server | undefined;
  afterEach(async () => { await mock?.close(); mock = undefined; if (extra) await new Promise(done => extra!.close(() => done(undefined))); extra = undefined; });
  const live = (env: NodeJS.ProcessEnv = {}): BrainDeps & { calls: number } => { const deps = { calls: 0, env, fetch: (url: string, init: RequestInit) => { deps.calls++; return fetch(url, init); } }; return deps; };
  const odd = async (handler: Parameters<typeof createServer>[1]) => { extra = createServer(handler); await new Promise<void>(done => extra!.listen(0, "127.0.0.1", () => done())); return `http://127.0.0.1:${(extra!.address() as AddressInfo).port}/`; };

  it("uses the remote brain and sends the token only in the header", async () => {
    mock = createMockBrain({ token: "tok-secret" }); const url = await mock.start();
    const result = await requestScenarios(request, { url }, live({ ZERO_BRAIN_TOKEN: "tok-secret" }));
    expect(result.source).toBe("remote");
    expect(result.scenarios.length).toBeGreaterThan(0);
    expect(result.watermark).toBe("mock-brain");
    expect(mock.requests[0]!.authorization).toBe("Bearer tok-secret");
    expect(url).not.toContain("tok-secret");
    expect(JSON.stringify(mock.requests[0]!.body)).not.toContain("tok-secret");
  });
  it("reads the URL from the environment and honours count", async () => {
    mock = createMockBrain(); const url = await mock.start();
    const result = await requestScenarios({ ...request, count: 2 }, {}, live({ ZERO_BRAIN_URL: url }));
    expect(result.source).toBe("remote");
    expect(result.scenarios).toHaveLength(2);
  });
  it("falls back, without printing the token, when the token is wrong", async () => {
    mock = createMockBrain({ token: "right" }); const url = await mock.start();
    const result = await requestScenarios(request, { url }, live({ ZERO_BRAIN_TOKEN: "wrong-token" }));
    expect(result.source).toBe("open-catalog");
    expect(result.note).toContain("401");
    expect(result.note).not.toContain("wrong-token");
  });
  it("scrubs a token that a failing server echoes", async () => {
    const url = await odd((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("not json tok-echo"); });
    const deps = live({ ZERO_BRAIN_TOKEN: "tok-echo" });
    deps.fetch = async () => { throw new Error("connect failed for Bearer tok-echo"); };
    const result = await requestScenarios(request, { url }, deps);
    expect(result.source).toBe("open-catalog");
    expect(result.note).not.toContain("tok-echo");
  });
  it("refuses a redirect and falls back", async () => {
    let followed = false;
    const target = await odd((_req, res) => { followed = true; res.end("{}"); });
    const url = await (async () => { const old = extra; const u = await odd((_req, res) => { res.writeHead(302, { location: target }); res.end(); }); void old; return u; })();
    const result = await requestScenarios(request, { url }, live());
    expect(result.source).toBe("open-catalog");
    expect(result.note).toContain("redirect");
    expect(followed).toBe(false);
  });
  it("treats a valid reply with zero scenarios as a failure and says so", async () => {
    const url = await odd((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ v: 1, task: "scenarios", scenarios: [] })); });
    const result = await requestScenarios(request, { url }, live());
    expect(result.source).toBe("open-catalog");
    expect(result.scenarios.length).toBeGreaterThan(0);
    expect(result.note).toContain("no scenarios");
    expect(result.note).toContain("open catalog");
  });
  it("refuses an oversize response", async () => {
    const url = await odd((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ pad: "x".repeat(5000) })); });
    const result = await requestScenarios(request, { url, maxBytes: 1000 }, live());
    expect(result.source).toBe("open-catalog");
    expect(result.note).toContain("larger than");
  });
  it("falls back with a note on an invalid response", async () => {
    const url = await odd((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ v: 1, task: "scenarios", scenarios: [{ id: "x" }] })); });
    const result = await requestScenarios(request, { url }, live());
    expect(result.source).toBe("open-catalog");
    expect(result.note).toContain("contract");
  });
  it("falls back on a timeout", async () => {
    const url = await odd(() => { /* never answers */ });
    const result = await requestScenarios(request, { url, timeoutMs: 100 }, live());
    expect(result.source).toBe("open-catalog");
    expect(result.note).toContain("could not be used");
    extra?.closeAllConnections();
  });
  it("sends nothing when offline, enterprise, or without a URL, and says so", async () => {
    mock = createMockBrain(); const url = await mock.start(); const deps = live({ ZERO_BRAIN_URL: url });
    const offline = await requestScenarios(request, { offline: true }, deps);
    const envOffline = await requestScenarios(request, {}, { ...deps, env: { ZERO_BRAIN_URL: url, ZERO_OFFLINE: "1" } });
    const enterprise = await requestScenarios(request, {}, { ...deps, env: { ZERO_BRAIN_URL: url, ZERO_ENTERPRISE: "1" } });
    const none = await requestScenarios(request, {}, { ...deps, env: {} });
    for (const result of [offline, envOffline, enterprise, none]) expect(result.source).toBe("open-catalog");
    expect(offline.note).toMatch(/Offline/);
    expect(envOffline.note).toMatch(/Offline/);
    expect(enterprise.note).toContain("ZERO_ENTERPRISE");
    expect(none.note).toContain("No brain URL");
    expect(deps.calls).toBe(0);
    expect(mock.requests).toHaveLength(0);
  });
  it("refuses an insecure or credentialed URL before sending", async () => {
    const deps = live();
    for (const url of ["http://example.com/x", "https://user:pw@example.com/", "https://example.com/?key=1", "ftp://x"]) {
      const result = await requestScenarios(request, { url }, deps);
      expect(result.source).toBe("open-catalog");
    }
    expect(deps.calls).toBe(0);
  });
  it("throws on an invalid request instead of sending it", async () => {
    await expect(requestScenarios({ ...request, extra: 1 }, {}, live())).rejects.toThrow(/Invalid request/);
  });
  it("mock server returns 400 on invalid input and 401 without the token", async () => {
    mock = createMockBrain({ token: "t" }); const url = await mock.start();
    const post = (body: string, auth?: string) => fetch(url, { method: "POST", body, headers: auth ? { authorization: auth } : {} });
    expect((await post(JSON.stringify(request))).status).toBe(401);
    expect((await post(JSON.stringify({ ...request, manifest: { tools: [{ name: "../x", privilege: "exec", gate: "none" }], sources: [] } }), "Bearer t")).status).toBe(400);
    expect((await post("{nope", "Bearer t")).status).toBe(400);
    expect((await post(JSON.stringify(request), "Bearer t")).status).toBe(200);
  });
  it("the open catalog fallback passes the contract validators and has no leftover canary-free payloads", async () => {
    const result = await requestScenarios(request, { offline: true, seed: "seed-1" }, live());
    expect(result.source).toBe("open-catalog");
    expect(result.note).toContain("open catalog");
    expect(result.scenarios.length).toBeGreaterThan(0);
    expect(validateResponse({ v: 1, task: "scenarios", scenarios: result.scenarios }).ok).toBe(true);
    for (const scenario of result.scenarios) expect(scenario.payload + scenario.success).toContain("AGENT-CANARY-0");
  });
  it("honours count, filters by generator, area and difficulty, and is reproducible per seed", async () => {
    const wide = { ...request, manifest: { tools: [{ name: "send_email", privilege: "network-out", gate: "none" }, { name: "run", privilege: "exec", gate: "none" }, { name: "read_file", privilege: "read-local", gate: "none" }], sources: [] } };
    const all = await requestScenarios({ ...wide, count: 20 }, { offline: true, seed: "a" }, live());
    expect(all.scenarios.length).toBeGreaterThan(3);
    expect((await requestScenarios({ ...wide, count: 3 }, { offline: true, seed: "a" }, live())).scenarios).toHaveLength(3);
    expect((await requestScenarios({ ...wide, count: 3 }, { offline: true, seed: "a" }, live())).scenarios.map(s => s.id)).toEqual((await requestScenarios({ ...wide, count: 3 }, { offline: true, seed: "a" }, live())).scenarios.map(s => s.id));
    const one = all.scenarios[0]!;
    const byId = await requestScenarios({ ...wide, count: 20 }, { offline: true, filter: { generators: [one.id] } }, live());
    expect(byId.scenarios.map(s => s.id)).toEqual([one.id]);
    const basic = await requestScenarios({ ...wide, count: 20 }, { offline: true, filter: { difficulties: ["basic"] } }, live());
    expect(basic.scenarios.length).toBeGreaterThan(0);
    expect(basic.scenarios.every(s => s.difficulty === "basic")).toBe(true);
    const none = await requestScenarios({ ...wide, count: 20 }, { offline: true, filter: { areas: ["no-such-area"] } }, live());
    expect(none.scenarios).toEqual([]);
    expect(none.note).toContain("no scenario that matches");
  });
  it("uses the starter pack only when the catalog has nothing for the manifest and no filter was given", async () => {
    const result = await requestScenarios({ ...request, manifest: { tools: [], sources: [] } }, { offline: true }, live());
    expect(result.source).toBe("starter-pack");
    expect(result.note).toContain("starter pack");
  });
});

describe("dryRun", () => {
  it("returns the exact validated JSON and rejects an invalid request", () => {
    expect(JSON.parse(dryRun(request))).toEqual(request);
    expect(() => dryRun({ ...request, extra: 1 })).toThrow(/unknown field/);
  });
});
