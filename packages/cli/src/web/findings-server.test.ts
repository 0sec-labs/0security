import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { osecDB } from "@0/engine/storage";

// The license state is the only thing replaced: "full" is a valid license, "read-only" is past the grace period, "none" is no key.
const license = vi.hoisted(() => ({ mode: "none" as "full" | "read-only" | "none" }));
vi.mock("../findings-server-bridge.js", async importOriginal => {
  const original = await importOriginal<typeof import("../findings-server-bridge.js")>();
  return {
    ...original,
    hasFindingsServer: () => license.mode === "full",
    canReadFindingsServer: () => license.mode !== "none",
    findingsServerMessage: () => license.mode === "none" ? "The shared findings server needs an enterprise license. Get a key at https://0.security/enterprise/." : "Your 0security enterprise license expired. The shared findings server is read-only until you renew.",
  };
});

import { FindingsAccessTokenStore } from "./findings-access-tokens.js";
import { FindingsReadApi, handleFindingsReadRequest } from "./findings-read-api.js";
import { handleFindingsIngest } from "./findings-ingest.js";
import { handleFindingFamilyRequest } from "./finding-family-routes.js";
import { handleFindingsOrgRequest, parseFindingsOrgPath } from "./findings-org-routes.js";
import { errorStatusCode, json } from "./dashboard-http.js";

let directory: string, dbPath: string, server: Server, base: string, store: FindingsAccessTokenStore;

beforeEach(async () => {
  license.mode = "none";
  directory = mkdtempSync(join(tmpdir(), "0-findings-server-"));
  dbPath = join(directory, "findings.db");
  new osecDB(dbPath).close();
  store = new FindingsAccessTokenStore({ workspaceId: "w", stateDir: join(directory, "keys") });
  const read = new FindingsReadApi({ workspaceId: "w", dbPath });
  server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      const org = parseFindingsOrgPath(url.pathname);
      if (org) { await handleFindingsOrgRequest(req, res, url, org, dbPath); return; }
      const family = /^\/api\/finding-family\/([^/]+)\/(triage|workflow)$/.exec(url.pathname);
      if (family) { await handleFindingFamilyRequest(req, res, decodeURIComponent(family[1]!), family[2] as "triage" | "workflow", dbPath, "control", undefined, { engineRequest: false, userId: "user-1" }); return; }
      const credential = store.authenticate(req, url);
      if (!credential) throw Object.assign(new Error("A findings API key is required."), { statusCode: 401 });
      if (url.pathname === "/api/v1/findings/ingest") { const reply = await handleFindingsIngest(req, url, credential, dbPath); json(res, reply.status, reply.data); return; }
      const reply = handleFindingsReadRequest(req, url, read);
      json(res, reply?.status ?? 404, reply?.data ?? { error: "not found" });
    } catch (error) { json(res, errorStatusCode(error), { error: error instanceof Error ? error.message : String(error) }); }
  });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterEach(async () => { await new Promise(done => server.close(done)); rmSync(directory, { recursive: true, force: true }); });

const sarif = (...rules: string[]) => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "foxguard", rules: rules.map(id => ({ id })) } }, results: rules.map((ruleId, index) => ({ ruleId, level: "error", message: { text: `problem ${ruleId}` }, locations: [{ physicalLocation: { artifactLocation: { uri: `src/${ruleId}.ts` }, region: { startLine: index + 3 } } }] })) }] });
const writeKey = () => { license.mode = "full"; const token = store.create({ name: "ci-main", scopes: ["write:findings"] }, "owner").token; return token; };
const readKey = () => store.create({ name: "reader" }, "owner").token;
const send = (path: string, token: string, body: string, method = "POST") => fetch(`${base}${path}`, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, ...(method === "POST" ? { body } : {}) });
const get = (path: string, token: string) => fetch(`${base}${path}`, { headers: { Authorization: `Bearer ${token}` } });

describe("keys and scopes", () => {
  it("refuses to mint a write key without a license, and mints a read key as before", () => {
    expect(() => store.create({ name: "ci", scopes: ["write:findings"] }, "owner")).toThrow(/needs an enterprise license/);
    expect(store.create({ name: "reader" }, "owner").credential.scopes).toEqual(["read:findings"]);
  });
  it("lets a write key send findings and nothing else, and a read key read and nothing else", async () => {
    const write = writeKey();
    const read = readKey();
    expect((await send("/api/v1/findings/ingest?repo=acme/api", read, sarif("R1"))).status).toBe(403);
    expect((await get("/api/v1/findings", write)).status).toBe(403);
    expect((await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R1"))).status).toBe(201);
    expect((await get("/api/v1/findings", read)).status).toBe(200);
  });
});

describe("license gating", () => {
  it("answers 'needs an enterprise license' without a key and stores nothing", async () => {
    const write = writeKey();
    license.mode = "none";
    const reply = await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R1"));
    expect(reply.status).toBe(403);
    expect((await reply.json() as { error: string }).error).toMatch(/needs an enterprise license/);
    const db = new osecDB(dbPath, { readOnly: true });
    try { expect(db.listOrgFindings()).toEqual([]); } finally { db.close(); }
  });
  it("leaves the plain read API free, and gates repo filters and history", async () => {
    const read = readKey();
    expect((await get("/api/v1/findings", read)).status).toBe(200);
    expect((await get("/api/v1/findings?repo=acme/api", read)).status).toBe(403);
    expect((await get("/api/v1/findings/fx:abc/history", read)).status).toBe(403);
  });
  it("stops ingest after expiry but keeps stored data readable", async () => {
    const write = writeKey();
    expect((await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R1"))).status).toBe(201);
    license.mode = "read-only";
    const refused = await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R2"));
    expect(refused.status).toBe(403);
    expect((await refused.json() as { error: string }).error).toMatch(/expired/);
    const read = readKey();
    expect(((await (await get("/api/v1/findings?repo=acme/api", read)).json()) as { findings: unknown[] }).findings).toHaveLength(1);
    const overview = await (await fetch(`${base}/api/findings-server/overview`)).json() as { available: boolean; canWrite: boolean; summary: { total: number } };
    expect(overview).toMatchObject({ available: true, canWrite: false, summary: { total: 1 } });
  });
  it("tells the browser there is no license without failing", async () => {
    expect(await (await fetch(`${base}/api/findings-server/overview`)).json()).toMatchObject({ available: false });
  });
});

describe("ingest", () => {
  it("stores SARIF with repo and source labels, and is idempotent", async () => {
    const write = writeKey();
    const first = await send("/api/v1/findings/ingest?repo=acme/api&source=nightly&commit=abc1234&ref=main", write, sarif("R1", "R2"));
    expect(first.status).toBe(201);
    expect(await first.json()).toMatchObject({ created: 2, known: 0, alreadyImported: false, repo: "acme/api", source: "nightly", format: "sarif" });
    const again = await send("/api/v1/findings/ingest?repo=acme/api&source=nightly&commit=abc1234&ref=main", write, sarif("R1", "R2"));
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({ alreadyImported: true, created: 0 });
    // A later upload with one new finding adds only that one.
    const later = await send("/api/v1/findings/ingest?repo=acme/api&source=nightly", write, sarif("R1", "R2", "R3"));
    expect(await later.json()).toMatchObject({ created: 1, known: 2 });
    const read = readKey();
    const list = await (await get("/api/v1/findings?repo=acme/api&source=nightly", read)).json() as { findings: Array<{ repo: string; source: string }> };
    expect(list.findings).toHaveLength(3);
    expect(list.findings[0]).toMatchObject({ repo: "acme/api", source: "nightly" });
    expect(((await (await get("/api/v1/findings?repo=acme/other", read)).json()) as { findings: unknown[] }).findings).toHaveLength(0);
  });
  it("defaults the source to the key name and accepts findings JSON", async () => {
    const write = writeKey();
    const body = JSON.stringify({ findings: [{ title: "Hardcoded key", severity: "high", templateId: "secrets", evidence: { request: "a.ts:4", response: "key=..." } }] });
    const reply = await send("/api/v1/findings/ingest?repo=acme/api", write, body);
    expect(await reply.json()).toMatchObject({ created: 1, source: "ci-main", format: "findings-json" });
  });
  it("accepts a findings rollup export, and does not let it set a triage state", async () => {
    const write = writeKey();
    const row = (fingerprint: string, triage: string) => ({ repository: "acme/api", fingerprint, title: `Rolled up ${fingerprint}`, severity: "medium", category: "xss", status: "discovered", triage, owner: null, firstSeen: "2026-01-01T00:00:00Z", lastSeen: "2026-01-02T00:00:00Z" });
    const body = JSON.stringify({ schema: "0.findings-rollup.v1", exportedAt: "2026-01-03T00:00:00Z", findings: [row("a", "new"), row("b", "suppressed")] });
    const reply = await send("/api/v1/findings/ingest?repo=acme/api", write, body);
    expect(await reply.json()).toMatchObject({ created: 2, format: "findings-json" });
    const rows = (await (await fetch(`${base}/api/findings-server/overview`)).json() as { findings: Array<{ triageStatus: string }> }).findings;
    expect(rows.map(item => item.triageStatus)).toEqual(["new", "new"]);
  });
  it("rejects bad labels, bad JSON, wrong shapes, bad severities and too many findings", async () => {
    const write = writeKey();
    for (const [query, body, status] of [
      ["", sarif("R1"), 400], ["?repo=nope", sarif("R1"), 400], ["?repo=a/b&commit=zz", sarif("R1"), 400],
      ["?repo=a/b", "{", 400], ["?repo=a/b", "[]", 400], ["?repo=a/b", "{}", 400],
      ["?repo=a/b", JSON.stringify({ findings: [{ title: "x", severity: "bad" }] }), 400],
      ["?repo=a/b", JSON.stringify({ findings: new Array(5001).fill({ title: "x", severity: "low" }) }), 413],
    ] as const) {
      expect((await send(`/api/v1/findings/ingest${query}`, write, body)).status, `${query} ${body.slice(0, 20)}`).toBe(status);
    }
  });
  it("refuses a body over 20 MB before storing it", async () => {
    const write = writeKey();
    const reply = await send("/api/v1/findings/ingest?repo=a/b", write, " ".repeat(20 * 1024 * 1024 + 10)).catch(() => undefined);
    // The server may close the connection once it has refused; a status, when seen, is 413.
    if (reply) expect(reply.status).toBe(413);
    const db = new osecDB(dbPath, { readOnly: true });
    try { expect(db.listOrgFindings()).toEqual([]); } finally { db.close(); }
  });
});

describe("triage reason and history", () => {
  const triage = (fingerprint: string, body: object) => fetch(`${base}/api/finding-family/${encodeURIComponent(fingerprint)}/triage`, { method: "POST", headers: { "Content-Type": "application/json", "X-0-Control-Token": "control" }, body: JSON.stringify(body) });
  const fingerprintOf = async () => {
    const reply = await (await fetch(`${base}/api/findings-server/overview`)).json() as { findings: Array<{ fingerprint: string }> };
    return reply.findings[0]!.fingerprint;
  };

  it("requires a reason to suppress, records who and why, and shows the history", async () => {
    const write = writeKey();
    await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R1"));
    const fingerprint = await fingerprintOf();
    const refused = await triage(fingerprint, { triageStatus: "suppressed" });
    expect(refused.status).toBe(400);
    expect((await refused.json() as { error: string }).error).toMatch(/reason/);
    expect((await triage(fingerprint, { triageStatus: "suppressed", triageNote: "test fixture, not shipped" })).status).toBe(200);
    expect((await triage(fingerprint, { triageStatus: "new" })).status).toBe(200);
    const history = (await (await fetch(`${base}/api/findings-server/history/${encodeURIComponent(fingerprint)}`)).json() as { history: Array<{ action: string; actor: string; reason: string | null; prevState: string; newState: string; repo: string }> }).history;
    expect(history.map(row => row.action)).toEqual(["open", "suppress", "reopen"]);
    expect(history[1]).toMatchObject({ actor: "user-1", reason: "test fixture, not shipped", prevState: "new", newState: "suppressed", repo: "acme/api" });
    const viaApi = await (await get(`/api/v1/findings/${fingerprint}/history`, readKey())).json() as { history: unknown[] };
    expect(viaApi.history).toHaveLength(3);
  });

  it("does not let Cancelled suppress without a reason, and records Done as an acceptance", async () => {
    const write = writeKey();
    await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R1", "R2"));
    const rows = (await (await fetch(`${base}/api/findings-server/overview`)).json() as { findings: Array<{ fingerprint: string }> }).findings;
    const workflow = (fingerprint: string, workflowStatus: string) => fetch(`${base}/api/finding-family/${encodeURIComponent(fingerprint)}/workflow`, { method: "POST", headers: { "Content-Type": "application/json", "X-0-Control-Token": "control" }, body: JSON.stringify({ workflowStatus }) });
    const refused = await workflow(rows[0]!.fingerprint, "cancelled");
    expect(refused.status).toBe(400);
    expect((await refused.json() as { error: string }).error).toMatch(/reason/);
    expect((await workflow(rows[1]!.fingerprint, "done")).status).toBe(200);
    const history = (await (await fetch(`${base}/api/findings-server/history/${encodeURIComponent(rows[1]!.fingerprint)}`)).json() as { history: Array<{ action: string }> }).history;
    expect(history.map(row => row.action)).toEqual(["open", "accept"]);
  });

  it("leaves the free behaviour alone: no reason needed and no history without a license", async () => {
    const write = writeKey();
    await send("/api/v1/findings/ingest?repo=acme/api", write, sarif("R1"));
    const fingerprint = await fingerprintOf();
    license.mode = "none";
    expect((await triage(fingerprint, { triageStatus: "suppressed" })).status).toBe(200);
    const db = new osecDB(dbPath, { readOnly: true });
    try { expect(db.listFindingHistory(fingerprint).map(row => row.action)).toEqual(["open"]); } finally { db.close(); }
  });
});
