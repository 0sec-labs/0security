// Signed webhook deliveries for release and check events. Tested against a local server with computed signatures and fakes
// for the dispatcher; no request ever reaches GitHub.
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { configureAudit } from "./audit.js";
import { GITHUB_WEBHOOK_PATH, GitHubWebhookReceiver, WebhookSecretStore } from "./github-webhook.js";
import type { GithubEvent } from "./sentinel-github-events.js";

const dirs: string[] = [];
const servers: Server[] = [];
let delivery = 0;
const sign = (body: string, secret: string) => `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
const releaseBody = (over: Record<string, unknown> = {}) => JSON.stringify({ action: "published", repository: { full_name: "acme/app" }, release: { tag_name: "v1.2.0", name: "Release <b>one</b>", draft: false }, ...over });
const checkBody = (conclusion = "failure") => JSON.stringify({ action: "completed", repository: { full_name: "acme/app" }, check_run: { id: 9, name: "build", conclusion, head_sha: "b".repeat(40), check_suite: { head_branch: "main" }, pull_requests: [{ number: 3 }] } });

async function fixture(options: { repos?: string[]; maxBody?: number } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "zero-webhook-events-"));
  dirs.push(dir);
  configureAudit(join(dir, "audit.db"));
  const secrets = new WebhookSecretStore(dir);
  const secret = secrets.create()!;
  const delivered: Array<{ id: string; event: GithubEvent }> = [];
  const repos = options.repos ?? ["acme/app"];
  const receiver = new GitHubWebhookReceiver({
    secrets, ...(options.maxBody ? { maxBodyBytes: options.maxBody } : {}),
    dispatcher: () => ({
      targets: () => [], check: async () => true,
      eventTargets: event => (repos.includes(event.repo.toLowerCase()) ? [{ id: "trig-1" }] : []),
      deliver: async (id, event) => { delivered.push({ id, event }); return true; },
    }),
  });
  const server = createServer((req, res) => { void receiver.handle(req, res, req.socket.remoteAddress ?? "?"); });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  servers.push(server);
  const port = (server.address() as AddressInfo).port;
  const post = (event: string, body: string, headers: Record<string, string> = {}, id = `d-${String(++delivery).padStart(8, "0")}`) => new Promise<number>((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: GITHUB_WEBHOOK_PATH, method: "POST", headers: { "content-type": "application/json", "x-github-event": event, "x-github-delivery": id, "x-hub-signature-256": sign(body, secret), "content-length": String(Buffer.byteLength(body)), ...headers } }, res => { res.resume(); res.on("end", () => resolve(res.statusCode!)); });
    req.on("error", reject); req.end(body);
  });
  return { receiver, post, delivered, secret };
}

afterEach(async () => { configureAudit(null); for (const s of servers.splice(0)) await new Promise<void>(done => { s.closeAllConnections(); s.close(() => done()); }); for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

describe("release and check deliveries", () => {
  it("hands a correctly signed release to the matching trigger with neutral data", async () => {
    const f = await fixture();
    expect(await f.post("release", releaseBody())).toBe(202);
    await f.receiver.settled();
    expect(f.delivered).toHaveLength(1);
    expect(f.delivered[0]).toMatchObject({ id: "trig-1", event: { kind: "release", tag: "v1.2.0" } });
    expect(JSON.stringify(f.delivered[0]!.event.fields)).not.toMatch(/[<>]/);
  });
  it("hands a signed failed check run and a pushed tag to their triggers", async () => {
    const f = await fixture();
    await f.post("check_run", checkBody());
    await f.post("push", JSON.stringify({ ref: "refs/tags/v3.0.0", after: "c".repeat(40), repository: { full_name: "acme/app" } }));
    await f.receiver.settled();
    expect(f.delivered.map(item => `${item.event.kind}:${item.event.key}`)).toEqual(["check-completed:9", "release:v3.0.0"]);
    expect(f.delivered[0]!.event).toMatchObject({ pr: 3, conclusion: "failure", branch: "main" });
  });
  it("rejects a bad signature with 401 and starts nothing", async () => {
    const f = await fixture();
    const body = releaseBody();
    expect(await f.post("release", body, { "x-hub-signature-256": sign(body, "ee".repeat(32)) })).toBe(401);
    expect(await f.post("release", body, { "x-hub-signature-256": sign(`${body} `, f.secret) })).toBe(401);
    await f.receiver.settled();
    expect(f.delivered).toHaveLength(0);
  });
  it("answers a replayed delivery id with 202 and starts nothing the second time", async () => {
    const f = await fixture();
    expect(await f.post("release", releaseBody(), {}, "replay-0001")).toBe(202);
    expect(await f.post("release", releaseBody(), {}, "replay-0001")).toBe(202);
    await f.receiver.settled();
    expect(f.delivered).toHaveLength(1);
    expect(f.receiver.status().deliveries[0]).toMatchObject({ result: "ignored", reason: "duplicate_delivery" });
  });
  it("refuses an oversized body with 413 before verifying or parsing it", async () => {
    const f = await fixture({ maxBody: 2_000 });
    const big = releaseBody({ padding: "x".repeat(5_000) });
    const status = await f.post("release", big).catch(() => 413);
    expect(status).toBe(413);
    await f.receiver.settled();
    expect(f.delivered).toHaveLength(0);
  });
  it("ignores events that are not allowed, and events for a repository no trigger watches", async () => {
    const f = await fixture();
    expect(await f.post("issues", JSON.stringify({ action: "opened" }))).toBe(202);
    expect(f.receiver.status().deliveries[0]).toMatchObject({ reason: "event_not_allowed" });
    expect(await f.post("release", releaseBody({ repository: { full_name: "other/repo" } }))).toBe(202);
    expect(f.receiver.status().deliveries[0]).toMatchObject({ reason: "no_matching_trigger" });
    expect(await f.post("release", releaseBody({ action: "created" }))).toBe(202);
    expect(f.receiver.status().deliveries[0]).toMatchObject({ reason: "action_not_allowed" });
    await f.receiver.settled();
    expect(f.delivered).toHaveLength(0);
  });
  it("does not call the dispatcher for a malformed payload", async () => {
    const f = await fixture();
    expect(await f.post("check_run", JSON.stringify({ action: "completed", repository: { full_name: "acme/app" }, check_run: { id: "nine" } }))).toBe(202);
    await f.receiver.settled();
    expect(f.delivered).toHaveLength(0);
    expect(f.receiver.status().deliveries[0]).toMatchObject({ reason: "payload_shape" });
  });
});
