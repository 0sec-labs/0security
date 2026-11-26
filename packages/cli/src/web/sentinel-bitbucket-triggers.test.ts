// The bitbucket-pr trigger: store and API, polling and signed webhook deliveries, tested with a fake Bitbucket server and the
// pinned Atlassian payload excerpts. Nothing here reaches a real Bitbucket and no model runs.
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSecurityWorkflowTemplate } from "@0/engine/shared";
import { SecurityWorkflowStore, SentinelStore } from "@0/engine/storage";
import { BitbucketClient, type PullRequest } from "../bitbucket/client.js";
import { cloudPr, dcPr, startFakeBitbucket, type FakeBitbucket } from "../bitbucket/__tests__/fake-bitbucket.js";
import type { ReviewRunner } from "../bitbucket/review.js";
import type { Reviewer, ReviewerSettings } from "../bitbucket/service.js";
import { configureAudit } from "./audit.js";
import { SignedWebhookReceiver, SignedWebhookSecrets } from "./signed-webhook.js";
import { WebSentinelService } from "./sentinels.js";

const P = "/api/console/sentinels";
const ID = "0b9f5d1e-3c5a-4c7e-9a52-1d6f2a7b8c90";
const dirs: string[] = [];
const servers: Server[] = [];
const fakes: FakeBitbucket[] = [];
const services: WebSentinelService[] = [];
let clock = Date.parse("2026-03-02T10:00:00Z");
const MIN = 60_000;
const fixture = (name: string) => readFileSync(new URL(`../__fixtures__/bitbucket/${name}`, import.meta.url), "utf8");
const hex = (body: string, secret: string) => createHmac("sha256", secret).update(body).digest("hex");
const DIFF = ["diff --git a/app/db.py b/app/db.py", "--- a/app/db.py", "+++ b/app/db.py", "@@ -1,2 +1,3 @@", " import os", "+run(name)", " end", ""].join("\n");

afterEach(async () => {
  configureAudit(null);
  clock = Date.parse("2026-03-02T10:00:00Z");
  for (const service of services.splice(0)) await service.dispose();
  for (const fake of fakes.splice(0)) await fake.close();
  for (const server of servers.splice(0)) await new Promise<void>(done => { server.closeAllConnections(); server.close(() => done()); });
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const finding = { category: "sql-injection", severity: "high", title: "SQL built from input", description: "d", status: "confirmed", confidence: 0.9, location: { path: "app/db.py", startLine: 2 }, evidence: { analysis: "CWE: CWE-89" } };

interface Harness {
  service: WebSentinelService; store: SentinelStore; call: (method: string, path: string, body?: unknown) => Promise<{ status: number; data: any }>;
  sentinelId: string; automationId: string; scans: PullRequest[]; settings: ReviewerSettings[];
  create(config: Record<string, unknown>, enabled?: boolean): Promise<{ status: number; data: any }>;
  tick(minutes: number): Promise<void>; activations(): Promise<Array<Record<string, any>>>; trigger(id: string): Record<string, any>;
}

async function harness(options: { reviewerFor?: (settings: ReviewerSettings) => Reviewer; env?: NodeJS.ProcessEnv } = {}): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "zero-bitbucket-trigger-"));
  dirs.push(dir);
  const dbPath = join(dir, "control.db");
  const scans: PullRequest[] = [];
  const settings: ReviewerSettings[] = [];
  const runner: ReviewRunner = { async scan(pr) { scans.push(pr); return { sha: pr.headSha.padEnd(40, "0"), json: JSON.stringify({ findings: [finding] }), exitCode: 0 }; } };
  const missions = { create: vi.fn(() => ({ id: "m1" })), send: vi.fn(async () => ({})), pendingDecisions: vi.fn(() => 0), subscribe: vi.fn(() => () => undefined) };
  const reviewer = (s: ReviewerSettings): Reviewer => {
    settings.push(s);
    if (options.reviewerFor) return options.reviewerFor(s);
    throw new Error("no reviewer for this test");
  };
  const service = new WebSentinelService({
    dbPath, missions: missions as never, now: () => clock, executionProfile: () => "local", checkout: async () => undefined, persistentThread: () => false,
    bitbucket: { env: options.env ?? { BITBUCKET_TOKEN: "fake-token-value" }, reviewer: (s: ReviewerSettings) => { const r = reviewer(s); return { ...r, runner }; } },
  });
  services.push(service);
  const workflows = new SecurityWorkflowStore(dbPath);
  const store = new SentinelStore(dbPath);
  const call = async (method: string, path: string, body?: unknown) => { const url = new URL(`http://localhost${path}`); return (await service.handle(url.pathname, method, body, url.searchParams))! as { status: number; data: any }; };
  const sentinelId = (await call("POST", P, { name: "PR Review", skills: ["pr-diff-review"] })).data.sentinel.id as string;
  await call("POST", `${P}/${sentinelId}/resume`, { acknowledge: true });
  const automationId = workflows.save({ ...createSecurityWorkflowTemplate("dependency-review", { target: "." }), ownerSentinelId: sentinelId }).id;
  return {
    service, store, call, sentinelId, automationId, scans, settings,
    create: (config, enabled = true) => call("POST", `${P}/${sentinelId}/triggers`, { automationId, kind: "bitbucket-pr", bitbucket: config, enabled, ...(enabled ? { approval: "enable-reviewed-trigger" } : {}) }),
    tick: async minutes => { clock += minutes * MIN; await service.tick(clock); await service.settled(); },
    activations: async () => (await call("GET", `${P}/${sentinelId}/activations`)).data.activations,
    trigger: id => store.getTrigger(id) as unknown as Record<string, any>,
  };
}

const cloudSettings = { platform: "cloud", repo: "ws/app", checkout: "/srv/clones/app", pollMs: 60_000 };

async function withFake(platform: "bitbucket-cloud" | "bitbucket-dc") {
  const fake = await startFakeBitbucket(platform);
  fakes.push(fake);
  fake.diff = DIFF;
  const cloud = platform === "bitbucket-cloud";
  const h = await harness({
    reviewerFor: s => {
      const client = new BitbucketClient({ platform, token: s.token, ...(cloud ? { cloudApiUrl: `${fake.url}/2.0` } : { baseUrl: fake.url }) });
      return { platform, owner: cloud ? "ws" : "PRJ", repo: "app", client, runner: undefined as never, review: { reportId: s.reportId, maxFiles: s.maxFiles, maxInline: s.maxInline, comments: s.comments, insights: s.insights } };
    },
  });
  return { fake, h, cloud };
}

describe("settings and storage", () => {
  it("round-trips Cloud and Data Center settings with defaults, and shows a one-line summary", async () => {
    const h = await harness();
    const cloud = await h.create({ platform: "cloud", repo: "ws/app", checkout: "/srv/clones/app" }, false);
    expect(cloud.status).toBe(201);
    expect(cloud.data.trigger.bitbucket).toEqual({ platform: "cloud", repo: "ws/app", checkout: "/srv/clones/app", allowInsecureHttp: false, tokenEnv: "BITBUCKET_TOKEN", events: ["opened", "updated"], pollMs: 120_000, maxFiles: 50, maxInline: 10, budgetUsd: 2, reportId: "0-security", comments: true, insights: true });
    expect(cloud.data.trigger.summary).toBe("Bitbucket Cloud pull requests in ws/app (opened and updated), reports as comments and Code Insights");
    const dc = await h.create({ platform: "dc", repo: "PRJ/app", baseUrl: "https://bitbucket.example.com", checkout: "/srv/clones/app", tokenEnv: "BITBUCKET_DC_TOKEN", events: ["updated"], maxFiles: 20, budgetUsd: 0.5 }, false);
    expect(dc.status).toBe(201);
    const listed = (await h.call("GET", `${P}/${h.sentinelId}/triggers`)).data.triggers as Array<{ kind: string; bitbucket: Record<string, unknown> }>;
    expect(listed.map(item => item.kind)).toEqual(["bitbucket-pr", "bitbucket-pr"]);
    expect(listed.find(item => item.bitbucket["platform"] === "dc")!.bitbucket).toMatchObject({ platform: "dc", baseUrl: "https://bitbucket.example.com", tokenEnv: "BITBUCKET_DC_TOKEN", events: ["updated"], maxFiles: 20, budgetUsd: 0.5 });
    expect(h.service.isWebhookTrigger(cloud.data.trigger.id)).toBe(true);
  });

  it("refuses inline secrets, odd credentials, relative paths, bad urls and missing settings", async () => {
    const h = await harness();
    const bad = async (config: Record<string, unknown>) => (await h.create({ ...cloudSettings, ...config }, false)).status;
    expect(await bad({ token: "x" })).toBe(400);
    expect(await bad({ tokenEnv: "OPENAI_API_KEY" })).toBe(400);
    expect(await bad({ tokenEnv: "BITBUCKET_TOKEN=abc" })).toBe(400);
    expect(await bad({ tokenEnv: "bitbucket_token" })).toBe(400);
    expect(await bad({ checkout: "../clone" })).toBe(400);
    expect(await bad({ repo: "ws" })).toBe(400);
    expect(await bad({ repo: "ws/../x" })).toBe(400);
    expect(await bad({ platform: "dc" })).toBe(400);
    expect(await bad({ platform: "dc", baseUrl: "https://user:pass@bitbucket.example.com" })).toBe(400);
    expect(await bad({ platform: "dc", baseUrl: "ftp://bitbucket.example.com" })).toBe(400);
    expect(await bad({ events: [] })).toBe(400);
    expect(await bad({ events: ["deleted"] })).toBe(400);
    expect(await bad({ maxFiles: 0 })).toBe(400);
    expect(await bad({ budgetUsd: 1000 })).toBe(400);
    expect(await bad({ pollMs: 1000 })).toBe(400);
    expect(await bad({ reportId: "has space" })).toBe(400);
    expect((await h.call("POST", `${P}/${h.sentinelId}/triggers`, { automationId: h.automationId, kind: "bitbucket-pr" })).status).toBe(400);
    expect((await h.call("POST", `${P}/${h.sentinelId}/triggers`, { automationId: h.automationId, kind: "manual", bitbucket: cloudSettings })).status).toBe(400);
  });

  it("starts disabled, needs review to enable, and a settings edit turns it off again", async () => {
    const h = await harness();
    expect((await h.call("POST", `${P}/${h.sentinelId}/triggers`, { automationId: h.automationId, kind: "bitbucket-pr", bitbucket: cloudSettings, enabled: true })).status).toBe(400);
    const created = await h.create(cloudSettings, false);
    expect(created.data.trigger.enabled).toBe(false);
    const id = created.data.trigger.id as string;
    expect((await h.call("PATCH", `${P}/${h.sentinelId}/triggers/${id}`, { enabled: true, approval: "enable-reviewed-trigger" })).data.trigger.enabled).toBe(true);
    const edited = await h.call("PATCH", `${P}/${h.sentinelId}/triggers/${id}`, { bitbucket: { ...cloudSettings, maxFiles: 5 } });
    expect(edited.data.trigger).toMatchObject({ enabled: false, bitbucket: { maxFiles: 5 } });
  });
});

describe.each(["bitbucket-cloud", "bitbucket-dc"] as const)("polling on %s", platform => {
  it("records what is open, then reviews a new pull request and new commits once each", async () => {
    const { fake, h, cloud } = await withFake(platform);
    const make = cloud ? cloudPr : dcPr;
    fake.pullRequests.push(make(1));
    const config = cloud ? cloudSettings : { platform: "dc", repo: "PRJ/app", baseUrl: fake.url, checkout: "/srv/clones/app", pollMs: 60_000 };
    const trigger = (await h.create(config)).data.trigger.id as string;
    h.store.updateTrigger(trigger, { runModel: { providerId: "azure", model: "deployment", reasoning: "high" }, enabled: true }, undefined, clock);

    await h.tick(0);
    expect(h.trigger(trigger)).toMatchObject({ lastStatus: "baseline", cursor: { "1": expect.any(String) } });
    expect(h.scans).toHaveLength(0);

    // A new pull request: reviewed, commented and reported.
    fake.pullRequests.push(make(2));
    await h.tick(1);
    expect(h.scans.map(pr => pr.id)).toEqual([2]);
    expect(h.settings.at(-1)).toMatchObject({ providerId: "azure", model: "deployment", reasoning: "high" });
    expect(fake.comments.length).toBeGreaterThanOrEqual(2);
    expect(fake.report).toBeDefined();
    expect(h.trigger(trigger)).toMatchObject({ lastStatus: "reviewed" });
    const first = await h.activations();
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ status: "completed", trigger: { kind: "bitbucket-pr", triggerId: trigger, event: { repo: expect.any(String), pr: 2, event: "opened" } } });
    expect(first[0]!.note).toContain("1 finding");

    // Nothing changed: no second review, no second comment.
    const comments = fake.comments.length;
    await h.tick(1);
    expect(h.scans).toHaveLength(1);
    expect(fake.comments).toHaveLength(comments);

    // New commits on pull request 2.
    fake.pullRequests[1] = cloud ? cloudPr(2, { source: { branch: { name: "feature-2" }, commit: { hash: "cccccccccccc" }, repository: { full_name: "ws/app" } } }) : dcPr(2, { fromRef: { ...(dcPr(2).fromRef), latestCommit: "c".repeat(40) } });
    await h.tick(1);
    expect(h.scans.map(pr => pr.id)).toEqual([2, 2]);
    expect((await h.activations())[0]).toMatchObject({ trigger: { event: { pr: 2, event: "updated" } } });
    // The summary is edited in place.
    expect(fake.comments.filter(comment => comment.text.includes("[0-review:0-security:summary]"))).toHaveLength(1);
    expect(JSON.stringify(fake.comments)).not.toContain(fake.token);
  });

  it("skips a draft and a fork once, then reviews the draft when it is ready", async () => {
    const { fake, h, cloud } = await withFake(platform);
    const make = cloud ? cloudPr : dcPr;
    fake.pullRequests.push(make(1));
    const config = cloud ? cloudSettings : { platform: "dc", repo: "PRJ/app", baseUrl: fake.url, checkout: "/srv/clones/app", pollMs: 60_000 };
    await h.create(config);
    await h.tick(0);
    fake.pullRequests.push(make(2, { draft: true }));
    fake.pullRequests.push(cloud ? cloudPr(3, { source: { branch: { name: "f" }, commit: { hash: "dddddddddddd" }, repository: { full_name: "other/app" } } }) : dcPr(3, { fromRef: { ...dcPr(3).fromRef, repository: { id: 9, slug: "app", project: { key: "OTHER" } } } }));
    await h.tick(1);
    await h.tick(1);
    expect(h.scans).toHaveLength(0);
    const skipped = (await h.activations()).filter(item => item.status === "skipped");
    expect(skipped.map(item => item.trigger.event.pr).sort()).toEqual([2, 3]);
    // Marking the draft ready starts a review at the same commit.
    fake.pullRequests[1] = make(2, { draft: false });
    await h.tick(1);
    expect(h.scans.map(pr => pr.id)).toEqual([2]);
  });

  it("respects the events setting", async () => {
    const { fake, h, cloud } = await withFake(platform);
    const make = cloud ? cloudPr : dcPr;
    fake.pullRequests.push(make(1));
    const config = cloud ? { ...cloudSettings, events: ["updated"] } : { platform: "dc", repo: "PRJ/app", baseUrl: fake.url, checkout: "/srv/clones/app", pollMs: 60_000, events: ["updated"] };
    await h.create(config);
    await h.tick(0);
    fake.pullRequests.push(make(2));
    await h.tick(1);
    expect(h.scans).toHaveLength(0);
  });

  it("skips a pull request with more files than the limit and says so on the pull request", async () => {
    const { fake, h, cloud } = await withFake(platform);
    const make = cloud ? cloudPr : dcPr;
    fake.diff = [DIFF, "diff --git a/b.py b/b.py", "--- a/b.py", "+++ b/b.py", "@@ -1 +1,2 @@", " x", "+y", ""].join("\n");
    fake.pullRequests.push(make(1));
    const config = cloud ? { ...cloudSettings, maxFiles: 1 } : { platform: "dc", repo: "PRJ/app", baseUrl: fake.url, checkout: "/srv/clones/app", pollMs: 60_000, maxFiles: 1 };
    await h.create(config);
    await h.tick(0);
    fake.pullRequests.push(make(2));
    await h.tick(1);
    expect(h.scans).toHaveLength(0);
    expect(fake.comments.some(comment => comment.text.includes("more than the limit of 1"))).toBe(true);
    expect((await h.activations())[0]!.note).toContain("too many");
  });
});

describe("credentials and enterprise mode", () => {
  it("reads the token from the named variable only, and reports a missing one on the trigger", async () => {
    const h = await harness({ env: { BITBUCKET_TOKEN: "", BITBUCKET_OTHER: "other-token" } });
    const id = (await h.create({ ...cloudSettings, tokenEnv: "BITBUCKET_OTHER" })).data.trigger.id as string;
    expect(JSON.stringify((await h.call("GET", `${P}/${h.sentinelId}/triggers`)).data)).not.toContain("other-token");
    const missing = (await h.create({ ...cloudSettings, repo: "ws/two" })).data.trigger.id as string;
    await h.tick(0);
    expect(h.trigger(missing)).toMatchObject({ lastStatus: "blocked" });
    expect(h.trigger(missing).lastError).toContain("BITBUCKET_TOKEN");
    expect(h.settings.map(s => s.token)).toEqual(["other-token"]);
    expect(h.settings[0]!.secretVariables).toEqual(["BITBUCKET_OTHER"]);
    expect(id).not.toBe(missing);
  });

  it("is refused in enterprise mode before anything is sent", async () => {
    const before = process.env["ZERO_ENTERPRISE"];
    process.env["ZERO_ENTERPRISE"] = "1";
    try {
      const h = await harness();
      const id = (await h.create(cloudSettings)).data.trigger.id as string;
      await h.tick(0);
      expect(h.trigger(id)).toMatchObject({ lastStatus: "blocked" });
      expect(h.settings).toHaveLength(0);
      expect(h.scans).toHaveLength(0);
    } finally { if (before === undefined) delete process.env["ZERO_ENTERPRISE"]; else process.env["ZERO_ENTERPRISE"] = before; }
  });
});

/** A client that serves the pull requests in the pinned webhook excerpts without any network. */
function stubReviewer(platform: "bitbucket-cloud" | "bitbucket-dc", prs: () => PullRequest[]): (s: ReviewerSettings) => Reviewer {
  return s => {
    const [owner, repo] = s.repo.split("/") as [string, string];
    const client = {
      platform, listOpenPullRequests: async () => prs(), diff: async () => ({ text: DIFF, truncated: false }), findComments: async () => [],
      addComment: vi.fn(async () => undefined), updateComment: vi.fn(async () => undefined), deleteComment: vi.fn(async () => undefined), publishInsights: vi.fn(async () => undefined),
    } as unknown as BitbucketClient;
    return { platform, owner, repo, client, runner: undefined as never, review: { reportId: s.reportId, maxFiles: s.maxFiles, maxInline: s.maxInline, comments: s.comments, insights: s.insights } };
  };
}

async function receiverFor(h: Harness, triggerId: string) {
  const secretsDir = mkdtempSync(join(tmpdir(), "zero-bitbucket-secrets-"));
  dirs.push(secretsDir);
  configureAudit(join(secretsDir, "audit.db"));
  const secrets = new SignedWebhookSecrets(secretsDir, () => clock);
  const secret = secrets.rotate(triggerId);
  const receiver = new SignedWebhookReceiver({ secrets, now: () => clock, dispatcher: () => ({ deliver: (id, input) => h.service.deliverSignedWebhook(id, input) }) });
  const server = createServer((req, res) => { void receiver.handle(req, res, "127.0.0.1", triggerId); });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  servers.push(server);
  const port = (server.address() as AddressInfo).port;
  const post = (body: string, headers: Record<string, string> = {}) => new Promise<{ status: number }>((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), ...headers } }, res => { res.resume(); res.on("end", () => resolve({ status: res.statusCode! })); });
    req.on("error", reject); req.end(body);
  });
  const signed = (body: string, event: string, extra: Record<string, string> = {}) => post(body, { "x-hub-signature": `sha256=${hex(body, secret)}`, "x-event-key": event, ...extra });
  return { post, signed, secret, receiver };
}

describe("signed webhook deliveries", () => {
  it("reviews the pull request in a Data Center pr:from_ref_updated delivery, once, and ignores a replay", async () => {
    const h = await harness({ reviewerFor: stubReviewer("bitbucket-dc", () => []) });
    const id = (await h.create({ platform: "dc", repo: "GIT/dvcs", baseUrl: "https://bitbucket.example.com", checkout: "/srv/clones/dvcs", pollMs: 60_000 })).data.trigger.id as string;
    const web = await receiverFor(h, id);
    const body = fixture("dc-pr-from-ref-updated.json");
    expect((await web.signed(body, "pr:from_ref_updated", { "x-request-id": "dc-delivery-0001" })).status).toBe(202);
    await web.receiver.settled(); await h.service.settled();
    expect(h.scans).toHaveLength(1);
    expect(h.scans[0]).toMatchObject({ owner: "GIT", repo: "dvcs", id: 2, platform: "bitbucket-dc" });
    expect(await h.activations()).toHaveLength(1);
    expect((await h.activations())[0]).toMatchObject({ status: "completed", trigger: { kind: "bitbucket-pr", event: { event: "updated", pr: 2 } } });
    // The same delivery again, and the same commit under a new delivery id: no second review.
    expect((await web.signed(body, "pr:from_ref_updated", { "x-request-id": "dc-delivery-0001" })).status).toBe(202);
    expect((await web.signed(body, "pr:from_ref_updated", { "x-request-id": "dc-delivery-0002" })).status).toBe(202);
    await web.receiver.settled(); await h.service.settled();
    expect(h.scans).toHaveLength(1);
    expect(await h.activations()).toHaveLength(1);
    // A webhook before any poll leaves the first poll free to record what is open.
    expect(h.trigger(id).cursor).toBeUndefined();
  });

  it("reviews the pull request in a Cloud pullrequest:updated delivery", async () => {
    const h = await harness({ reviewerFor: stubReviewer("bitbucket-cloud", () => []) });
    const id = (await h.create({ ...cloudSettings, repo: "workspace/repo" })).data.trigger.id as string;
    const web = await receiverFor(h, id);
    expect((await web.signed(fixture("cloud-pullrequest-created.json"), "pullrequest:updated", { "x-request-uuid": "cloud-delivery-1" })).status).toBe(202);
    await web.receiver.settled(); await h.service.settled();
    expect(h.scans).toHaveLength(1);
    expect(h.scans[0]).toMatchObject({ owner: "workspace", repo: "repo", id: 1, platform: "bitbucket-cloud" });
  });

  it("ignores other events, other repositories and events the trigger is not set to react to", async () => {
    const h = await harness({ reviewerFor: stubReviewer("bitbucket-cloud", () => []) });
    const id = (await h.create({ ...cloudSettings, repo: "workspace/repo", events: ["opened"] })).data.trigger.id as string;
    const web = await receiverFor(h, id);
    const body = fixture("cloud-pullrequest-created.json");
    expect((await web.signed(body, "repo:push", { "x-request-uuid": "cloud-delivery-1" })).status).toBe(202);
    expect((await web.signed(body, "pullrequest:updated", { "x-request-uuid": "cloud-delivery-2" })).status).toBe(202);
    expect((await web.signed(body.replace(/workspace\/repo/g, "someone/else"), "pullrequest:created", { "x-request-uuid": "cloud-delivery-3" })).status).toBe(202);
    await web.receiver.settled(); await h.service.settled();
    expect(h.scans).toHaveLength(0);
    expect(await h.activations()).toHaveLength(0);
    expect((await web.signed(body, "pullrequest:created", { "x-request-uuid": "cloud-delivery-4" })).status).toBe(202);
    await web.receiver.settled(); await h.service.settled();
    expect(h.scans).toHaveLength(1);
  });

  it("rejects a wrong signature, a missing signature, the wrong content type and an oversize body, and starts nothing", async () => {
    const h = await harness({ reviewerFor: stubReviewer("bitbucket-cloud", () => []) });
    const id = (await h.create({ ...cloudSettings, repo: "workspace/repo" })).data.trigger.id as string;
    const web = await receiverFor(h, id);
    const body = fixture("cloud-pullrequest-created.json");
    expect((await web.post(body, { "x-hub-signature": `sha256=${hex(body, "wrong-secret")}`, "x-event-key": "pullrequest:created" })).status).toBe(401);
    expect((await web.post(body, { "x-event-key": "pullrequest:created" })).status).toBe(401);
    expect((await web.post(body, { "x-hub-signature": "sha1=abc", "x-event-key": "pullrequest:created" })).status).toBe(401);
    expect((await web.signed(body, "pullrequest:created", { "content-type": "text/plain" })).status).toBe(415);
    const huge = JSON.stringify({ pad: "x".repeat(300 * 1024) });
    expect((await web.signed(huge, "pullrequest:created").catch(() => ({ status: 413 }))).status).toBe(413);
    await web.receiver.settled(); await h.service.settled();
    expect(h.scans).toHaveLength(0);
    expect(await h.activations()).toHaveLength(0);
  });

  it("does nothing for a disabled trigger", async () => {
    const h = await harness({ reviewerFor: stubReviewer("bitbucket-cloud", () => []) });
    const id = (await h.create({ ...cloudSettings, repo: "workspace/repo" }, false)).data.trigger.id as string;
    expect(await h.service.deliverSignedWebhook(id, { key: "id-1", fields: {}, eventKey: "pullrequest:created", payload: JSON.parse(fixture("cloud-pullrequest-created.json")) })).toBe(false);
    expect(h.scans).toHaveLength(0);
  });
});
