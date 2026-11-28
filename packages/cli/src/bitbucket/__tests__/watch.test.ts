import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect, type AddressInfo, type Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BitbucketClient, type PullRequest } from "../client.js";
import { parseDiff } from "../diff.js";
import { MAX_WEBHOOK_BODY, MAX_WEBHOOK_CONNECTIONS, createWebhookServer, pollOnce, ReviewQueue } from "../watch.js";
import { cloudPr, startFakeBitbucket, type FakeBitbucket } from "./fake-bitbucket.js";

const pr = (id: number, over: Partial<PullRequest> = {}): PullRequest => ({ platform: "bitbucket-cloud", owner: "workspace", repo: "repo", id, title: "t", draft: false, fork: false, open: true, headSha: "a".repeat(40), headBranch: "b", baseBranch: "main", ...over });
const sample = (name: string) => readFileSync(new URL(`../../__fixtures__/bitbucket/${name}`, import.meta.url), "utf8");

describe("diff reading", () => {
  it("lists changed files and the lines of the new file, skipping deletions and odd paths", () => {
    const diff = [
      "diff --git a/a.py b/a.py", "--- a/a.py", "+++ b/a.py", "@@ -1,3 +1,4 @@", " one", "-two", "+TWO", "+three", " four", "\\ No newline at end of file",
      "@@ -10,1 +11,2 @@", " ten", "+eleven",
      "diff --git a/gone.py b/gone.py", "--- a/gone.py", "+++ /dev/null", "@@ -1 +0,0 @@", "-x",
      "diff --git a/../evil b/../evil", "--- a/../evil", "+++ b/../evil", "@@ -1 +1 @@", "+x",
      "diff --git a/dir/n.js b/dir/n.js", "--- /dev/null", "+++ b/dir/n.js", "@@ -0,0 +1,2 @@", "++++ not a header", "+b", "",
    ].join("\n");
    const files = parseDiff(diff);
    expect(files.map(file => file.path)).toEqual(["a.py", "dir/n.js"]);
    expect([...files[0]!.lines]).toEqual([[1, "CONTEXT"], [2, "ADDED"], [3, "ADDED"], [4, "CONTEXT"], [11, "CONTEXT"], [12, "ADDED"]]);
    expect([...files[1]!.lines]).toEqual([[1, "ADDED"], [2, "ADDED"]]);
  });
});

describe("review queue", () => {
  it("runs one review at a time and queues a pull request once", async () => {
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>(done => { release = done; });
    const queue = new ReviewQueue({
      review: async item => { order.push(`start ${item.id}`); if (item.id === 1) await gate; order.push(`end ${item.id}`); return { status: "skipped", reason: "unchanged" }; },
      log: () => undefined,
    });
    queue.add(pr(1));
    queue.add(pr(2));
    queue.add(pr(2, { headSha: "b".repeat(40) }));
    await new Promise(done => setTimeout(done, 20));
    expect(order).toEqual(["start 1"]);
    release();
    await queue.idle();
    expect(order).toEqual(["start 1", "end 1", "start 2", "end 2"]);
    expect(queue.pending).toBe(0);
  });

  it("logs a failed review and carries on", async () => {
    const lines: string[] = [];
    const queue = new ReviewQueue({ review: async item => { if (item.id === 1) throw new Error("boom\nsecond line"); return { status: "skipped", reason: "draft" }; }, log: line => lines.push(line) });
    queue.add(pr(1));
    queue.add(pr(2));
    await queue.idle();
    expect(lines).toEqual(["bitbucket-cloud:workspace/repo#1: review failed: boom", "bitbucket-cloud:workspace/repo#2: skipped (draft)"]);
  });
});

describe("polling", () => {
  let fake: FakeBitbucket | undefined;
  afterEach(async () => { await fake?.close(); });

  it("queues open pull requests whose head commit is new, skipping drafts, forks and ones already reviewed", async () => {
    fake = await startFakeBitbucket("bitbucket-cloud");
    fake.pullRequests.push(cloudPr(1), cloudPr(2, { draft: true }), cloudPr(3, { source: { branch: { name: "f" }, commit: { hash: "cccccccccccc" }, repository: { full_name: "other/fork" } } }), cloudPr(4), cloudPr(5), cloudPr(6));
    const client = new BitbucketClient({ platform: "bitbucket-cloud", token: fake.token, cloudApiUrl: `${fake.url}/2.0` });
    const queued: number[] = [];
    const queue = new ReviewQueue({ review: async item => { queued.push(item.id); return { status: "skipped", reason: "unchanged" }; }, log: () => undefined });
    const reviewed = new Map([["bitbucket-cloud:ws/app#4", "aaaaaaaaaaa4zzzz"]]);
    const count = await pollOnce(client, { owner: "ws", repo: "app" }, queue, { get: key => reviewed.get(key) }, 2);
    await queue.idle();
    expect(count).toBe(2);
    expect(queued).toEqual([1, 5]);
  });
});

describe("webhook server", () => {
  const secret = "a-webhook-secret-of-some-length";
  const sign = (body: string, key = secret) => `sha256=${createHmac("sha256", key).update(body).digest("hex")}`;
  let server: ReturnType<typeof createWebhookServer> | undefined;
  afterEach(async () => { server?.closeAllConnections(); await new Promise<void>(done => (server ? server.close(() => done()) : done())); server = undefined; });

  async function start(platform: "bitbucket-cloud" | "bitbucket-dc", repo: { owner: string; repo: string }) {
    const queued: PullRequest[] = [];
    const logs: string[] = [];
    const queue = new ReviewQueue({ review: async item => { queued.push(item); return { status: "skipped", reason: "unchanged" }; }, log: () => undefined });
    server = createWebhookServer({ platform, secret, repo, queue, log: line => logs.push(line) });
    await new Promise<void>(done => server!.listen(0, "127.0.0.1", done));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const post = (body: string, headers: Record<string, string>) => fetch(url, { method: "POST", body, headers });
    return { queued, queue, logs, post, url };
  }

  it("queues a signed Cloud delivery for the named repository", async () => {
    const { queued, queue, post } = await start("bitbucket-cloud", { owner: "workspace", repo: "repo" });
    const body = sample("cloud-pullrequest-created.json");
    const response = await post(body, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(body) });
    expect(response.status).toBe(202);
    await queue.idle();
    expect(queued.map(item => item.id)).toEqual([1]);
  });

  it("queues a signed Data Center delivery from the documentation sample", async () => {
    const { queued, queue, post } = await start("bitbucket-dc", { owner: "git", repo: "DVCS" });
    const body = sample("dc-pr-from-ref-updated.json");
    expect((await post(body, { "X-Event-Key": "pr:from_ref_updated", "X-Hub-Signature": sign(body) })).status).toBe(202);
    await queue.idle();
    expect(queued).toHaveLength(1);
    expect(queued[0]).toMatchObject({ owner: "GIT", repo: "dvcs", headSha: "aab847db240ccae221f8036605b00f777eba95d2" });
  });

  it("refuses a bad or missing signature, a wrong method and a large body, and ignores other events and repositories", async () => {
    const { queued, queue, post, url, logs } = await start("bitbucket-cloud", { owner: "workspace", repo: "repo" });
    const body = sample("cloud-pullrequest-created.json");
    expect((await post(body, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(body, "wrong secret value here") })).status).toBe(401);
    expect((await post(body, { "X-Event-Key": "pullrequest:created" })).status).toBe(401);
    expect((await fetch(url, { method: "GET" })).status).toBe(405);
    const big = "x".repeat(MAX_WEBHOOK_BODY + 10);
    expect((await post(big, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(big) }).catch(() => ({ status: 413 }))).status).toBe(413);
    expect((await post(body, { "X-Event-Key": "repo:push", "X-Hub-Signature": sign(body) })).status).toBe(202);
    const other = body.replaceAll('"full_name": "workspace/repo"', '"full_name": "workspace/else"');
    expect((await post(other, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(other) })).status).toBe(202);
    const notJson = "not json";
    expect((await post(notJson, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(notJson) })).status).toBe(400);
    await queue.idle();
    expect(queued).toEqual([]);
    expect(logs.join("\n")).toContain("signature did not match");
  });

  it("caps open connections and sets short timeouts, then still takes a signed delivery", async () => {
    const { queued, queue, post } = await start("bitbucket-cloud", { owner: "workspace", repo: "repo" });
    expect(server!.headersTimeout).toBeLessThanOrEqual(10_000);
    expect(server!.requestTimeout).toBeGreaterThan(0);
    expect(server!.requestTimeout).toBeLessThanOrEqual(15_000);
    expect(MAX_WEBHOOK_CONNECTIONS * MAX_WEBHOOK_BODY).toBeLessThanOrEqual(64 * 1024 * 1024);
    const port = (server!.address() as AddressInfo).port;
    const open = () => new Promise<Socket>(done => { const socket = connect(port, "127.0.0.1", () => done(socket)); socket.on("error", () => undefined); });
    const held: Socket[] = [];
    for (let i = 0; i < MAX_WEBHOOK_CONNECTIONS; i++) held.push(await open());
    const extra = await open();
    const outcome = await Promise.race([new Promise(done => extra.once("close", () => done("closed"))), new Promise(done => setTimeout(() => done("still open"), 2_000))]);
    expect(outcome).toBe("closed");
    expect(held.some(socket => socket.destroyed)).toBe(false);
    for (const socket of held) socket.destroy();
    extra.destroy();
    await new Promise(done => setTimeout(done, 100));
    const body = sample("cloud-pullrequest-created.json");
    expect((await post(body, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(body) })).status).toBe(202);
    await queue.idle();
    expect(queued.map(item => item.id)).toEqual([1]);
  });

  it("cuts off an unsigned body that does not arrive within 10 seconds", async () => {
    await start("bitbucket-cloud", { owner: "workspace", repo: "repo" });
    const port = (server!.address() as AddressInfo).port;
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let answer: string;
    try {
      const socket = connect(port, "127.0.0.1");
      socket.on("error", () => undefined);
      const received = new Promise<string>(done => { let text = ""; socket.on("data", chunk => { text += chunk.toString(); }); socket.once("close", () => done(text)); });
      const handled = new Promise<void>(done => server!.once("request", () => done()));
      socket.write(`POST / HTTP/1.1\r\nHost: x\r\nContent-Length: ${MAX_WEBHOOK_BODY}\r\n\r\n${"a".repeat(1024)}`);
      await handled;
      await vi.advanceTimersByTimeAsync(10_001);
      vi.useRealTimers();
      answer = await Promise.race([received, new Promise<string>(done => setTimeout(() => { socket.destroy(); done("still open"); }, 2_000))]);
    } finally { vi.useRealTimers(); }
    expect(answer).toMatch(/^HTTP\/1\.1 408 /);
  });

  it("answers 429 to an address that keeps sending, before reading the body", async () => {
    const { post } = await start("bitbucket-cloud", { owner: "workspace", repo: "repo" });
    const body = sample("cloud-pullrequest-created.json");
    for (let i = 0; i < 30; i++) expect((await post(body, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(body, "wrong secret value here") })).status).toBe(401);
    const limited = await post(body, { "X-Event-Key": "pullrequest:created", "X-Hub-Signature": sign(body) });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
  });
});
