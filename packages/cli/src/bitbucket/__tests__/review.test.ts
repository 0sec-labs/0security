import { afterEach, describe, expect, it } from "vitest";
import { BitbucketClient, type Platform, type PullRequest } from "../client.js";
import { reviewPullRequest, type ReviewRunner, type ScanResult } from "../review.js";
import { cloudPr, dcPr, startFakeBitbucket, type FakeBitbucket } from "./fake-bitbucket.js";

const DIFF = [
  "diff --git a/app/db.py b/app/db.py", "index 111..222 100644", "--- a/app/db.py", "+++ b/app/db.py", "@@ -1,2 +1,4 @@",
  " import os", "+query = \"select \" + name", "+run(query)", " end",
  "diff --git a/old.py b/old.py", "deleted file mode 100644", "--- a/old.py", "+++ /dev/null", "@@ -1 +0,0 @@", "-gone", "",
].join("\n");

const finding = (over: Record<string, unknown> = {}) => ({
  category: "sql-injection", severity: "high", title: "SQL built from input", description: "The query joins user input.", status: "confirmed", confidence: 0.9,
  location: { path: "app/db.py", startLine: 2 }, evidence: { analysis: "CWE: CWE-89\nname reaches the query." }, impact: { rationale: "An attacker reads the table." },
  suggestedFix: { replacement: "run(query, [name])" }, ...over,
});
const scan = (findings: unknown[], exitCode = 0): ScanResult => ({ sha: "", json: JSON.stringify({ findings }), exitCode });
const runnerOf = (result: () => ScanResult): ReviewRunner & { calls: number } => { const runner = { calls: 0, async scan(pr: PullRequest) { runner.calls++; return { ...result(), sha: pr.headSha.padEnd(40, "0") }; } }; return runner; };
const memory = () => { const data = new Map<string, string>(); return { get: (key: string) => data.get(key), set: (key: string, sha: string) => { data.set(key, sha); } }; };

let fake: FakeBitbucket | undefined;
afterEach(async () => { await fake?.close(); fake = undefined; });

async function setup(platform: Platform) {
  fake = await startFakeBitbucket(platform);
  fake.diff = DIFF;
  const cloud = platform === "bitbucket-cloud";
  const raw = cloud ? cloudPr(7) : dcPr(7);
  fake.pullRequests.push(raw);
  const client = new BitbucketClient({ platform, token: fake.token, ...(cloud ? { cloudApiUrl: `${fake.url}/2.0` } : { baseUrl: fake.url }) });
  const pr = (await client.getPullRequest(cloud ? "ws" : "PRJ", "app", 7))!;
  return { fake, client, pr, cloud };
}

describe.each<Platform>(["bitbucket-cloud", "bitbucket-dc"])("review on %s", platform => {
  it("publishes the report, one summary and inline comments, and does not repeat itself", async () => {
    const { fake, client, pr, cloud } = await setup(platform);
    const state = memory();
    const runner = runnerOf(() => scan([
      finding(),
      finding({ title: "Far away", location: { path: "app/db.py", startLine: 900 }, evidence: { analysis: "CWE: CWE-20" } }),
      finding({ title: "Elsewhere", location: { path: "other/file.py", startLine: 3 } }),
    ]));
    const first = await reviewPullRequest(pr, { client, runner, state });
    const full = pr.headSha.padEnd(40, "0");
    expect(first).toMatchObject({ status: "reviewed", sha: full, total: 2, inlinePosted: 1, inlineRemoved: 0, partial: false, warnings: [] });

    // Code Insights at the full commit the scan used.
    expect(fake.report!.path).toContain(full);
    expect(fake.report!.annotations).toHaveLength(2);
    // One summary and one inline comment.
    expect(fake.comments).toHaveLength(2);
    const inline = fake.comments.find(c => c.inline)!;
    expect(inline.inline).toEqual(cloud ? { path: "app/db.py", to: 2 } : { diffType: "EFFECTIVE", fileType: "TO", path: "app/db.py", line: 2, lineType: "ADDED" });
    expect(inline.text).toContain("SQL built from input");
    expect(inline.text).toContain("Fix: run(query, name)");
    const summary = fake.comments.find(c => !c.inline)!;
    expect(summary.text).toContain("Found 2 issues");
    expect(summary.text).toContain("reviewed 1 changed file");
    // The token is never in a comment.
    expect(JSON.stringify(fake.comments)).not.toContain(fake.token);

    // The same head commit again: nothing is sent.
    const before = fake.requests.length;
    expect(await reviewPullRequest(pr, { client, runner, state })).toEqual({ status: "skipped", reason: "unchanged" });
    expect(fake.requests.length).toBe(before);
    expect(runner.calls).toBe(1);

    // State lost: the comments are found again, so nothing is duplicated.
    const again = await reviewPullRequest(pr, { client, runner, state: memory() });
    expect(again).toMatchObject({ status: "reviewed", inlinePosted: 0, inlineRemoved: 0 });
    expect(fake.comments).toHaveLength(2);

    // A new commit that fixes the finding removes the inline comment and updates the summary in place.
    const fixed = await reviewPullRequest({ ...pr, headSha: "d".repeat(40) }, { client, runner: runnerOf(() => scan([])), state });
    expect(fixed).toMatchObject({ status: "reviewed", total: 0, inlineRemoved: 1 });
    expect(fake.comments).toHaveLength(1);
    expect(fake.comments[0]!.text).toContain("No findings");
  });

  it("reads comments and pull requests across pages", async () => {
    const { fake, client, pr } = await setup(platform);
    fake.smallPages = true;
    fake.pullRequests.push(platform === "bitbucket-cloud" ? cloudPr(8) : dcPr(8), platform === "bitbucket-cloud" ? cloudPr(9) : dcPr(9));
    expect((await client.listOpenPullRequests(platform === "bitbucket-cloud" ? "ws" : "PRJ", "app")).map(item => item.id)).toEqual([7, 8, 9]);
    const state = memory();
    const runner = runnerOf(() => scan([finding()]));
    await reviewPullRequest(pr, { client, runner, state });
    await reviewPullRequest(pr, { client, runner, state: memory() });
    expect(fake.comments).toHaveLength(2);
  });

  it("leaves scan text out of comments as links, markup and mentions", async () => {
    const { fake, client, pr } = await setup(platform);
    const hostile = finding({ title: "Hi @victim <img src=x onerror=1> see https://evil.example/x `rm`", impact: { rationale: "Open https://evil.example/y and ping @everyone" } });
    await reviewPullRequest(pr, { client, runner: runnerOf(() => scan([hostile])), state: memory() });
    const all = fake.comments.map(c => c.text).join("\n");
    expect(all).not.toMatch(/@victim|@everyone/);
    expect(all).not.toContain("https://");
    expect(all).not.toContain("<img");
    expect(all).not.toContain("`rm`");
  });

  it("skips closed, draft and fork pull requests and says when a pull request is too large", async () => {
    const { fake, client, pr } = await setup(platform);
    const runner = runnerOf(() => scan([]));
    const deps = { client, runner, state: memory() };
    const setupRequests = fake.requests.length;
    expect(await reviewPullRequest({ ...pr, open: false }, deps)).toEqual({ status: "skipped", reason: "closed" });
    expect(await reviewPullRequest({ ...pr, draft: true }, deps)).toEqual({ status: "skipped", reason: "draft" });
    expect(await reviewPullRequest({ ...pr, fork: true }, deps)).toEqual({ status: "skipped", reason: "fork" });
    expect(runner.calls).toBe(0);
    expect(fake.requests).toHaveLength(setupRequests);
    expect(await reviewPullRequest(pr, deps, { maxFiles: 0 })).toEqual({ status: "too-large", files: 1 });
    expect(runner.calls).toBe(0);
    expect(fake.comments[0]!.text).toContain("did not review");
  });

  it("keeps going when Code Insights fails and reports it", async () => {
    const { fake, client, pr } = await setup(platform);
    const original = client.publishInsights.bind(client);
    client.publishInsights = async () => { throw new Error("Bitbucket answered 403 to PUT"); };
    const outcome = await reviewPullRequest(pr, { client, runner: runnerOf(() => scan([finding()])), state: memory() });
    expect(outcome).toMatchObject({ status: "reviewed", warnings: [expect.stringContaining("403")] });
    expect(fake.comments).toHaveLength(2);
    client.publishInsights = original;
  });

  it("does not remember a pull request whose scan failed", async () => {
    const { client, pr } = await setup(platform);
    const state = memory();
    await expect(reviewPullRequest(pr, { client, runner: { async scan(): Promise<ScanResult> { throw new Error("The scan failed (exit 2)."); } }, state })).rejects.toThrow("exit 2");
    expect(state.get(`${platform}:${pr.owner}/${pr.repo}#7`)).toBeUndefined();
  });

  it("marks a scan that stopped early as partial", async () => {
    const { fake, client, pr } = await setup(platform);
    const outcome = await reviewPullRequest(pr, { client, runner: runnerOf(() => scan([], 3)), state: memory() });
    expect(outcome).toMatchObject({ status: "reviewed", partial: true });
    expect(fake.comments[0]!.text).toContain("partial");
  });

  it("can publish the report without comments", async () => {
    const { fake, client, pr } = await setup(platform);
    await reviewPullRequest(pr, { client, runner: runnerOf(() => scan([finding()])), state: memory() }, { comments: false });
    expect(fake.report!.annotations).toHaveLength(1);
    expect(fake.comments).toHaveLength(0);
  });
});

describe("client safety", () => {
  it("sends the token as a bearer header, only to the server's origin, and never in an error", async () => {
    fake = await startFakeBitbucket("bitbucket-dc");
    const wrong = new BitbucketClient({ platform: "bitbucket-dc", token: "wrong-token-value", baseUrl: fake.url });
    const error = await wrong.listOpenPullRequests("PRJ", "app").catch(e => e as Error);
    expect((error as Error).message).toContain("401");
    expect((error as Error).message).not.toContain("wrong-token-value");

    const redirecting = new BitbucketClient({
      platform: "bitbucket-dc", token: "t0ken-value-1234", baseUrl: "https://bitbucket.example.com",
      http: async () => ({ ok: false, status: 302, headers: { get: () => "https://elsewhere.example.net/steal" }, text: async () => "" }),
    });
    await expect(redirecting.diff({ owner: "PRJ", repo: "app", id: 1 })).rejects.toThrow("different host");
  });

  it("refuses plain http to another host and credentials in the URL", () => {
    expect(() => new BitbucketClient({ platform: "bitbucket-dc", token: "t", baseUrl: "http://bitbucket.example.com" })).toThrow("plain HTTP");
    expect(() => new BitbucketClient({ platform: "bitbucket-dc", token: "t", baseUrl: "http://bitbucket.example.com", allowInsecureHttp: true })).not.toThrow();
    expect(() => new BitbucketClient({ platform: "bitbucket-dc", token: "t", baseUrl: "https://user:pass@bitbucket.example.com" })).toThrow("credentials");
    expect(() => new BitbucketClient({ platform: "bitbucket-dc", token: "t" })).toThrow("base URL");
  });

  it("refuses to send anything in enterprise mode", async () => {
    fake = await startFakeBitbucket("bitbucket-cloud");
    const previous = process.env["ZERO_ENTERPRISE"];
    process.env["ZERO_ENTERPRISE"] = "1";
    try {
      const client = new BitbucketClient({ platform: "bitbucket-cloud", token: fake.token, cloudApiUrl: `${fake.url}/2.0` });
      await expect(client.listOpenPullRequests("ws", "app")).rejects.toThrow();
      expect(fake.requests).toHaveLength(0);
    } finally { if (previous === undefined) delete process.env["ZERO_ENTERPRISE"]; else process.env["ZERO_ENTERPRISE"] = previous; }
  });
});
