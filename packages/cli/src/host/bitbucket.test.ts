import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BitbucketHost } from "./bitbucket.js";
import { selectFixHost } from "./fix-host.js";

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
const git = (cwd: string, args: string[]) => execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
function originRunner(origin: string, push = origin) { return async (args: string[]) => args[0] === "config" ? "" : args.includes("--push") ? push : origin; }

describe("origin-aware fix host selection", () => {
  it.each(["https://bitbucket.org/team/repo.git", "git@bitbucket.org:team/repo.git", "ssh://git@bitbucket.org/team/repo.git"])("selects Cloud from %s", async origin => {
    const host = await selectFixHost({ git: originRunner(origin), run: async () => "", env: { BITBUCKET_TOKEN: "secret" } });
    expect(host.name).toBe("bitbucket-cloud"); expect(await host.currentRepo()).toBe("team/repo");
  });
  it.each(["https://code.example/bb/scm/PRJ/repo.git", "ssh://git@code.example:7999/PRJ/repo.git"])("selects DC with context path from %s", async origin => {
    const host = await selectFixHost({ git: originRunner(origin), run: async () => "", env: { BITBUCKET_TOKEN: "secret", BITBUCKET_URL: "https://code.example/bb" } });
    expect(host.name).toBe("bitbucket-dc"); expect(await host.currentRepo()).toBe("PRJ/repo");
  });
  it("refuses mismatched/multiple push destinations and credentials before writes", async () => {
    for (const push of ["git@evil.example:PRJ/repo.git", "https://bitbucket.org/a/b.git\nhttps://evil.example/a/b.git"]) await expect(selectFixHost({ git: originRunner("https://bitbucket.org/a/b.git", push), run: async () => "" })).rejects.toThrow("push URL");
    await expect(selectFixHost({ git: originRunner("https://user:token@bitbucket.org/a/b.git"), run: async () => "" })).rejects.toThrow("credentials");
    await expect(selectFixHost({ git: originRunner("https://bitbucket.org/a/b.git"), run: async () => "", env: {} })).rejects.toThrow("BITBUCKET_TOKEN");
    await expect(selectFixHost({ git: originRunner("https://code.example/scm/P/r.git"), run: async () => "", env: { BITBUCKET_TOKEN: "secret", BITBUCKET_URL: "https://evil.example" } })).rejects.toThrow("match origin");
  });
  it("keeps GitHub and rejects unsupported hosts", async () => {
    expect((await selectFixHost({ git: originRunner("git@github.com:a/b.git"), run: async () => "" })).name).toBe("github");
    await expect(selectFixHost({ host: "gitlab", git: originRunner("https://gitlab.com/a/b.git"), run: async () => "" })).rejects.toThrow("Unsupported");
  });
});

async function server(platform: "bitbucket-cloud" | "bitbucket-dc") {
  const requests: Array<{ method: string; url: string; body: Record<string, any> }> = [];
  let pr: Record<string, any> | undefined;
  let state = "SUCCESSFUL";
  const repo = { slug: "repo", project: { key: "PRJ" } };
  const srv = createServer(async (req, res) => {
    let body = ""; for await (const chunk of req) body += String(chunk);
    const parsed = body ? JSON.parse(body) : {};
    requests.push({ method: req.method!, url: req.url!, body: parsed });
    if (req.headers.authorization !== "Bearer secret-token") { res.writeHead(401); res.end(); return; }
    res.setHeader("content-type", "application/json");
    if (req.url!.includes("/statuses") || req.url!.includes("/builds")) { res.end(JSON.stringify({ values: [{ state }], isLastPage: true })); return; }
    if (req.url!.includes("/commits")) { res.end(JSON.stringify({ values: [{ hash: "a" }, { hash: "b" }], isLastPage: true })); return; }
    if (req.method === "POST") {
      if (pr) { res.writeHead(409); res.end(); return; }
      pr = { ...parsed, id: 7, state: "OPEN", version: 0, ...(platform === "bitbucket-cloud" ? { source: { ...parsed.source, repository: { full_name: "PRJ/repo" } } } : { fromRef: { ...parsed.fromRef, repository: repo, latestCommit: "a".repeat(40) } }) };
      res.writeHead(201); res.end(JSON.stringify(pr)); return;
    }
    if (req.method === "PUT") {
      if (platform === "bitbucket-dc" && parsed.version !== pr?.version) { res.writeHead(409); res.end(); return; }
      pr = { ...pr, ...parsed, version: (pr?.version ?? 0) + 1 }; res.end(JSON.stringify(pr)); return;
    }
    if (/\/(pullrequests|pull-requests)\?/.test(req.url!)) res.end(JSON.stringify({ values: pr ? [pr] : [], isLastPage: true }));
    else res.end(JSON.stringify(pr));
  });
  await new Promise<void>(resolve => srv.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => new Promise<void>((resolve, reject) => srv.close(error => error ? reject(error) : resolve())));
  const address = srv.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${address.port}/bb`;
  // Cloud transport is redirected to the local server only by this injected test fetch;
  // production Cloud always calls api.bitbucket.org and never follows redirects.
  const localFetch: typeof fetch = (input, init) => fetch(platform === "bitbucket-cloud" ? `${baseUrl}${new URL(String(input)).pathname}${new URL(String(input)).search}` : input, init);
  return { baseUrl, requests, localFetch, setState: (value: string) => { state = value; } };
}

describe.each(["bitbucket-cloud", "bitbucket-dc"] as const)("%s fix PR integration", platform => {
  it("pushes an actual fix branch, creates one draft, updates it, reads lifecycle and real HTTP CI responses", async () => {
    const temp = mkdtempSync(join(tmpdir(), "0-bitbucket-host-")); cleanups.push(() => rmSync(temp, { recursive: true, force: true }));
    const remote = join(temp, "remote.git"), clone = join(temp, "clone");
    execFileSync("git", ["init", "--bare", remote], { stdio: "ignore" });
    execFileSync("git", ["clone", remote, clone], { stdio: "ignore" });
    git(clone, ["config", "user.name", "Test"]); git(clone, ["config", "user.email", "test@example.invalid"]);
    git(clone, ["checkout", "-b", "main"]); writeFileSync(join(clone, "code.txt"), "base"); git(clone, ["add", "."]); git(clone, ["commit", "-m", "base"]); git(clone, ["push", "origin", "main"]);
    git(clone, ["checkout", "-b", "0/fix-test"]); writeFileSync(join(clone, "code.txt"), "fixed"); git(clone, ["commit", "-am", "fix"]);
    const api = await server(platform);
    const host = new BitbucketHost({ platform, owner: "PRJ", repo: "repo", token: "secret-token", baseUrl: api.baseUrl, fetch: api.localFetch, git: async args => git(clone, args) });
    await host.pushBranch("0/fix-test");
    expect(git(clone, ["rev-parse", "HEAD"]).trim()).toBe(git(remote, ["rev-parse", "refs/heads/0/fix-test"]).trim());
    expect(git(remote, ["rev-parse", "main"]).trim()).not.toBe(git(clone, ["rev-parse", "HEAD"]).trim());
    const body = join(temp, "body.md"); writeFileSync(body, "Fix details and failed test evidence");
    expect(await host.findOpenPullRequest("0/fix-test")).toBeUndefined();
    const url = await host.createPullRequest({ base: "main", head: "0/fix-test", title: "Fix SQL injection", bodyFile: body, draft: true });
    expect(await host.findOpenPullRequest("0/fix-test")).toEqual({ number: 7, url, isDraft: true });
    writeFileSync(body, "Updated verified fix"); await host.updatePullRequestBody(7, body); await host.setPullRequestReady(7, true);
    expect(await host.pullRequestState(url)).toEqual({ state: "open", draft: false, commits: 2 });
    expect(await host.pullRequestChecks(url)).toMatchObject({ status: "passing" }); api.setState("FAILED"); expect(await host.pullRequestChecks(url)).toMatchObject({ status: "failing" }); api.setState("INPROGRESS"); expect(await host.pullRequestChecks(url)).toMatchObject({ status: "pending" });
    expect(api.requests.filter(r => r.method === "POST")).toHaveLength(1);
    const create = api.requests.find(r => r.method === "POST")!.body;
    expect(create.draft).toBe(true); expect(create.description).toContain("failed test");
    expect(platform === "bitbucket-cloud" ? create.destination.branch.name : create.toRef.id).toBe(platform === "bitbucket-cloud" ? "main" : "refs/heads/main");
  });
});

it("refuses redirects and off-repository pagination before exposing credentials", async () => {
  let calls = 0;
  const host = new BitbucketHost({ platform: "bitbucket-dc", owner: "P", repo: "r", token: "secret-token", baseUrl: "https://code.example", git: async () => "", fetch: async () => { calls++; return new Response(null, { status: 302, headers: { location: "https://evil.example" } }); } });
  await expect(host.findOpenPullRequest("0/fix-a")).rejects.toThrow("302"); expect(calls).toBe(1);
  const cloud = new BitbucketHost({ platform: "bitbucket-cloud", owner: "P", repo: "r", token: "secret-token", git: async () => "", fetch: async () => { calls++; return Response.json({ values: [], next: "https://evil.example/steal" }); } });
  await expect(cloud.findOpenPullRequest("0/fix-a")).rejects.toThrow("outside this repository"); expect(calls).toBe(2);
  await expect(host.pullRequestState("https://evil.example/pull-requests/7")).rejects.toThrow("pull request URL"); expect(calls).toBe(2);
});

it("binds GitHub PR state and checks to the selected origin repository", async () => {
  const calls: string[][] = [];
  const host = await selectFixHost({ git: originRunner("git@github.com:team/repo.git"), run: async args => { calls.push(args); return '{"state":"OPEN","commits":1,"statusCheckRollup":[]}'; } });
  await expect(host.pullRequestState("https://github.com/other/private/pull/7")).rejects.toThrow("this GitHub repository");
  await expect(host.pullRequestChecks!("https://github.com/other/private/pull/7")).rejects.toThrow("this GitHub repository");
  expect(calls).toHaveLength(0);
  await host.pullRequestState("https://github.com/team/repo/pull/7");
  expect(calls[0]!.slice(-2)).toEqual(["--repo", "team/repo"]);
});

it("rechecks origin after the agent has edited the worktree", async () => {
  let origin = "https://bitbucket.org/team/repo.git";
  const pushes: string[][] = [];
  const host = await selectFixHost({ git: async args => { if (args[0] === "config") return ""; if (args[0] === "remote") return origin; pushes.push(args); return ""; }, run: async () => "", env: { BITBUCKET_TOKEN: "secret" } });
  origin = "https://evil.example/team/repo.git";
  await expect(host.pushBranch("0/fix-test")).rejects.toThrow("Origin changed");
  expect(pushes).toEqual([]);
});


it("restricted fixing requires the actual HTTPS git destination inside the explicit allowlist", async () => {
  const env = { ZERO_ENTERPRISE: "1", ZERO_BITBUCKET_URL: "https://code.example/bb", BITBUCKET_URL: "https://code.example/bb", BITBUCKET_TOKEN: "secret" };
  for (const origin of ["ssh://git@code.example:7999/PRJ/repo.git", "https://code.example:8443/bb/scm/PRJ/repo.git"]) await expect(selectFixHost({ git: originRunner(origin), run: async () => "", env })).rejects.toThrow();
  await expect(selectFixHost({ git: originRunner("https://code.example/bb/scm/PRJ/repo.git"), run: async () => "", env: { ...env, ZERO_BITBUCKET_URL: "https://code.example/other" } })).rejects.toThrow();
  expect((await selectFixHost({ git: originRunner("https://code.example/bb/scm/PRJ/repo.git"), run: async () => "", env })).name).toBe("bitbucket-dc");
});

it("refuses initial and mid-run git URL rewrite rules before publishing", async () => {
  for (const key of ["url.https://evil.example/.insteadof", "url.ssh://git@code.example:7999/.pushinsteadof"]) {
    const runner = async (args: string[]) => args[0] === "config" ? key : "https://bitbucket.org/team/repo.git";
    await expect(selectFixHost({ git: runner, run: async () => "", env: { BITBUCKET_TOKEN: "secret" } })).rejects.toThrow("rewriting");
  }
  let rewriting = false;
  const host = await selectFixHost({ git: async args => args[0] === "config" ? rewriting ? "url.https://evil.example/.pushinsteadof" : "" : "https://bitbucket.org/team/repo.git", run: async () => "", env: { BITBUCKET_TOKEN: "secret" } });
  rewriting = true;
  await expect(host.pushBranch("0/fix-test")).rejects.toThrow("rewriting");
});
