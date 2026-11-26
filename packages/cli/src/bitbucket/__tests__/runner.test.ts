import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PullRequest } from "../client.js";
import { defaultExec, fileState, gitScanRunner, headRefspec } from "../runner.js";

const run = (cwd: string, ...args: string[]) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], { cwd, encoding: "utf8", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } }).trim();

let root: string;
let origin: string;
let clone: string;
let fakeScan: string;
let featureSha: string;
const saved = { token: process.env["BITBUCKET_TOKEN"], secret: process.env["BITBUCKET_WEBHOOK_SECRET"] };

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "0-runner-test-"));
  origin = join(root, "origin");
  clone = join(root, "clone");
  run(root, "init", "-q", "-b", "main", origin);
  writeFileSync(join(origin, "base.txt"), "base\n");
  run(origin, "add", ".");
  run(origin, "commit", "-q", "-m", "base");
  run(origin, "checkout", "-q", "-b", "feature");
  writeFileSync(join(origin, "new.txt"), "new\n");
  run(origin, "add", ".");
  run(origin, "commit", "-q", "-m", "feature");
  featureSha = run(origin, "rev-parse", "HEAD");
  run(origin, "checkout", "-q", "main");
  run(root, "clone", "-q", origin, clone);
  // A stand-in for `0security scan`: records what the scan could see and writes a report.
  fakeScan = join(root, "fake-scan.mjs");
  writeFileSync(fakeScan, [
    'import { existsSync, writeFileSync } from "node:fs";',
    "const args = process.argv.slice(2);",
    'const tree = args[args.indexOf("scan") + 1];',
    'const out = args[args.indexOf("-o") + 1];',
    'if (process.env.FAKE_SCAN_EXIT) process.exit(Number(process.env.FAKE_SCAN_EXIT));',
    "const seen = { args, hasNew: existsSync(`${tree}/new.txt`), token: process.env.BITBUCKET_TOKEN ?? null, secret: process.env.BITBUCKET_WEBHOOK_SECRET ?? null };",
    "writeFileSync(out, JSON.stringify({ findings: [], seen }));",
    "if (process.env.FAKE_SCAN_PARTIAL) process.exit(3);",
  ].join("\n"));
  process.env["BITBUCKET_TOKEN"] = "token-value-for-test-1234";
  process.env["BITBUCKET_WEBHOOK_SECRET"] = "secret-value-for-test-1234";
});
afterEach(() => {
  for (const [name, value] of [["BITBUCKET_TOKEN", saved.token], ["BITBUCKET_WEBHOOK_SECRET", saved.secret]] as const) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
});

const pr = (over: Partial<PullRequest> = {}): PullRequest => ({ platform: "bitbucket-cloud", owner: "ws", repo: "app", id: 5, title: "t", draft: false, fork: false, open: true, headSha: featureSha.slice(0, 12), headBranch: "feature", baseBranch: "main", ...over });

describe("git scan runner", () => {
  it("scans the pull request's commit in a temporary worktree and cleans up", async () => {
    const runner = gitScanRunner({ checkout: clone, scanCommand: [process.execPath, fakeScan], budget: "1.5", providerId: "azure", model: "deployment", reasoning: "high" });
    const result = await runner.scan(pr());
    expect(result).toMatchObject({ sha: featureSha, exitCode: 0 });
    const report = JSON.parse(result.json) as { seen: { args: string[]; hasNew: boolean; token: string | null; secret: string | null } };
    expect(report.seen.hasNew).toBe(true);
    expect(report.seen.args).toEqual(expect.arrayContaining(["--diff", "origin/main", "--format", "json", "--budget", "1.5", "--provider", "azure", "--model", "deployment", "--reasoning", "high"]));
    // The scan never sees the Bitbucket token or the webhook secret.
    expect(report.seen.token).toBeNull();
    expect(report.seen.secret).toBeNull();
    // The operator's clone is back to one worktree and the pull request ref is gone.
    expect(run(clone, "worktree", "list").split("\n")).toHaveLength(1);
    expect(run(clone, "for-each-ref", "refs/0")).toBe("");
    expect(existsSync(join(clone, "new.txt"))).toBe(false);
    expect(run(clone, "rev-parse", "--abbrev-ref", "HEAD")).toBe("main");
  });

  it("runs nothing the clone's own git config names (fsmonitor, hooks, filter drivers, ssh command)", async () => {
    const markers = join(root, "markers");
    const hooks = join(root, "hooks");
    mkdirSync(markers); mkdirSync(hooks);
    const mark = (name: string) => `echo x > '${join(markers, name).replaceAll("\\", "/")}'`;
    for (const hook of ["post-checkout", "reference-transaction"]) writeFileSync(join(hooks, hook), `#!/bin/sh\n${mark(hook)}\nexit 0\n`, { mode: 0o755 });
    const hostile = (dir: string) => {
      run(dir, "config", "core.hooksPath", hooks);
      run(dir, "config", "core.fsmonitor", `${mark("fsmonitor")}; false`);
      run(dir, "config", "core.sshCommand", `${mark("sshCommand")}; false`);
      run(dir, "config", "filter.evil.smudge", `${mark("smudge")}; cat`);
      run(dir, "config", "filter.evil.clean", `${mark("clean")}; cat`);
      mkdirSync(join(dir, ".git", "info"), { recursive: true });
      writeFileSync(join(dir, ".git", "info", "attributes"), "*.txt filter=evil\n");
    };
    // Control: the same config does run under plain git.
    const control = join(root, "control");
    run(root, "clone", "-q", origin, control);
    hostile(control);
    run(control, "fetch", "-q", "origin", "feature");
    run(control, "worktree", "add", "-q", "--detach", join(root, "control-tree"), "origin/feature");
    expect(readdirSync(markers).length).toBeGreaterThan(0);
    for (const name of readdirSync(markers)) rmSync(join(markers, name));

    hostile(clone);
    const result = await gitScanRunner({ checkout: clone, scanCommand: [process.execPath, fakeScan] }).scan(pr());
    expect(result).toMatchObject({ sha: featureSha, exitCode: 0 });
    expect(readdirSync(markers)).toEqual([]);
  });

  it("fetches real approved HTTP git under restricted egress, rejecting repository mismatches and rewrites", async () => {
    run(origin, "update-ref", "refs/pull-requests/6/from", featureSha);
    run(origin, "update-server-info");
    const requests: string[] = [];
    const server = createServer((req, res) => {
      requests.push(req.url!);
      expect(req.headers.authorization).toBeUndefined();
      const path = new URL(req.url!, "http://localhost").pathname;
      const prefix = "/bitbucket/scm/ws/app.git/";
      if (!path.startsWith(prefix) || path.includes("..")) { res.writeHead(404); res.end(); return; }
      try { res.end(readFileSync(join(origin, ".git", path.slice(prefix.length)))); }
      catch { res.writeHead(404); res.end(); }
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as { port: number };
    const base = `http://127.0.0.1:${port}/bitbucket`;
    const httpClone = join(root, "http-clone");
    run(root, "init", "-q", "-b", "main", httpClone);
    run(httpClone, "remote", "add", "origin", `${base}/scm/ws/app.git`);
    vi.stubEnv("ZERO_ENTERPRISE", "1"); vi.stubEnv("ZERO_BITBUCKET_URL", base);
    try {
      const runner = gitScanRunner({ checkout: httpClone, scanCommand: [process.execPath, fakeScan] });
      expect((await runner.scan(pr({ platform: "bitbucket-dc", id: 6, headSha: featureSha }))).sha).toBe(featureSha);
      expect(requests.some(path => path.includes("info/refs"))).toBe(true);
      expect(requests.some(path => path.includes("/objects/"))).toBe(true);
      const before = requests.length;
      await expect(runner.scan(pr({ platform: "bitbucket-dc", repo: "other", headSha: featureSha }))).rejects.toThrow("does not match");
      run(httpClone, "config", "url.https://evil.invalid/.insteadOf", base);
      await expect(runner.scan(pr({ platform: "bitbucket-dc", headSha: featureSha }))).rejects.toThrow("URL rewrites");
      expect(requests.length).toBe(before);
    } finally {
      vi.unstubAllEnvs();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it("also hides the variable a trigger names for its token", async () => {
    process.env["BITBUCKET_TEAM_TOKEN"] = "team-token-value-1234";
    try {
      const seenEnv = vi.fn();
      const result = await gitScanRunner({ checkout: clone, scanCommand: [process.execPath, fakeScan], secretVariables: ["BITBUCKET_TEAM_TOKEN"], exec: async (file, args, options) => { seenEnv(options.env["BITBUCKET_TEAM_TOKEN"]); return defaultExec(file, args, options); } }).scan(pr());
      expect(result.exitCode).toBe(0);
      expect(seenEnv).toHaveBeenCalled();
      expect(seenEnv.mock.calls.every(call => call[0] === undefined)).toBe(true);
    } finally { delete process.env["BITBUCKET_TEAM_TOKEN"]; }
  });

  it("fetches the Data Center pull request ref", async () => {
    run(origin, "update-ref", "refs/pull-requests/6/from", featureSha);
    const runner = gitScanRunner({ checkout: clone, scanCommand: [process.execPath, fakeScan] });
    const result = await runner.scan(pr({ platform: "bitbucket-dc", id: 6, headBranch: "any-name", headSha: featureSha }));
    expect(result.sha).toBe(featureSha);
    expect(headRefspec(pr({ platform: "bitbucket-dc", id: 6 }))).toBe("+refs/pull-requests/6/from:refs/0/pr/6");
  });

  it("refuses branch names git could read as an option, and cleans up when the scan fails", async () => {
    const runner = gitScanRunner({ checkout: clone, scanCommand: [process.execPath, fakeScan] });
    await expect(runner.scan(pr({ headBranch: "--upload-pack=touch-x" }))).rejects.toThrow("branch name");
    process.env["FAKE_SCAN_EXIT"] = "2";
    try { await expect(runner.scan(pr())).rejects.toThrow("exit 2"); } finally { delete process.env["FAKE_SCAN_EXIT"]; }
    expect(run(clone, "worktree", "list").split("\n")).toHaveLength(1);
    expect(run(clone, "for-each-ref", "refs/0")).toBe("");
  });

  it("passes a partial scan (exit 3) through, and treats exit 3 with no report as an error", async () => {
    const runner = gitScanRunner({ checkout: clone, scanCommand: [process.execPath, fakeScan] });
    process.env["FAKE_SCAN_PARTIAL"] = "1";
    try { expect(await runner.scan(pr())).toMatchObject({ exitCode: 3 }); } finally { delete process.env["FAKE_SCAN_PARTIAL"]; }
    process.env["FAKE_SCAN_EXIT"] = "3";
    try { await expect(runner.scan(pr())).rejects.toThrow("no report"); } finally { delete process.env["FAKE_SCAN_EXIT"]; }
  });
});

describe("review state file", () => {
  it("remembers commits across restarts and ignores a damaged file", () => {
    const files = new Map<string, string>();
    const io = { read: (path: string) => files.get(path), write: (path: string, text: string) => { files.set(path, text); } };
    const state = fileState("s.json", io);
    state.set("k", "abc");
    expect(fileState("s.json", io).get("k")).toBe("abc");
    files.set("s.json", "{not json");
    expect(fileState("s.json", io).get("k")).toBeUndefined();
    files.set("s.json", JSON.stringify({ a: 1, b: "x" }));
    expect(fileState("s.json", io).get("b")).toBe("x");
    expect(fileState("s.json", io).get("a")).toBeUndefined();
    expect(readFileSync(fakeScan, "utf8")).toContain("writeFileSync");
  });
});
