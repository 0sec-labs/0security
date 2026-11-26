import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readFixDiff } from "../../web/finding-fix.js";
import { defaultFixDeps } from "../fix.js";
import { defaultThreatModelDeps } from "../threat-model.js";

const ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
const cleanups: string[] = [];
afterEach(() => { for (const dir of cleanups.splice(0)) rmSync(dir, { recursive: true, force: true }); });

/** A checkout whose own .git/config would run a command, leaving a marker file behind, for each of these features. */
function hostile() {
  const root = mkdtempSync(join(tmpdir(), "zero-callers-git-"));
  cleanups.push(root);
  const repo = join(root, "repo");
  const markers = join(root, "markers");
  const hooks = join(root, "hooks");
  mkdirSync(repo); mkdirSync(markers); mkdirSync(hooks);
  const git = (...args: string[]) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", env: ENV, stdio: ["ignore", "pipe", "ignore"] });
  const mark = (name: string) => `echo x > '${join(markers, name).replaceAll("\\", "/")}'`;
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "a.txt"), "one\n");
  git("add", "a.txt");
  git("commit", "-qm", "fixture");
  git("branch", "fix/one");
  for (const hook of ["pre-commit", "post-commit", "post-checkout"]) writeFileSync(join(hooks, hook), `#!/bin/sh\n${mark(hook)}\nexit 0\n`, { mode: 0o755 });
  git("config", "core.hooksPath", hooks.replaceAll("\\", "/"));
  git("config", "core.fsmonitor", `${mark("fsmonitor")}; false`);
  git("config", "core.sshCommand", `${mark("sshCommand")}; false`);
  git("config", "filter.evil.clean", `${mark("clean")}; cat`);
  git("config", "filter.evil.smudge", `${mark("smudge")}; cat`);
  mkdirSync(join(repo, ".git", "info"), { recursive: true });
  writeFileSync(join(repo, ".git", "info", "attributes"), "*.txt filter=evil\n");
  const touch = (text: string) => {
    writeFileSync(join(repo, "a.txt"), text);
    const later = new Date(Date.now() + 5_000);
    utimesSync(join(repo, "a.txt"), later, later); // racy stat: git must re-hash the file
  };
  return { root, repo, git, touch, fired: () => readdirSync(markers).sort() };
}

const plain = (repo: string, args: string[]) => { try { execFileSync("git", ["-C", repo, ...args], { env: ENV, stdio: "ignore" }); } catch { /* not the point */ } };

describe("callers that run git in a repository they do not trust", () => {
  it("the fixture fires every marker under plain git (control)", () => {
    const f = hostile();
    f.touch("two\n");
    plain(f.repo, ["status", "--porcelain"]);
    plain(f.repo, ["add", "-A"]);
    plain(f.repo, ["commit", "-qm", "x"]);
    plain(f.repo, ["worktree", "add", "-q", "--detach", join(f.root, "wt"), "HEAD"]);
    expect(f.fired()).toEqual(expect.arrayContaining(["fsmonitor", "clean", "pre-commit", "post-commit", "post-checkout"]));
  });

  for (const [name, deps] of [["fix", defaultFixDeps], ["threat-model", defaultThreatModelDeps]] as const) {
    it(`${name} status, add, commit and worktree add run nothing the repository configured`, async () => {
      const f = hostile();
      f.touch("two\n");
      await deps.git(f.repo, ["status", "--porcelain", "--untracked-files=all"]);
      await deps.git(f.repo, ["add", "-A"]);
      await deps.git(f.repo, ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", "x"]);
      const tree = join(f.root, "wt");
      await deps.git(f.repo, ["worktree", "add", "--quiet", "-B", "fix/two", tree, "HEAD"]);
      expect(await deps.git(tree, ["rev-parse", "--abbrev-ref", "HEAD"])).toBe("fix/two\n");
      expect(f.fired()).toEqual([]);
    });
  }

  it("fix push and fetch use plain ssh, not the repository's ssh command", async () => {
    const f = hostile();
    f.git("remote", "add", "origin", "ssh://git@host.invalid/owner/repo.git");
    await defaultFixDeps.git(f.repo, ["fetch", "--quiet", "origin"]).catch(() => undefined);
    await defaultFixDeps.git(f.repo, ["push", "--quiet", "origin", "main"]).catch(() => undefined);
    expect(f.fired()).toEqual([]);
  }, 60_000);

  it("reading the fix diff for the console runs nothing the repository configured", async () => {
    const f = hostile();
    f.touch("two\n");
    plain(f.repo, ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.evil.clean=", "-c", "filter.evil.smudge=", "checkout", "-q", "fix/one"]);
    plain(f.repo, ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.evil.clean=", "-c", "filter.evil.smudge=", "commit", "--allow-empty", "-qm", "fix"]);
    const result = await readFixDiff(f.repo, "fix/one");
    expect(result).not.toBeNull();
    expect(f.fired()).toEqual([]);
  });
});
