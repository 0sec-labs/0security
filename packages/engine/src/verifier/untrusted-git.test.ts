import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { UNTRUSTED_GIT_BASE_CONFIG, UntrustedGitConfigError, untrustedGitConfig, type GitConfigReader } from "./untrusted-git.js";
import { isGitRepo, snapshotHead, snapshotWorktree } from "./snapshot.js";

const GIT_ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
const cleanups: string[] = [];
afterEach(() => { for (const dir of cleanups.splice(0)) rmSync(dir, { recursive: true, force: true }); });

/** A checkout whose own .git/config would run a command that leaves a marker file behind. */
function hostileCheckout(): { repo: string; markers: string; fired: () => string[]; touch: () => void } {
  const root = mkdtempSync(join(tmpdir(), "zero-untrusted-git-"));
  cleanups.push(root);
  const repo = join(root, "repo");
  const markers = join(root, "markers");
  mkdirSync(repo); mkdirSync(markers);
  const git = (...args: string[]) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", env: GIT_ENV, stdio: ["ignore", "pipe", "ignore"] });
  git("init", "-q");
  writeFileSync(join(repo, "a.txt"), "one\n");
  writeFileSync(join(repo, "b.md"), "two\n");
  git("add", "a.txt", "b.md");
  git("commit", "-qm", "fixture");
  const mark = (name: string) => `echo x > '${join(markers, name).replaceAll("\\", "/")}'`;
  git("config", "core.fsmonitor", `${mark("fsmonitor")}; false`);
  git("config", "filter.evil.clean", `${mark("clean")}; cat`);
  git("config", "filter.evil.smudge", `${mark("smudge")}; cat`);
  // A driver defined in a file the repository includes is just as local.
  const included = join(root, "included.cfg");
  writeFileSync(included, `[filter "side.car"]\n\tclean = ${mark("included")}; cat\n`);
  git("config", "include.path", included.replaceAll("\\", "/"));
  // .git/info/attributes is not covered by GIT_ATTR_SOURCE, so the drivers themselves have to be switched off.
  mkdirSync(join(repo, ".git", "info"), { recursive: true });
  writeFileSync(join(repo, ".git", "info", "attributes"), "*.txt filter=evil\n*.md filter=side.car\n");
  const touch = () => {
    writeFileSync(join(repo, "a.txt"), "one\nchanged\n");
    const later = new Date(Date.now() + 5_000);
    for (const file of ["a.txt", "b.md"]) utimesSync(join(repo, file), later, later); // racy stat: Git must re-hash
  };
  return { repo, markers, fired: () => readdirSync(markers).sort(), touch };
}

const runGit = (repo: string, args: string[]) => {
  try { execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", env: GIT_ENV, stdio: ["ignore", "pipe", "ignore"] }); } catch { /* exit code is not the point */ }
};

describe("untrusted git config", () => {
  it("the fixture really runs its commands under plain git (control)", () => {
    const fixture = hostileCheckout();
    fixture.touch();
    runGit(fixture.repo, ["status", "--porcelain"]);
    runGit(fixture.repo, ["diff", "--name-only", "HEAD", "--"]);
    expect(fixture.fired()).toEqual(expect.arrayContaining(["fsmonitor", "clean"]));
  });

  it("core.fsmonitor=false alone still lets a repository filter driver run", () => {
    const fixture = hostileCheckout();
    fixture.touch();
    runGit(fixture.repo, [...UNTRUSTED_GIT_BASE_CONFIG, "diff", "--name-only", "HEAD", "--"]);
    expect(fixture.fired()).toContain("clean");
  });

  it("status, diff and ls-files run nothing the repository configured", () => {
    const fixture = hostileCheckout();
    const config = untrustedGitConfig(fixture.repo);
    expect(config).toEqual(expect.arrayContaining(["filter.evil.clean=", "filter.evil.smudge=", "filter.evil.process=", "filter.side.car.clean="]));
    fixture.touch();
    runGit(fixture.repo, [...config, "status", "--porcelain", "--untracked-files=all"]);
    fixture.touch();
    runGit(fixture.repo, [...config, "diff", "--no-ext-diff", "--name-only", "HEAD", "--"]);
    runGit(fixture.repo, [...config, "ls-files", "-z", "--cached", "--others", "--exclude-standard"]);
    expect(fixture.fired()).toEqual([]);
  });

  it("the verifier snapshots copy the checkout without running its fsmonitor or filter drivers", async () => {
    const fixture = hostileCheckout();
    fixture.touch();
    expect(await isGitRepo(fixture.repo)).toBe(true);
    const worktree = await snapshotWorktree(fixture.repo);
    const head = await snapshotHead(fixture.repo);
    try {
      expect(readFileSync(join(worktree.dir, "a.txt"), "utf8")).toBe("one\nchanged\n");
      expect(readFileSync(join(head.dir, "a.txt"), "utf8").replaceAll("\r\n", "\n")).toBe("one\n");
      expect(existsSync(join(head.dir, "b.md"))).toBe(true);
    } finally { worktree.cleanup(); head.cleanup(); }
    expect(fixture.fired()).toEqual([]);
  });
});

describe("untrustedGitConfig parsing", () => {
  const reader = (listing: string | { status: number }, scoped: string | { status: number } = listing): GitConfigReader => (args) => {
    const answer = args.includes("--show-scope") ? scoped : listing;
    if (typeof answer === "string") return answer;
    throw Object.assign(new Error("git failed"), answer);
  };

  it("leaves drivers from the user's own config alone and overrides the repository's", () => {
    const listing = ["system", "filter.lfs.clean", "global", "filter.lfs.process", "local", "filter.x.clean", "worktree", "filter.y.z.process", "command", "filter.c.clean", ""].join("\0");
    const args = untrustedGitConfig("/repo", reader(listing));
    expect(args.slice(0, 2)).toEqual([...UNTRUSTED_GIT_BASE_CONFIG]);
    expect(args).toContain("filter.x.clean=");
    expect(args).toContain("filter.y.z.smudge=");
    expect(args).toContain("filter.y.z.required=false");
    expect(args.join(" ")).not.toContain("filter.lfs");
    expect(args.join(" ")).not.toContain("filter.c.");
  });

  it("returns only the base overrides when no filter is configured", () => {
    expect(untrustedGitConfig("/repo", reader({ status: 1 }))).toEqual([...UNTRUSTED_GIT_BASE_CONFIG]);
  });

  it("switches every driver off on a Git without --show-scope", () => {
    const args = untrustedGitConfig("/repo", reader(["filter.lfs.clean", "filter.x.process", ""].join("\0"), { status: 129 }));
    expect(args).toContain("filter.lfs.clean=");
    expect(args).toContain("filter.x.process=");
  });

  it("refuses a driver name that cannot be overridden on the command line", () => {
    expect(() => untrustedGitConfig("/repo", reader(["local", "filter.a=b.clean", ""].join("\0")))).toThrow(UntrustedGitConfigError);
    expect(() => untrustedGitConfig("/repo", reader(["local", "filter.a\nb.clean", ""].join("\0")))).toThrow(UntrustedGitConfigError);
  });

  it("does not hide a git failure as an empty listing", () => {
    expect(() => untrustedGitConfig("/repo", reader({ status: 128 }))).toThrow();
  });
});
