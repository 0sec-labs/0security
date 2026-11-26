import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { BurndownState, StateStore } from "../commands/burndown.js";
import { findingFixInfo, locationOf, readFixDiff, MAX_DIFF_BYTES } from "./finding-fix.js";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-finding-fix-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const run = (...args: string[]) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
function repoWithFix(content = "fixed\n"): void {
  run("init", "-q", "-b", "main");
  writeFileSync(join(dir, "a.txt"), "broken\n"); run("add", "."); run("commit", "-q", "-m", "base");
  run("checkout", "-q", "-b", "0/fix-abc");
  writeFileSync(join(dir, "a.txt"), content); run("commit", "-q", "-am", "fix");
  run("checkout", "-q", "main");
}
const store = (findings: BurndownState["findings"]): StateStore => ({ load: () => ({ version: 1, findings, runs: [] }), save: () => undefined });
const key = (repo: string, fp: string) => `${repo}\u0000${fp}`;

describe("locationOf", () => {
  it("reads the stored annotation of the newest row that has one", () => {
    expect(locationOf([{}, { reviewAnnotation: JSON.stringify({ path: "src/a.ts", startLine: 4, endLine: 6, suggestion: "x" }) }])).toEqual({ path: "src/a.ts", startLine: 4, endLine: 6, suggestion: "x" });
  });
  it("is null without a usable path and line", () => {
    expect(locationOf([{ reviewAnnotation: JSON.stringify({ path: "a.ts" }) }, { reviewAnnotation: JSON.stringify({ path: "", startLine: 1 }) }, { reviewAnnotation: "not json" }])).toBeNull();
  });
  it("drops an end line before the start line", () => {
    expect(locationOf([{ reviewAnnotation: JSON.stringify({ path: "a.ts", startLine: 9, endLine: 2 }) }])).toEqual({ path: "a.ts", startLine: 9 });
  });
});

describe("readFixDiff", () => {
  it("returns the fix commit as a diff from the local branch", async () => {
    repoWithFix();
    const out = await readFixDiff(dir, "0/fix-abc");
    expect(out?.truncated).toBe(false);
    expect(out?.diff).toContain("-broken");
    expect(out?.diff).toContain("+fixed");
  });
  it("bounds a large diff", async () => {
    repoWithFix("x\n".repeat(MAX_DIFF_BYTES));
    const out = await readFixDiff(dir, "0/fix-abc");
    expect(out?.truncated).toBe(true);
    expect(out!.diff.length).toBeLessThanOrEqual(MAX_DIFF_BYTES);
  });
  it("refuses a missing branch, an option-shaped branch and a relative repository", async () => {
    repoWithFix();
    expect(await readFixDiff(dir, "0/fix-missing")).toBeNull();
    expect(await readFixDiff(dir, "--output=/tmp/x")).toBeNull();
    expect(await readFixDiff(dir, "a..b")).toBeNull();
    expect(await readFixDiff("relative/repo", "0/fix-abc")).toBeNull();
  });
  it("shows no diff when the branch holds more than one commit", async () => {
    repoWithFix();
    run("checkout", "-q", "0/fix-abc"); writeFileSync(join(dir, "a.txt"), "again\n"); run("commit", "-q", "-am", "more"); run("checkout", "-q", "main");
    expect(await readFixDiff(dir, "0/fix-abc")).not.toBeNull();
    run("checkout", "-q", "-b", "0/fix-two", "main"); run("merge", "-q", "--no-ff", "-m", "merge", "0/fix-abc");
    expect(await readFixDiff(dir, "0/fix-two")).toBeNull();
  });
});

describe("findingFixInfo", () => {
  const record = { finding: "f-aaaaaaaaaaaa", branch: "0/fix-abc", result: "pr-opened" as const, pullRequestUrl: "https://github.com/o/r/pull/1", draft: true, checksPassing: false, runId: "r", updatedAt: "2026-03-01T10:00:00.000Z" };
  it("returns the recorded fix for the fingerprint with the exact command, and no repository path", async () => {
    repoWithFix();
    const info = await findingFixInfo("fp-a", "f-aaaaaaaaaaaa-rest", undefined, store({ [key(dir, "fp-a")]: record, [key(dir, "fp-b")]: { ...record, finding: "other" } }));
    expect(info.command).toBe("0security findings fix f-aaaaaa");
    expect(info.records).toHaveLength(1);
    expect(info.records[0]).toMatchObject({ branch: "0/fix-abc", pullRequestUrl: "https://github.com/o/r/pull/1", draft: true, checksPassing: false });
    expect(info.records[0]!.diff).toContain("+fixed");
    expect(JSON.stringify(info)).not.toContain(dir);
  });
  it("is empty without a record, for a no-change run, and for a corrupt state file", async () => {
    expect((await findingFixInfo("fp-a", "f-1", undefined, store({}))).records).toEqual([]);
    expect((await findingFixInfo("fp-a", "f-1", undefined, store({ [key(dir, "fp-a")]: { ...record, result: "no-change" } }))).records).toEqual([]);
    expect((await findingFixInfo("fp-a", "f-1", undefined, { load: () => { throw new Error("bad"); }, save: () => undefined })).records).toEqual([]);
  });
  it("drops a pull request link that is not http or https", async () => {
    const info = await findingFixInfo("fp-a", "f-1", undefined, store({ [key(dir, "fp-a")]: { ...record, pullRequestUrl: "javascript:alert(1)", branch: "bad branch" } }));
    expect(info.records[0]).toMatchObject({ pullRequestUrl: null, branch: null });
    expect(info.records[0]!.diff).toBeUndefined();
  });
  it("hides records of repositories outside a scoped account's scope", async () => {
    const records = store({ [key(dir, "fp-a")]: record });
    expect((await findingFixInfo("fp-a", "f-1", target => target !== dir, records)).records).toEqual([]);
    expect((await findingFixInfo("fp-a", "f-1", target => target === dir, records)).records).toHaveLength(1);
  });
});
