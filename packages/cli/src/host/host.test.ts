import { describe, expect, it } from "vitest";
import { selectHost } from "./index.js";

function fake(replies: Record<string, string> = {}) {
  const calls: Array<{ args: string[]; input?: string }> = [];
  const gitCalls: string[][] = [];
  const host = selectHost({
    run: async (args, input) => { calls.push({ args, ...(input !== undefined ? { input } : {}) }); return replies[args.slice(0, 2).join(" ")] ?? ""; },
    git: async args => { gitCalls.push(args); return ""; },
  });
  return { host, calls, gitCalls };
}

describe("selectHost", () => {
  it("returns GitHub by default and rejects other hosts", () => {
    expect(selectHost({ run: async () => "" }).name).toBe("github");
    expect(() => selectHost({ host: "gitlab", run: async () => "" })).toThrow(/Unsupported code host 'gitlab'/);
  });
});

describe("GitHub host over a fake gh", () => {
  it("validates repository names", () => {
    const { host } = fake();
    expect(host.isValidRepo("o/r")).toBe(true);
    for (const bad of ["", "o", "../r", "o/..", "o/r/x", "o r/x"]) expect(host.isValidRepo(bad)).toBe(false);
  });

  it("reads the current repository and tolerates failure", async () => {
    expect(await fake({ "repo view": "o/r\n" }).host.currentRepo()).toBe("o/r");
    const failing = selectHost({ run: async () => { throw new Error("no"); } });
    expect(await failing.currentRepo()).toBe("");
  });

  it("finds, creates and edits pull requests with plain argument arrays", async () => {
    const { host, calls } = fake({ "pr list": '[{"number":7,"url":"u","isDraft":true}]', "pr create": "note\nhttps://x/pull/9\n" });
    expect(await host.findOpenPullRequest("b")).toEqual({ number: 7, url: "u", isDraft: true });
    expect(await host.createPullRequest({ base: "main", head: "b", title: "t", bodyFile: "/f", draft: true })).toBe("https://x/pull/9");
    await host.createPullRequest({ base: "main", head: "b", title: "t", bodyFile: "/f", draft: false });
    await host.updatePullRequestBody(7, "/f");
    await host.setPullRequestReady(7, true);
    await host.setPullRequestReady(7, false);
    expect(calls.map(call => call.args)).toEqual([
      ["pr", "list", "--head", "b", "--state", "open", "--json", "number,url,isDraft"],
      ["pr", "create", "--base", "main", "--head", "b", "--title", "t", "--body-file", "/f", "--draft"],
      ["pr", "create", "--base", "main", "--head", "b", "--title", "t", "--body-file", "/f"],
      ["pr", "edit", "7", "--body-file", "/f"],
      ["pr", "ready", "7"],
      ["pr", "ready", "--undo", "7"],
    ]);
  });

  it("finds no pull request when gh prints nothing", async () => {
    expect(await fake().host.findOpenPullRequest("b")).toBeUndefined();
  });

  it("pushes only the named branch with a lease", async () => {
    const { host, gitCalls } = fake();
    await host.pushBranch("0/fix-x");
    expect(gitCalls).toEqual([["push", "--force-with-lease", "--set-upstream", "origin", "0/fix-x:0/fix-x"]]);
  });

  it("uploads SARIF and reads its status", async () => {
    const { host, calls } = fake({ "api --method": '{"id":"abc"}', "api repos/o/r/code-scanning/sarifs/a%2Fb": '{"processing_status":"complete"}' });
    expect(await host.uploadSarif("o/r", { commit: "c", ref: "refs/heads/m", sarif: "S", tool: "t" })).toEqual({ id: "abc" });
    expect(JSON.parse(calls[0]!.input!)).toEqual({ commit_sha: "c", ref: "refs/heads/m", sarif: "S", tool_name: "t" });
    expect(calls[0]!.args).toEqual(["api", "--method", "POST", "repos/o/r/code-scanning/sarifs", "--input", "-"]);
    expect(await host.sarifStatus("o/r", "a/b")).toEqual({ processing_status: "complete" });
  });

  it("hands out an issue tracker for a repository", async () => {
    const { host, calls } = fake({ "api --method": '{"number":3}' });
    expect(await host.issues("o/r").create({ title: "t", body: "b", labels: [] })).toBe(3);
    expect(calls[0]!.args).toEqual(["api", "--method", "POST", "repos/o/r/issues", "--input", "-"]);
  });
});

describe("GitHub host: pull request labels, reviewers and state", () => {
  it("adds labels and reviewers as separate flag=value arguments, never a shell string", async () => {
    const { host, calls } = fake();
    await host.editPullRequest(7, { addLabels: ["security", "needs review"], addReviewers: ["alice", "acme/appsec"] });
    await host.editPullRequest(7, {});
    expect(calls).toEqual([{ args: ["pr", "edit", "7", "--add-label=security", "--add-label=needs review", "--add-reviewer=alice", "--add-reviewer=acme/appsec"] }]);
  });

  it("reads merged, closed and open pull requests, and refuses anything but a GitHub pull request URL", async () => {
    const url = "https://github.com/o/r/pull/7";
    expect(await fake({ "pr view": '{"state":"MERGED","isDraft":false,"commits":2}' }).host.pullRequestState(url)).toEqual({ state: "merged", draft: false, commits: 2 });
    expect((await fake({ "pr view": '{"state":"CLOSED","isDraft":true,"commits":1}' }).host.pullRequestState(url)).state).toBe("closed");
    expect((await fake({ "pr view": '{"state":"OPEN","isDraft":false,"commits":1}' }).host.pullRequestState(url)).state).toBe("open");
    const { host, calls } = fake();
    for (const bad of ["--help", "https://evil.example/o/r/pull/7", "https://github.com/o/r/issues/7", "https://github.com/o/r/pull/7 --web"]) await expect(host.pullRequestState(bad)).rejects.toThrow("pull request URL");
    expect(calls).toEqual([]);
  });
});

describe("GitHub live CI summary", () => {
  it.each([
    [[], "none"],
    [[{ state: "SUCCESS" }], "passing"],
    [[{ status: "COMPLETED", conclusion: "SUCCESS" }, { status: "QUEUED" }], "pending"],
    [[{ status: "COMPLETED", conclusion: "FAILURE" }], "failing"],
    [[{ status: "COMPLETED", conclusion: "UNKNOWN" }], "pending"],
  ] as const)("maps check states", async (checks, status) => {
    const { host } = fake({ "pr view": JSON.stringify({ statusCheckRollup: checks }) });
    expect(await host.pullRequestChecks!("https://github.com/o/r/pull/7")).toMatchObject({ status });
  });
});
