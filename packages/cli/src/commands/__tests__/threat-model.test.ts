import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkThreatModel, humanBlocks, pullRequestBody, REQUIRED_HEADINGS, runThreatModel, THREAT_MODEL_BRANCH, type ThreatModelDeps } from "../threat-model.js";

const dirs: string[] = [];
const folder = () => { const dir = mkdtempSync(join(tmpdir(), "tm-test-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

const good = `---\ntitle: Threat model\ngenerated: 2026-01-01\ncommit: abc1234\n---\n# Threat model: app\n${REQUIRED_HEADINGS.map(heading => `## ${heading}\ntext`).join("\n")}\n`;
const finished = { session: { id: "t1", status: "ready" }, usage: { costUsd: 0.02 }, messages: [{ role: "assistant", content: [{ type: "text", text: "Wrote it @someone #12" }] }] };

function fakes(onThread: (workspace: string) => void, git: (args: string[]) => string | Error = () => "") {
  const requests: Array<[string, string, unknown]> = [];
  const gitCalls: string[][] = []; const ghCalls: string[][] = []; const written: Record<string, string> = {};
  const client = {
    request: vi.fn(async (method: string, path: string, body?: unknown) => {
      requests.push([method, path, body]);
      if (method === "PATCH") onThread((body as { workspacePath: string }).workspacePath);
      return method === "GET" ? { snapshot: finished } : { session: { id: "t1" } };
    }),
    dispose: vi.fn(),
  };
  const deps: ThreatModelDeps = {
    open: async () => client as never, err: () => {}, sleep: async () => {}, startConsole: vi.fn(async () => () => {}), out: () => {},
    async git(_cwd, args) { gitCalls.push(args); const result = git(args); if (result instanceof Error) throw result; return result; },
    async gh(_cwd, args) { ghCalls.push(args); return args[1] === "list" ? "[]" : "https://example.test/pr/1\n"; },
    makeTemp: () => folder(), removeTemp: () => {}, writeFile: (path, text) => { written[path] = text; },
    readFile: path => { try { return readFileSync(path, "utf8"); } catch { return undefined; } },
  };
  return { deps, requests, gitCalls, ghCalls, written };
}
const options = (extra: Record<string, unknown> = {}) => ({ budget: "3", timeout: "60", ...extra }) as never;
const put = (path: string, text: string) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, text); };

describe("threat model file checks", () => {
  it("accepts the documented structure and names what is missing", () => {
    expect(checkThreatModel(good)).toEqual([]);
    expect(checkThreatModel(undefined)[0]).toMatch(/was not written/);
    expect(checkThreatModel("# no front matter\n## Summary")).toEqual(expect.arrayContaining(["it has no front matter", expect.stringMatching(/missing sections: What matters most/)]));
    expect(checkThreatModel(good.replace("commit: abc1234\n", ""))).toContain("the front matter has no commit");
  });
  it("finds the human-marked blocks", () => {
    const text = "## Actors\n<!-- human -->\nAdmins are staff only.\n\n## Entry points\nx\n<!-- human -->\nkept\n<!-- /human -->\nnot kept";
    expect(humanBlocks(text)).toEqual(["Admins are staff only.", "kept"]);
  });
  it("keeps model text from notifying people in the pull request body", () => {
    const body = pullRequestBody("hi @someone see #12", [], true);
    expect(body).not.toMatch(/@someone/);
    expect(body).not.toMatch(/ #12/);
    expect(body).toContain("--context");
    expect(body).toContain("base branch");
  });
});

describe("0 threat-model", () => {
  it("writes the file in the folder, without git or gh", async () => {
    const dir = folder();
    const { deps, requests, ghCalls } = fakes(workspace => put(join(workspace, ".0", "threat-model.md"), good));
    const outcome = await runThreatModel(dir, options(), deps);
    expect(outcome).toMatchObject({ written: true, changed: true, problems: [] });
    expect(readFileSync(join(dir, ".0", "threat-model.md"), "utf8")).toBe(good);
    const prompt = (requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string }).text;
    expect(prompt).toContain("`threat-model` skill");
    expect(prompt).toContain("The file does not exist yet");
    expect(ghCalls).toEqual([]);
  });

  it("reports a malformed file and a human section that was changed", async () => {
    const dir = folder();
    put(join(dir, ".0", "threat-model.md"), `${good}\n<!-- human -->\nAdmins are staff only.\n`);
    const { deps, requests } = fakes(workspace => put(join(workspace, ".0", "threat-model.md"), "# rewritten\n"));
    const outcome = await runThreatModel(dir, options(), deps);
    expect(outcome.humanSectionsKept).toBe(false);
    expect(outcome.problems.join(" ")).toMatch(/no front matter/);
    expect(outcome.problems.join(" ")).toMatch(/human/);
    expect((requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string }).text).toContain("keep every section marked <!-- human --> unchanged");
  });

  it("with --pr works in a separate work tree on 0/threat-model, commits only that file and opens a pull request", async () => {
    const dir = folder();
    let tree = "";
    const { deps, gitCalls, ghCalls, written } = fakes(workspace => { tree = workspace; put(join(workspace, ".0", "threat-model.md"), good); put(join(workspace, "src", "app.js"), "edited"); }, args => {
      if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return `${dir}\n`;
      if (args[0] === "symbolic-ref") return "origin/main\n";
      if (args[0] === "rev-parse" && args.includes("--quiet")) return new Error("no such ref");
      if (args[0] === "status") return "?? .0/threat-model.md\n M src/app.js\n";
      if (args[0] === "diff") return new Error("changes staged");
      return "";
    });
    const outcome = await runThreatModel(dir, options({ pr: true }), deps);
    expect(tree).not.toBe(dir);
    expect(gitCalls).toContainEqual(["worktree", "add", "--quiet", "-B", THREAT_MODEL_BRANCH, expect.any(String), "origin/main"]);
    expect(gitCalls).toContainEqual(["add", "--", ".0/threat-model.md"]);
    expect(gitCalls.some(args => args.includes("push") && args.some(arg => arg.startsWith("--force")))).toBe(false);
    expect(gitCalls.some(args => args[0] === "worktree" && args[1] === "remove")).toBe(true);
    expect(ghCalls.find(args => args[1] === "create")).toEqual(expect.arrayContaining(["--head", THREAT_MODEL_BRANCH, "--base", "main"]));
    expect(outcome.pullRequest).toEqual({ url: "https://example.test/pr/1", created: true });
    expect(outcome.problems.join(" ")).toMatch(/other file/);
    expect(Object.values(written)[0]).toContain("unknown: confirm with the team");
  });

  it("with --pr builds on the branch's existing commits and opens nothing when the file is malformed", async () => {
    const dir = folder();
    const { deps, gitCalls, ghCalls } = fakes(workspace => put(join(workspace, ".0", "threat-model.md"), "junk"), args => {
      if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return `${dir}\n`;
      if (args[0] === "symbolic-ref") return "origin/main\n";
      if (args[0] === "rev-parse" && args.includes("refs/remotes/origin/0/threat-model")) return "abc\n";
      if (args[0] === "rev-parse" && args.includes("--quiet")) return new Error("no");
      return "";
    });
    const outcome = await runThreatModel(dir, options({ pr: true }), deps);
    expect(gitCalls).toContainEqual(["worktree", "add", "--quiet", "-B", THREAT_MODEL_BRANCH, expect.any(String), `origin/${THREAT_MODEL_BRANCH}`]);
    expect(ghCalls).toEqual([]);
    expect(outcome.changed).toBe(false);
  });

  it("refuses --computer, a bad budget and a missing folder", async () => {
    const { deps } = fakes(() => {});
    await expect(runThreatModel(folder(), options({ computer: "x" }), deps)).rejects.toThrow(/local console/);
    await expect(runThreatModel(folder(), options({ budget: "0" }), deps)).rejects.toThrow(/--budget/);
    await expect(runThreatModel("/no/such/dir", options(), deps)).rejects.toThrow(/not a folder/);
  });
});
