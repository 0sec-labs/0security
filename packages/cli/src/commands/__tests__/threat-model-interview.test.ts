import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseScope } from "@0/engine/shared";
import { REQUIRED_HEADINGS, resolveOutputPath, runThreatModel, THREAT_MODEL_BRANCH, type ThreatModelDeps } from "../threat-model.js";

const dirs: string[] = [];
const folder = () => { const dir = mkdtempSync(join(tmpdir(), "tmi-test-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

const good = `---\ntitle: Threat model\ngenerated: 2026-01-01\ncommit: abc1234\n---\n# Threat model: app\n${REQUIRED_HEADINGS.map(heading => `## ${heading}\ntext`).join("\n")}\n`;
const put = (path: string, text: string) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, text); };
const options = (extra: Record<string, unknown> = {}) => ({ budget: "3", timeout: "60", ...extra }) as never;
const fenced = (value: unknown) => `\`\`\`json\n${JSON.stringify(value)}\n\`\`\``;

interface Setup { answers?: string[]; tty?: boolean; failModel?: boolean; questions?: unknown[]; wording?: unknown; output?: string; git?: (args: string[]) => string | Error }
function fakes(setup: Setup = {}) {
  const answers = [...(setup.answers ?? [])];
  const prompts: string[] = []; const said: string[] = []; const gitCalls: string[][] = []; const ghCalls: string[][] = [];
  let last = "";
  const client = {
    request: vi.fn(async (method: string, path: string, body?: unknown) => {
      if (method === "PATCH") workspace = (body as { workspacePath: string }).workspacePath;
      if (method === "POST" && path.endsWith("/messages")) {
        last = (body as { text: string }).text; prompts.push(last);
        if (last.includes("Write the threat model")) put(join(workspace, setup.output ?? ".0/threat-model.md"), good);
      }
      if (method === "GET") {
        const reply = last.includes("Mode 1") ? fenced({ questions: setup.questions ?? [] }) : last.includes("Mode 2") ? fenced(setup.wording ?? { entries: [] }) : "Wrote it";
        return { snapshot: { session: { id: "t1", status: setup.failModel ? "failed" : "ready" }, usage: { costUsd: 0.01 }, messages: [{ role: "assistant", content: [{ type: "text", text: reply }] }] } };
      }
      return { session: { id: "t1" } };
    }),
    dispose: vi.fn(),
  };
  let workspace = "";
  const deps: ThreatModelDeps = {
    open: async () => client as never, err: () => {}, sleep: async () => {}, startConsole: vi.fn(async () => () => {}), out: () => {},
    async git(_cwd, args) { gitCalls.push(args); const result = setup.git?.(args) ?? ""; if (result instanceof Error) throw result; return result; },
    async gh(_cwd, args) { ghCalls.push(args); return args[1] === "list" ? "[]" : "https://example.test/pr/1\n"; },
    makeTemp: () => folder(), removeTemp: () => {}, writeFile: (path, text) => writeFileSync(path, text), writePublic: (path, text) => writeFileSync(path, text),
    readFile: path => { try { return readFileSync(path, "utf8"); } catch { return undefined; } },
    isTTY: () => setup.tty ?? true,
    openTerminal: () => ({ say: text => { said.push(text); }, ask: async question => { said.push(question); return answers.shift(); }, close: () => {} }),
    now: () => new Date("2026-11-23T12:00:00Z"),
  };
  return { deps, prompts, said, gitCalls, ghCalls };
}

const exportQuestion = { id: "export-auth", question: "GET /export has no auth check. Do you want findings about it?", evidence: "src/routes/export.js:12", category: "broken-access-control" };

describe("0 threat-model --interview", () => {
  it("needs a terminal: without one it is a usage error and nothing is written", async () => {
    const dir = folder();
    const { deps } = fakes({ tty: false });
    await expect(runThreatModel(dir, options({ interview: true }), deps)).rejects.toThrow(/Run it in a terminal/);
  });

  it("drafts, asks the model's question, and writes SECURITY.md and the human block", async () => {
    const dir = folder();
    put(join(dir, "src/routes/export.js"), "app.get('/export', h);\n");
    put(join(dir, "SECURITY.md"), "# Security\r\n\r\nMail us.\r\n");
    const { deps, prompts, said } = fakes({ answers: ["2: it is a public download", "", "y"], questions: [exportQuestion], wording: { entries: [{ questionId: "export-auth", reason: "public download" }] } });
    const outcome = await runThreatModel(dir, options({ interview: true }), deps);
    expect(outcome.interview).toMatchObject({ mode: "model", asked: 1, answered: 1, entries: 1, wroteSecurity: true });
    const security = readFileSync(join(dir, "SECURITY.md"), "utf8");
    expect(security.startsWith("# Security\r\n\r\nMail us.\r\n")).toBe(true);
    expect(security).not.toMatch(/[^\r]\n/);
    expect(parseScope(security).entries[0]).toMatchObject({ kind: "out", category: "broken-access-control", reason: "public download", paths: ["src/routes/export.js"] });
    const model = readFileSync(join(dir, ".0", "threat-model.md"), "utf8");
    expect(model.startsWith(good.slice(0, good.indexOf("## Summary") + 11))).toBe(true);
    expect(model).toContain("## Summary\n\nDeclared scope:");
    expect(model).toContain("## Scope decisions");
    expect(model).toContain("<!-- human -->");
    expect(model).toContain("GET /export has no auth check");
    expect(model).toContain("Declared scope: [SECURITY.md#scope](../SECURITY.md#scope)");
    expect(prompts[1]).toContain("Mode 1");
    expect(said.join("\n")).toContain("Mode: questions from the model");
    expect(outcome.problems).toEqual([]);
  });

  it("writes nothing when the person says no to the final change", async () => {
    const dir = folder();
    const { deps } = fakes({ answers: ["2: public", "", "n"], questions: [exportQuestion] });
    const outcome = await runThreatModel(dir, options({ interview: true }), deps);
    expect(outcome.interview?.wroteSecurity).toBe(false);
    expect(() => readFileSync(join(dir, "SECURITY.md"), "utf8")).toThrow();
    expect(readFileSync(join(dir, ".0", "threat-model.md"), "utf8")).toBe(good);
  });

  it("the prompt for the draft links the scope only when SECURITY.md has a Scope section", async () => {
    const dir = folder();
    put(join(dir, "SECURITY.md"), "## Scope\n### Out of scope\n- dos: gateway\n");
    const { deps, prompts } = fakes({ answers: [], questions: [] });
    await runThreatModel(dir, options({ interview: true }), deps);
    expect(prompts[0]).toContain("Declared scope: [SECURITY.md#scope](../SECURITY.md#scope)");
    const plain = folder();
    const other = fakes({ questions: [] });
    await runThreatModel(plain, options({ interview: true }), other.deps);
    expect(other.prompts[0]).not.toContain("SECURITY.md#scope");
  });

  it("falls back to the fixed questionnaire when the model fails, and says which mode ran", async () => {
    const dir = folder();
    const { deps, said } = fakes({ failModel: true, answers: ["", "", "denial of service: gateway", "", "", "", "", "", "", "y"] });
    const outcome = await runThreatModel(dir, options({ interview: true }), deps);
    expect(outcome.interview).toMatchObject({ mode: "questionnaire", entries: 1, wroteSecurity: true });
    expect(said.join("\n")).toContain("Mode: fixed questionnaire");
    expect(parseScope(readFileSync(join(dir, "SECURITY.md"), "utf8")).entries[0]).toMatchObject({ kind: "out", category: "denial-of-service" });
  });

  it("with --pr commits SECURITY.md and the threat model together on 0/threat-model", async () => {
    const dir = folder();
    const { deps, gitCalls, ghCalls } = fakes({ answers: ["2: public download", "", "y"], questions: [exportQuestion], git: args => {
      if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return `${dir}\n`;
      if (args[0] === "symbolic-ref") return "origin/main\n";
      if (args[0] === "rev-parse" && args.includes("--quiet")) return new Error("no such ref");
      if (args[0] === "status") return "?? .0/threat-model.md\n?? SECURITY.md\n";
      if (args[0] === "diff") return new Error("changes staged");
      return "";
    } });
    // The work tree is a temp folder: give it the file the question cites.
    const realTemp = deps.makeTemp;
    deps.makeTemp = () => { const temp = realTemp(); put(join(temp, "tree", "src/routes/export.js"), "x"); return temp; };
    const outcome = await runThreatModel(dir, options({ interview: true, pr: true }), deps);
    expect(gitCalls).toContainEqual(["add", "--", ".0/threat-model.md"]);
    expect(gitCalls).toContainEqual(["add", "--", "SECURITY.md"]);
    expect(gitCalls.find(args => args.includes("commit"))!.join(" ")).toContain("declare its scope");
    expect(ghCalls.find(args => args[1] === "create")).toEqual(expect.arrayContaining(["--head", THREAT_MODEL_BRANCH]));
    expect(outcome.pullRequest?.created).toBe(true);
    expect(outcome.problems.join(" ")).not.toMatch(/other file/);
  });

  it("a budget for the interview threads only goes with --interview", async () => {
    await expect(runThreatModel(folder(), options({ interviewBudget: "1" }), fakes().deps)).rejects.toThrow(/applies to --interview/);
    await expect(runThreatModel(folder(), options({ interview: true, interviewBudget: "0" }), fakes().deps)).rejects.toThrow(/--interview-budget/);
  });
});

describe("0 threat-model --output", () => {
  it("accepts a relative Markdown path inside the folder", () => {
    const dir = folder();
    expect(resolveOutputPath(dir, undefined)).toBe(".0/threat-model.md");
    expect(resolveOutputPath(dir, "THREAT_MODEL.md")).toBe("THREAT_MODEL.md");
    expect(resolveOutputPath(dir, "./docs/security/model.md")).toBe("docs/security/model.md");
  });

  it("refuses anything else", () => {
    const dir = folder();
    for (const bad of ["/etc/x.md", "../x.md", "a/../../x.md", "x.txt", "", " ", "SECURITY.md", "security.md", ".git/x.md", "a\u0000b.md", "C:\\x.md", "~/x.md", "docs//", "a/./b.md"]) {
      expect(() => resolveOutputPath(dir, bad), JSON.stringify(bad)).toThrow(/--output/);
    }
  });

  it("refuses a path that leaves the folder through a link", () => {
    const dir = folder(); const outside = folder();
    symlinkSync(outside, join(dir, "link"));
    expect(() => resolveOutputPath(dir, "link/model.md")).toThrow(/--output/);
  });

  it("writes there, tells the thread the path, and keeps the human sections of an existing file there", async () => {
    const dir = folder();
    put(join(dir, "THREAT_MODEL.md"), `${good}\n<!-- human -->\nAdmins are staff only.\n`);
    const { deps, prompts } = fakes({ output: "THREAT_MODEL.md" });
    const outcome = await runThreatModel(dir, options({ output: "THREAT_MODEL.md" }), deps);
    expect(prompts[0]).toContain("Write it to THREAT_MODEL.md");
    expect(prompts[0]).toContain("keep every section marked <!-- human --> unchanged");
    expect(outcome.file).toBe(join(dir, "THREAT_MODEL.md"));
    await expect(runThreatModel(dir, options({ output: "../x.md" }), deps)).rejects.toThrow(/--output/);
  });

  it("with --pr commits the file at the chosen path", async () => {
    const dir = folder();
    const { deps, gitCalls } = fakes({ output: "THREAT_MODEL.md", git: args => {
      if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return `${dir}\n`;
      if (args[0] === "symbolic-ref") return "origin/main\n";
      if (args[0] === "rev-parse" && args.includes("--quiet")) return new Error("no");
      if (args[0] === "status") return "?? THREAT_MODEL.md\n";
      if (args[0] === "diff") return new Error("staged");
      return "";
    } });
    await runThreatModel(dir, options({ output: "THREAT_MODEL.md", pr: true }), deps);
    expect(gitCalls).toContainEqual(["add", "--", "THREAT_MODEL.md"]);
  });
});
