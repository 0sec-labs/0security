import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { followUpText, openedFiles, reviewDepth, reviewScopeFiles, shallowReviewWarning, toolCallText, unopenedFiles } from "./scan-review.js";

const dirs: string[] = [];
const app = () => {
  const dir = mkdtempSync(join(tmpdir(), "scan-review-"));
  dirs.push(dir);
  mkdirSync(join(dir, "routes"));
  for (const file of ["server.js", "routes/calc.js", "routes/users.js"]) writeFileSync(join(dir, file), "const r = require('express').Router();\nr.get('/x', (req, res) => res.send(eval(req.query.x)));\n");
  return dir;
};
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe("toolCallText", () => {
  it("joins the inputs of tool calls and ignores their results and the model's text", () => {
    const text = toolCallText({ messages: [
      { role: "assistant", content: [{ type: "text", text: "I read hidden.js" }, { type: "tool_use", name: "bash", input: { command: "cat -n server.js" } }] },
      { role: "user", content: [{ type: "tool_result", content: "routes/other.js" }] },
    ] });
    expect(text).toBe("bash\t{\"command\":\"cat -n server.js\"}");
    expect(text).toContain("server.js");
    expect(text).not.toContain("hidden.js");
    expect(text).not.toContain("other.js");
  });
});

describe("reviewDepth", () => {
  it("lists the source files no tool call named", () => {
    const depth = reviewDepth(app(), "cat -n server.js && cat routes/calc.js");
    expect(depth).toMatchObject({ sourceFiles: 3, opened: 2 });
    expect(depth?.notOpened).toEqual(["routes/users.js"]);
  });

  it("has nothing to report when every file was named", () => {
    const depth = reviewDepth(app(), "cat server.js routes/calc.js routes/users.js");
    expect(depth?.notOpened).toEqual([]);
    expect(shallowReviewWarning(depth)).toBeUndefined();
  });

  it("says the review was shallow and which files were skipped", () => {
    const warning = shallowReviewWarning(reviewDepth(app(), "find . -type f"));
    expect(warning).toContain("opened 0 of 3 source files");
    expect(warning).toContain("routes/users.js");
  });

  it("counts files read through a shell glob, but not files only listed by a find pattern", () => {
    const dir = app();
    expect(reviewDepth(dir, JSON.stringify({ command: "for f in server.js routes/*.js; do nl -ba \"$f\"; done" }))?.notOpened).toEqual([]);
    expect(reviewDepth(dir, JSON.stringify({ command: "find . -name '*.js' -not -path '*/node_modules/*'" }))?.notOpened).toHaveLength(3);
  });

  it("has nothing to say about a folder without source files", () => {
    const dir = mkdtempSync(join(tmpdir(), "scan-review-"));
    dirs.push(dir);
    expect(reviewDepth(dir, "")).toBeUndefined();
  });
});

describe("unopenedFiles", () => {
  const files = ["server.js", "routes/calc.js", "routes/users.js", "app/data/profile-dao.js"];
  const open = (...commands: string[]) => unopenedFiles(files, commands.map(command => `bash\t${JSON.stringify({ command })}`).join("\n"));
  const all = [...files].sort();

  it.each([
    ["cat", "cat server.js", "server.js"],
    ["sed", "sed -n '1,80p' routes/calc.js", "routes/calc.js"],
    ["nl", "nl -ba routes/users.js", "routes/users.js"],
    ["head", "head -n 50 app/data/profile-dao.js", "app/data/profile-dao.js"],
    ["tail", "tail -n 20 server.js", "server.js"],
    ["less", "less routes/calc.js", "routes/calc.js"],
    ["bat", "bat --line-range 1:40 routes/users.js", "routes/users.js"],
    ["rg with a file", "rg -n 'query' app/data/profile-dao.js", "app/data/profile-dao.js"],
    ["grep with a file", "grep -n eval routes/calc.js", "routes/calc.js"],
    ["python open()", "python3 -c \"print(open('routes/users.js').read())\"", "routes/users.js"],
    ["node readFileSync", "node -e \"console.log(require('fs').readFileSync('server.js','utf8'))\"", "server.js"],
    ["an absolute path", "cat /work/app/server.js", "server.js"],
    ["cd then a relative path", "cd app/data && cat profile-dao.js", "app/data/profile-dao.js"],
    ["a basename only", "cat profile-dao.js", "app/data/profile-dao.js"],
    ["a shell glob", "cat routes/*.js", "routes/calc.js"],
    ["a brace glob", "cat routes/{calc,users}.js", "routes/users.js"],
    ["xargs cat", "find routes -name '*.js' | xargs cat", "routes/calc.js"],
    ["find -exec cat", "find . -type f -name '*.js' -exec cat {} +", "app/data/profile-dao.js"],
    ["cat of a command substitution", "cat $(git ls-files 'app/**/*.js')", "app/data/profile-dao.js"],
    ["a for loop", "for f in server.js routes/*.js; do nl -ba \"$f\"; done", "routes/users.js"],
  ])("counts %s as opening", (_name, command, file) => {
    expect(open(command)).not.toContain(file);
  });

  it.each([
    ["ls", "ls routes/calc.js"],
    ["ls -R", "ls -R app"],
    ["a find listing", "find . -name '*.js'"],
    ["a find by the file name", "find . -name calc.js"],
    ["a recursive search over a directory", "grep -rn eval routes/"],
    ["a search whose pattern is a file name", "grep -rn 'server.js' ."],
    ["a rg glob option", "rg -n eval --glob '*.js' ."],
    ["wc", "wc -l routes/*.js"],
    ["a command substitution with no reader", "echo $(find . -name '*.js')"],
    ["a directory read", "cat routes"],
  ])("does not count %s as opening", (_name, command) => {
    expect(open(command)).toEqual(all);
  });

  it("does not count a search that only lists directories with a read of another file", () => {
    expect(open("ls routes; cat server.js")).toEqual(all.filter(file => file !== "server.js"));
  });

  it("reads the path of a read tool and ignores a listing tool", () => {
    expect(unopenedFiles(files, "read_file\t{\"path\":\"routes/calc.js\",\"offset\":1}")).not.toContain("routes/calc.js");
    expect(unopenedFiles(files, "list_dir\t{\"path\":\"routes/calc.js\"}")).toEqual(all);
    expect(unopenedFiles(files, "read_file\t{\"path\":\"routes\"}")).toEqual(all);
  });

  it("counts files a task for a worker thread names", () => {
    const call = `spawn_agent\t${JSON.stringify({ tasks: [{ name: "a", task: "Files: routes/calc.js, users.js and app/data/profile-dao.js. Load skill scan." }] })}`;
    expect(unopenedFiles(files, call)).toEqual(["server.js"]);
  });

  it("takes plain commands and the folder prefix", () => {
    expect(openedFiles(files, "cat /tmp/x/server.js\nsed -n 1,5p /tmp/x/routes/calc.js", "/tmp/x")).toEqual(new Set(["server.js", "routes/calc.js"]));
  });

  it("counts a whole-tree read by an interpreter", () => {
    expect(open("python3 - <<'EOF'\nimport os\nfor r,_,fs in os.walk('.'):\n  for f in fs: print(open(os.path.join(r,f)).read())\nEOF")).toEqual([]);
  });
});

describe("reviewScopeFiles", () => {
  it("leaves out files over 200 KB, binary files and vendored folders", () => {
    const dir = app();
    writeFileSync(join(dir, "big.js"), `${"x".repeat(250 * 1024)}\n`);
    writeFileSync(join(dir, "bin.js"), Buffer.from([0, 1, 2, 3]));
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules/dep.js"), "x\n");
    expect(reviewScopeFiles(dir)).toEqual(["routes/calc.js", "routes/users.js", "server.js"]);
  });
});

describe("followUpText", () => {
  it("names the files and asks for a review", () => {
    const text = followUpText(["a.js", "b/c.js"]);
    expect(text).toContain("- a.js");
    expect(text).toContain("Open and review each one now, then add any findings and update your summary.");
  });
  it("counts the files it does not name", () => {
    expect(followUpText(Array.from({ length: 50 }, (_, i) => `f${i}.js`), 40)).toContain("and 10 more");
  });
});
