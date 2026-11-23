import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { reviewDepth, shallowReviewWarning, toolCallText } from "./scan-review.js";

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
