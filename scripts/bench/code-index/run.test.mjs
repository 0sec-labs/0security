import assert from "node:assert/strict";
import { test } from "node:test";
import { ARMS, INDEX_TOOLS, parseArgs, renderMarkdown, summarize, threadStats } from "./run.mjs";

test("threadStats counts assistant turns and tool calls by name", () => {
  const s = threadStats({ model: "m", consoleState: { configuration: { runtime: { providerId: "p" } } }, messages: [
    { role: "user", content: [{ type: "text", text: "go" }] },
    { role: "assistant", content: [{ type: "tool_use", name: "routes" }, { type: "tool_use", name: "bash" }] },
    { role: "user", content: [{ type: "tool_result" }] },
    { role: "assistant", content: [{ type: "tool_use", name: "routes" }] },
  ] });
  assert.equal(s.turns, 2);
  assert.deepEqual(s.tools, { routes: 2, bash: 1 });
  assert.equal(s.provider, "p");
});

test("arms differ only in toolset or skill", () => {
  assert.equal(ARMS.baseline.skill, undefined);
  assert.equal(ARMS["index-full"].env.ZERO_TOOLSET, "full");
  assert.equal(ARMS["index-skill"].skill, "seedless-depth-review");
  assert.deepEqual(INDEX_TOOLS, ["callers_of", "callees_of", "routes", "trace_to_sink"]);
});

test("parseArgs needs exactly one of --run and --dry-run and rejects unknown arms", () => {
  assert.throws(() => parseArgs([]));
  assert.throws(() => parseArgs(["--run", "--dry-run"]));
  assert.throws(() => parseArgs(["--dry-run", "--arms", "nope"]));
  assert.equal(parseArgs(["--dry-run"]).repeat, 3);
});

test("summarize groups runs and keeps every repeat so ranges can be shown", () => {
  const mk = (found, turns) => ({ fixture: "f", arm: "baseline", status: "complete", seconds: 10, turns, tokens: 1000, costUsd: 0, indexToolCalls: 0, authz: { found: 1, planted: 2 }, score: { planted: 4, found, recall: found / 4, falsePositives: 0, unmatched: [] } });
  const [row] = summarize([mk(3, 10), mk(4, 12), mk(2, 8)]);
  assert.deepEqual(row.found, [3, 4, 2]);
  assert.equal(row.runs, 3);
  assert.match(renderMarkdown([row], { mode: "scan", date: "d", providers: ["p"], models: ["m"], runs: 3 }), /\| f \| baseline \| 3\/3 \| 3\.0 \(2\.0-4\.0\)\/4 \|/);
});
