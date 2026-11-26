import assert from "node:assert/strict";
import test from "node:test";
import { parseArgs, relativize, sarifFindings, withAnnotations } from "./second-opinion.mjs";

const sarif = {
  version: "2.1.0",
  runs: [{
    tool: { driver: { name: "t", rules: [{ id: "r/sql", properties: { tags: ["CWE-89"] } }] } },
    results: [
      { ruleId: "r/sql", message: { text: "query built from input" }, locations: [{ physicalLocation: { artifactLocation: { uri: "file:///work/app/server.js" }, region: { startLine: 22, endLine: 22 } } }] },
      { ruleId: "r/none", message: { text: "no location" }, locations: [] },
    ],
  }],
};

test("sarifFindings turns results into matcher findings and skips results without a file", () => {
  const found = sarifFindings(sarif);
  assert.equal(found.length, 1);
  assert.equal(found[0].location.path, "/work/app/server.js");
  assert.equal(found[0].location.startLine, 22);
  assert.match(found[0].title, /CWE-89/);
});

test("relativize makes paths relative to the scanned folder", () => {
  const out = JSON.parse(relativize(JSON.stringify(sarif), "/work/app/"));
  assert.equal(out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "server.js");
});

test("parseArgs needs exactly one of --run and --dry-run unless it only runs the baselines", () => {
  assert.throws(() => parseArgs([]));
  assert.throws(() => parseArgs(["--run", "--dry-run"]));
  assert.doesNotThrow(() => parseArgs(["--baseline-only"]));
  const o = parseArgs(["--run", "--tools", "semgrep", "--repeat", "3", "--budget", "0.2", "--max-cost", "1", "--fixtures", "go-http,llm-app"]);
  assert.deepEqual(o.tools, ["semgrep"]);
  assert.equal(o.repeat, 3);
  assert.equal(o.maxCost, 1);
  assert.deepEqual(o.fixtures, ["go-http", "llm-app"]);
  assert.throws(() => parseArgs(["--run", "--tools", "bandit"]));
  assert.throws(() => parseArgs(["--run", "--bogus"]));
});

test("withAnnotations gives a flattened report location back to the finding so SARIF can name the file", () => {
  const out = withAnnotations({ findings: [{ id: "a", location: { path: "server.js", startLine: 3 } }, { id: "b" }] });
  assert.deepEqual(out.findings[0].reviewAnnotation, { path: "server.js", startLine: 3, endLine: undefined });
  assert.equal(out.findings[1].reviewAnnotation, undefined);
});

test("parseArgs accepts self as a baseline", () => {
  assert.deepEqual(parseArgs(["--dry-run", "--tools", "foxguard,self"]).tools, ["foxguard", "self"]);
});
