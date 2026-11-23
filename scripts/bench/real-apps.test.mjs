import assert from "node:assert/strict";
import test from "node:test";
import { CONFIGS, loadKeys, parseArgs, scanArgs, scrubComments, summarize } from "./real-apps.mjs";
import { validateAnswer } from "./match.mjs";

test("scrub keeps every line and blanks whole-line comments in JavaScript", () => {
  const src = ["const a = 1; // Insecure use of eval", "// Fix for A1", "/* block", "still block */", "const url = 'http://x.test/a'; // fine", "run(a)"].join("\n");
  const r = scrubComments(src, "js");
  assert.equal(r.text.split("\n").length, 6);
  assert.deepEqual(r.text.split("\n"), ["const a = 1;", "", "", "", "const url = 'http://x.test/a'; // fine", "run(a)"]);
  assert.equal(r.changed, 4);
});

test("scrub leaves comment markers inside strings alone", () => {
  const line = "const s = \"a // insecure b\";";
  assert.equal(scrubComments(line, "js").text, line);
  const py = "x = '# vuln'";
  assert.equal(scrubComments(py, "py").text, py);
});

test("scrub handles Python and HTML comments", () => {
  assert.deepEqual(scrubComments("# note\nif vuln:  # SQLi Injection\n    pass", "py").text.split("\n"), ["", "if vuln:", "    pass"]);
  assert.deepEqual(scrubComments("<p>a</p><!-- Fix for A8 -->\n<!-- multi\nline -->\n<b>x</b>", "html").text.split("\n"), ["<p>a</p>", "", "", "<b>x</b>"]);
});

test("every answer key is well formed and names its sources", () => {
  const keys = loadKeys();
  assert.deepEqual(keys.map((k) => k.fixture).sort(), ["dvna", "nodegoat", "vampi"]);
  for (const key of keys) {
    assert.deepEqual(validateAnswer(key), [], key.fixture);
    assert.match(key.sha, /^[0-9a-f]{40}$/);
    assert.ok(key.items.every((i) => i.docRef && ["doc-file-function", "located-by-us"].includes(i.source)), key.fixture);
    assert.ok(key.items.every((i) => !key.exclude.some((x) => i.path === x || i.path.startsWith(`${x}/`))), `${key.fixture}: an item is in an excluded path`);
  }
});

test("scan arguments per configuration", () => {
  const o = parseArgs(["--run", "--budget", "2"]);
  const args = (c) => scanArgs(c, "/f", "/o.json", o).join(" ");
  assert.ok(!args("default").includes("--prepass"));
  assert.match(args("prepass-off"), /--prepass off/);
  assert.match(args("foxguard-semgrep"), /--scanner foxguard,semgrep/);
  assert.match(args("batched"), /--batches on --batch-size 8 --concurrency 3/);
  assert.match(args("single"), /--batches off/);
  assert.match(args("lean"), /--batches off --prepass off/);
  assert.deepEqual(CONFIGS.length, 6);
  assert.throws(() => parseArgs([]), /exactly one/);
  assert.throws(() => parseArgs(["--run", "--dry-run"]), /exactly one/);
});

test("summaries average over repeats and list items missed in every repeat", () => {
  const score = (found, missedIds) => ({ planted: 4, found, recall: found / 4, findings: 5, unmatched: [], decoyHits: [], nearMisses: [], missedIds });
  const rows = summarize([
    { app: "a", config: "default", costUsd: 1, seconds: 10, status: "complete", coverage: null, score: score(3, ["x"]) },
    { app: "a", config: "default", costUsd: 2, seconds: 20, status: "complete", coverage: null, score: score(2, ["x", "y"]) },
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].recallMean, 0.625);
  assert.deepEqual(rows[0].missedEvery, ["x"]);
  assert.equal(rows[0].costMean, 1.5);
});
