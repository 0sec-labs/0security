import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAnswer, convert, failingTests, parsePatch, validate } from "./vul4j.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const patchText = `diff --git a/src/main/java/app/Reader.java b/src/main/java/app/Reader.java
--- a/src/main/java/app/Reader.java
+++ b/src/main/java/app/Reader.java
@@ -3,2 +3,3 @@ class Reader {
-    x();
+    y();
+    z();
diff --git a/src/test/java/app/ReaderTest.java b/src/test/java/app/ReaderTest.java
--- a/src/test/java/app/ReaderTest.java
+++ b/src/test/java/app/ReaderTest.java
@@ -1,1 +1,2 @@
+// test
`;
// A made-up checkout in the layout the converter reads. It is not a real Vul4J project.
function fakeCheckout(info = {}) {
  const dir = mkdtempSync(join(tmpdir(), "0-vul4j-"));
  const root = join(dir, "checkout");
  mkdirSync(join(root, "src/main/java/app"), { recursive: true });
  mkdirSync(join(root, "VUL4J/human_patch"), { recursive: true });
  writeFileSync(join(root, "pom.xml"), "<project/>\n");
  writeFileSync(join(root, "src/main/java/app/Reader.java"), "class Reader {\n  void a() {}\n    x();\n}\n");
  writeFileSync(join(root, "VUL4J/vulnerability_info.json"), JSON.stringify({ vul_id: "VUL4J-99", cve_id: "CVE-0000-0000", cwe_id: "CWE-611", repo_slug: "example/reader", build_system: "Maven", compliance_level: 8, compile_cmd: "mvn compile", test_cmd: "mvn test", failing_tests: { "app.ReaderTest#reads": "failure" }, human_patch: "abc123", ...info }));
  writeFileSync(join(root, "VUL4J/human_patch/fix.patch"), patchText);
  return { dir, root };
}

test("parsePatch separates source from test files and finds the first changed line", () => {
  const p = parsePatch(patchText);
  assert.deepEqual(p.source, [{ path: "src/main/java/app/Reader.java", firstLine: 3 }]);
  assert.deepEqual(p.tests.map((f) => f.path), ["src/test/java/app/ReaderTest.java"]);
});

test("failingTests reads an array, an object or a nested holder", () => {
  assert.deepEqual(failingTests({ failing_tests: ["a#b"] }), ["a#b"]);
  assert.deepEqual(failingTests({ failing_tests: { "a#b": "x" } }), ["a#b"]);
  assert.deepEqual(failingTests({ tests: { failing_tests: ["c#d"] } }), ["c#d"]);
  assert.deepEqual(failingTests({}), []);
});

test("buildAnswer reports missing fields instead of guessing", () => {
  const { problems } = buildAnswer({ vul_id: "V" }, { source: [], tests: [] });
  assert.equal(problems.length, 4);
});

test("convert writes a case folder that validates", () => {
  const { dir, root } = fakeCheckout();
  const out = join(dir, "case");
  const answer = convert(root, out);
  assert.equal(answer.id, "vul4j-99");
  assert.equal(answer.category, "xxe");
  assert.deepEqual(answer.proofTests, ["app.ReaderTest#reads"]);
  assert.deepEqual(answer.expectedFiles, ["src/main/java/app/Reader.java"]);
  assert.equal(existsSync(join(out, "repo/VUL4J")), false);
  assert.ok(existsSync(join(out, "repo/pom.xml")));
  assert.deepEqual(validate(out), []);
  const sarif = JSON.parse(readFileSync(join(out, "finding.sarif"), "utf8"));
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
});

test("validate names a case with no proof tests or a file that is not patched", () => {
  const { dir, root } = fakeCheckout();
  const out = join(dir, "case");
  convert(root, out);
  const file = join(out, "answer.json");
  const a = JSON.parse(readFileSync(file, "utf8"));
  writeFileSync(file, JSON.stringify({ ...a, proofTests: [], expectedFiles: ["src/main/java/app/Reader.java", "src/main/java/app/Other.java"] }));
  const problems = validate(out);
  assert.ok(problems.some((p) => /proofTests/.test(p)));
  assert.ok(problems.some((p) => /Other\.java is not in repo/.test(p)));
  assert.ok(problems.some((p) => /Other\.java is not changed/.test(p)));
});

test("convert refuses a checkout with no failing tests", () => {
  const { dir, root } = fakeCheckout({ failing_tests: {} });
  assert.throws(() => convert(root, join(dir, "case")), /no failing tests/);
});

test("the command line converts and validates", () => {
  const { dir, root } = fakeCheckout();
  const out = join(dir, "case");
  const c = spawnSync(process.execPath, [join(here, "vul4j.mjs"), "--convert", root, "--out", out], { encoding: "utf8" });
  assert.equal(c.status, 0, c.stderr);
  const v = spawnSync(process.execPath, [join(here, "vul4j.mjs"), "--validate", out], { encoding: "utf8" });
  assert.equal(v.status, 0, v.stderr);
  assert.match(v.stdout, /not done/);
});
