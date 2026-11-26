#!/usr/bin/env node
// Vul4J case-format support for the fix scorecard: turn a Vul4J checkout into a fix case folder, and check one.
//   node scripts/bench/vul4j.mjs --convert <vul4j checkout> --out <case folder> [--patch <human.patch>]
//   node scripts/bench/vul4j.mjs --validate <case folder>
//
// A Vul4J checkout is the project at its vulnerable revision plus a VUL4J/ folder. This reads VUL4J/vulnerability_info.json
// (fields vul_id, cve_id, cwe_id, repo_slug, build_system, compliance_level, compile_cmd, test_all_cmd, test_cmd,
// cmd_options, failing_module and the failing tests) and the human patch (VUL4J/human_patch/*.patch, or --patch). The
// field names come from the dataset's published columns and were not checked against a real checkout here: a field that
// is missing is reported, never guessed.
//
// The case differs from the small Java cases (see fix-cases/): there is no hidden Pov. The proof is the project's own
// failing tests, which fail on the vulnerable code and pass with the human patch, run through the project's build tool
// (Maven or Gradle). That run needs the build tool, a JDK of the right version and the project's dependencies, so this
// script does not run it. It only writes and checks the case files.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { isMain } from "./lib.mjs";

const CWE_CATEGORY = {
  "CWE-20": "missing-validation", "CWE-22": "path-traversal", "CWE-78": "command-injection", "CWE-79": "xss", "CWE-89": "sql-injection",
  "CWE-94": "code-injection", "CWE-116": "output-encoding", "CWE-200": "information-disclosure", "CWE-264": "broken-access-control",
  "CWE-287": "broken-authentication", "CWE-295": "tls-validation", "CWE-327": "weak-crypto", "CWE-352": "csrf", "CWE-400": "denial-of-service",
  "CWE-502": "deserialization", "CWE-611": "xxe", "CWE-776": "xxe", "CWE-918": "ssrf",
};
const isTestPath = (p) => /(^|\/)(src\/test|test|tests)\//.test(p) || /(Test|Tests|IT)\.java$/.test(p);

/** Files and the first changed line of each from a unified diff. Test files are listed apart. */
export function parsePatch(text) {
  const files = [];
  let cur;
  for (const line of text.split("\n")) {
    const header = /^\+\+\+ (?:b\/)?(.+?)(?:\t.*)?$/.exec(line);
    if (header) { cur = { path: header[1], firstLine: null }; files.push(cur); continue; }
    const hunk = /^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/.exec(line);
    if (hunk && cur && cur.firstLine === null) cur.firstLine = Number(hunk[1]);
  }
  const real = files.filter((f) => f.path !== "/dev/null");
  return { source: real.filter((f) => !isTestPath(f.path)), tests: real.filter((f) => isTestPath(f.path)) };
}

/** Normalise the failing tests, given as an array, an object keyed by name, or a { failing_tests } holder. */
export function failingTests(info) {
  const raw = info.failing_tests ?? info.tests?.failing_tests ?? info.tests?.failing ?? [];
  const list = Array.isArray(raw) ? raw : Object.keys(raw ?? {});
  return list.map(String).filter(Boolean);
}

/** The case's answer.json from the dataset's info and the parsed patch. Returns { answer, problems }. */
export function buildAnswer(info, patch) {
  const problems = [];
  const need = (k) => { if (!info[k]) problems.push(`vulnerability_info.json has no ${k}`); return info[k]; };
  const id = need("vul_id"), cwe = need("cwe_id"), system = need("build_system");
  const tests = failingTests(info);
  if (!tests.length) problems.push("vulnerability_info.json lists no failing tests, so there is no proof");
  if (!patch.source.length) problems.push("the human patch changes no source file");
  const cweKey = /^\d+$/.test(String(cwe)) ? `CWE-${cwe}` : String(cwe ?? "").toUpperCase();
  const cve = info.cve_id ? String(info.cve_id) : "no CVE id";
  const answer = {
    id: String(id ?? "").toLowerCase(), title: `${id} (${cve}, ${cweKey})`, category: CWE_CATEGORY[cweKey] ?? "other", severity: "high", language: "java", kind: "vul4j",
    source: { vulId: id, cveId: info.cve_id ?? null, cweId: cweKey, repo: info.repo_slug ?? null, humanPatchCommit: info.human_patch ?? null },
    build: { system, compliance: info.compliance_level ?? null, compile: info.compile_cmd ?? null, test: info.test_cmd ?? null, testAll: info.test_all_cmd ?? null, options: info.cmd_options ?? null, module: info.failing_module ?? null },
    proofTests: tests,
    expectedFiles: patch.source.map((f) => f.path),
    note: `Fix ${cve} (${cweKey}) without breaking the project. The tests in proofTests fail on the vulnerable code and pass with the human patch; the fix must make them pass and keep the rest of the suite green.`,
  };
  return { answer, problems };
}

/** A one-result SARIF at the human patch's first changed source line, as `0security findings import` reads it. */
export function buildSarif(answer, patch) {
  const first = patch.source[0];
  return { version: "2.1.0", runs: [{ tool: { driver: { name: "vul4j", rules: [{ id: answer.source.cweId, shortDescription: { text: answer.category } }] } }, results: [{ ruleId: answer.source.cweId, level: "error", message: { text: answer.title }, locations: [{ physicalLocation: { artifactLocation: { uri: first.path }, region: { startLine: Math.max(1, first.firstLine ?? 1), endLine: Math.max(1, first.firstLine ?? 1) } } }] }] }] };
}

export function convert(checkout, out, patchFile) {
  const infoFile = join(checkout, "VUL4J", "vulnerability_info.json");
  if (!existsSync(infoFile)) throw new Error(`${infoFile} not found: pass a Vul4J checkout`);
  const info = JSON.parse(readFileSync(infoFile, "utf8"));
  const patchDir = join(checkout, "VUL4J", "human_patch");
  const patchPath = patchFile ?? (existsSync(patchDir) ? readdirSync(patchDir).filter((f) => f.endsWith(".patch")).sort().map((f) => join(patchDir, f))[0] : undefined);
  if (!patchPath || !existsSync(patchPath)) throw new Error("no human patch found: pass --patch <file>");
  const patchText = readFileSync(patchPath, "utf8");
  const patch = parsePatch(patchText);
  const { answer, problems } = buildAnswer(info, patch);
  if (problems.length) throw new Error(problems.join("\n"));
  mkdirSync(out, { recursive: true });
  cpSync(checkout, join(out, "repo"), { recursive: true, filter: (src) => !/(^|\/)(\.git|VUL4J)(\/|$)/.test(src.slice(checkout.length)) });
  writeFileSync(join(out, "answer.json"), `${JSON.stringify(answer, null, 2)}\n`);
  writeFileSync(join(out, "finding.sarif"), `${JSON.stringify(buildSarif(answer, patch), null, 2)}\n`);
  writeFileSync(join(out, "human.patch"), patchText);
  return answer;
}

/** Static checks of a Vul4J case folder. Returns problems; the proof-test run itself needs the build tool and is not done. */
export function validate(dir) {
  const problems = [];
  for (const f of ["answer.json", "finding.sarif", "human.patch", "repo"]) if (!existsSync(join(dir, f))) problems.push(`missing ${f}`);
  if (problems.length) return problems;
  const answer = JSON.parse(readFileSync(join(dir, "answer.json"), "utf8"));
  if (answer.kind !== "vul4j") problems.push("answer.kind is not vul4j");
  if (answer.language !== "java") problems.push("answer.language must be java");
  for (const k of ["id", "category", "note"]) if (!answer[k]) problems.push(`answer needs ${k}`);
  if (!answer.build?.system) problems.push("answer.build.system is missing");
  if (!Array.isArray(answer.proofTests) || !answer.proofTests.length) problems.push("answer.proofTests is empty");
  if (!Array.isArray(answer.expectedFiles) || !answer.expectedFiles.length) problems.push("answer.expectedFiles is empty");
  for (const f of answer.expectedFiles ?? []) if (!existsSync(join(dir, "repo", f))) problems.push(`expected file ${f} is not in repo/`);
  try {
    const loc = JSON.parse(readFileSync(join(dir, "finding.sarif"), "utf8")).runs[0].results[0].locations[0].physicalLocation;
    const file = join(dir, "repo", loc.artifactLocation.uri);
    if (!existsSync(file)) problems.push(`the finding points at missing file ${loc.artifactLocation.uri}`);
    else if (loc.region.startLine > readFileSync(file, "utf8").split("\n").length) problems.push("the finding line is past the end of its file");
  } catch { problems.push("finding.sarif has no result with a location"); }
  const patch = parsePatch(readFileSync(join(dir, "human.patch"), "utf8"));
  const patched = new Set(patch.source.map((f) => f.path));
  for (const f of answer.expectedFiles ?? []) if (!patched.has(f)) problems.push(`expected file ${f} is not changed by human.patch`);
  return problems;
}

if (isMain(import.meta.url)) {
  const a = process.argv.slice(2);
  const get = (flag) => (a.includes(flag) ? a[a.indexOf(flag) + 1] : undefined);
  try {
    if (get("--convert")) {
      if (!get("--out")) throw new Error("--convert needs --out <case folder>");
      const out = resolve(get("--out"));
      const answer = convert(resolve(get("--convert")), out, get("--patch") && resolve(get("--patch")));
      const problems = validate(out);
      console.log(`wrote ${out}: ${answer.id}, ${answer.proofTests.length} proof test(s), expects ${answer.expectedFiles.join(", ")}${problems.length ? `\n${problems.join("\n")}` : ""}`);
      if (problems.length) process.exit(1);
    } else if (get("--validate")) {
      const problems = validate(resolve(get("--validate")));
      console.log(problems.length ? problems.join("\n") : "case files valid (the proof-test run needs the build tool and was not done)");
      if (problems.length) process.exit(1);
    } else throw new Error("pass --convert <checkout> --out <dir> or --validate <case folder>");
  } catch (e) { console.error(`${e.message}\nusage: node scripts/bench/vul4j.mjs --convert <vul4j checkout> --out <case folder> [--patch <file>] | --validate <case folder>`); process.exit(2); }
}
