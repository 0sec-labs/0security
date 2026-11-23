// Contract tests for the 0 GitHub Action (action.yml and scripts/action-run.sh).
// They run the real shell with a stand-in `0` binary that records its argv. No network, no model.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const repo = new URL("..", import.meta.url).pathname;
const script = join(repo, "scripts/action-run.sh");
const { parse } = createRequire(join(repo, "packages/cli/package.json"))("yaml");
const action = parse(readFileSync(join(repo, "action.yml"), "utf8"));
const hasJq = spawnSync("jq", ["--version"]).status === 0;

// ---- action.yml contract ----

test("existing inputs keep their names and defaults", () => {
  const want = { version: undefined, target: ".", "diff-base": "", model: "", budget: "5", passes: "1", "fail-on": "", upload: "true" };
  for (const [name, def] of Object.entries(want)) {
    assert.ok(name in action.inputs, `input ${name} is missing`);
    assert.equal(action.inputs[name].default, def, `default of ${name} changed`);
  }
  assert.equal(action.name, "0 security scan");
  for (const out of ["sarif", "exit-code", "status", "coverage"]) assert.ok(out in action.outputs, `output ${out} is missing`);
});

test("new inputs exist with safe defaults", () => {
  const defaults = { mode: "scan", scanner: "", rules: "", tiers: "", "known-sarif": "", "only-new": "false", context: "", scope: "", policy: "", skill: "", "allow-partial": "false", "licenses-preset": "" };
  for (const [name, def] of Object.entries(defaults)) assert.equal(action.inputs[name]?.default, def, `default of ${name}`);
});

test("no run block interpolates an expression", () => {
  for (const step of action.runs.steps) {
    if (step.run === undefined) continue;
    assert.ok(!step.run.includes("${{"), `step "${step.name}" interpolates an expression into its script`);
  }
});

test("every input reaches the shell only through env", () => {
  const used = new Set();
  for (const step of action.runs.steps) {
    const exprs = [];
    for (const [key, value] of Object.entries(step.env ?? {})) {
      for (const m of String(value).matchAll(/inputs\.([a-z-]+)/g)) { used.add(m[1]); exprs.push(m[1]); }
      assert.match(key, /^[A-Z_]+$/);
    }
    for (const value of Object.values(step.with ?? {})) for (const m of String(value).matchAll(/inputs\.([a-z-]+)/g)) used.add(m[1]);
    for (const m of String(step.if ?? "").matchAll(/inputs\.([a-z-]+)/g)) used.add(m[1]);
    if (step.run !== undefined) assert.equal(step.shell, "bash", `step "${step.name}" must set shell`);
  }
  for (const name of Object.keys(action.inputs)) assert.ok(used.has(name), `input ${name} is never used`);
});

test("third-party actions are pinned by commit", () => {
  for (const step of action.runs.steps) if (step.uses) assert.match(step.uses, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}( |$)/, step.uses);
});

// ---- shell behaviour ----

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "0-action-test-"));
  const ws = join(root, "ws");
  const temp = join(root, "tmp");
  const bin = join(root, "bin");
  for (const d of [ws, temp, bin, join(ws, "rules"), join(ws, "cfg")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(ws, "app.js"), "console.log(1)\n");
  writeFileSync(join(ws, "rules/r.yaml"), "rules: []\n");
  writeFileSync(join(ws, "cfg/tiers.yaml"), "default: standard\n");
  writeFileSync(join(ws, "cfg/known.sarif"), "{}\n");
  writeFileSync(join(ws, "cfg/ctx.md"), "# ctx\n");
  writeFileSync(join(ws, "cfg/scope.md"), "## Scope\\n");
  const log = join(root, "argv.log");
  const sarif = join(root, "fake.sarif");
  writeFileSync(sarif, JSON.stringify({ runs: [{ results: [] }] }));
  writeFileSync(join(bin, "0"), `#!/bin/sh
{ echo "--"; printf '%s\\n' "$@"; } >> "$FAKE_LOG"
out=""; prev=""
for a in "$@"; do [ "$prev" = -o ] && out="$a"; prev="$a"; done
if [ "$1" = sbom ] && [ "$2" = generate ] && [ -n "$out" ]; then echo '{"components":[{},{}]}' > "$out"; exit "\${FAKE_GEN_EXIT:-0}"; fi
if [ "$1" = sbom ] && [ "$2" = licenses ]; then exit "\${FAKE_LIC_EXIT:-0}"; fi
if [ -n "$out" ]; then cp "$FAKE_SARIF" "$out"; fi
if [ "$1" = sbom ]; then exit "\${FAKE_CHECK_EXIT:-0}"; fi
exit "\${FAKE_EXIT:-0}"
`);
  chmodSync(join(bin, "0"), 0o755);
  const run = (mode, extra = {}) => {
    const gout = join(root, "output");
    const gsum = join(root, "summary");
    writeFileSync(gout, ""); writeFileSync(gsum, "");
    const env = {
      PATH: `${bin}:${process.env.PATH}`, HOME: root, GITHUB_WORKSPACE: ws, RUNNER_TEMP: temp, GITHUB_OUTPUT: gout, GITHUB_STEP_SUMMARY: gsum,
      FAKE_LOG: log, FAKE_SARIF: sarif, BUDGET: "5", PASSES: "1", TARGET: ".", UPLOAD: "true", ...extra,
    };
    const r = spawnSync("bash", [script, mode], { env, cwd: ws, encoding: "utf8" });
    const outputs = Object.fromEntries(readFileSync(gout, "utf8").split("\n").filter(Boolean).map(l => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
    return { ...r, outputs, summary: readFileSync(gsum, "utf8"), argv: existsSync(log) ? readFileSync(log, "utf8") : "" };
  };
  return { root, ws, temp, sarif, log, run };
}

const calls = (argv) => argv.split("--\n").filter(Boolean).map(c => c.trim().split("\n"));

test("a full set of inputs becomes one argv array", () => {
  const f = fixture();
  const r = f.run("scan", { SCANNER: "foxguard,semgrep", RULES: "rules", TIERS: "cfg/tiers.yaml", KNOWN_SARIF: "cfg/known.sarif", ONLY_NEW: "true", CONTEXT: "cfg/ctx.md", SCOPE: "cfg/scope.md", POLICY: "cfg", SKILL: "scan", ALLOW_PARTIAL: "true", FAIL_ON: "high", MODEL: "gpt-6-luna", BUDGET: "0.5", PASSES: "2", DIFF_BASE: "origin/main" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const [argv] = calls(r.argv);
  const real = (p) => spawnSync("realpath", [join(f.ws, p)], { encoding: "utf8" }).stdout.trim();
  const at = (flag) => argv.flatMap((a, i) => (a === flag ? [argv[i + 1]] : []));
  assert.equal(argv[0], "scan");
  assert.deepEqual(at("--scanner"), ["foxguard", "semgrep"]);
  assert.deepEqual(at("--rules"), [real("rules")]);
  assert.deepEqual(at("--tiers"), [real("cfg/tiers.yaml")]);
  assert.deepEqual(at("--known"), [real("cfg/known.sarif")]);
  assert.deepEqual(at("--context"), [real("cfg/ctx.md")]);
  assert.deepEqual(at("--scope"), [real("cfg/scope.md")]);
  assert.deepEqual(at("--policy"), [real("cfg")]);
  assert.deepEqual(at("--skill"), ["scan"]);
  assert.deepEqual(at("--diff"), ["origin/main"]);
  assert.deepEqual(at("--model"), ["gpt-6-luna"]);
  assert.deepEqual(at("--budget"), ["0.5"]);
  assert.deepEqual(at("--fail-on"), ["high"]);
  assert.ok(argv.includes("--only-new") && argv.includes("--allow-partial"));
  assert.equal(r.outputs.code, "0");
});

test("defaults pass no optional flags", () => {
  const f = fixture();
  const r = f.run("scan", {});
  assert.equal(r.status, 0, r.stderr);
  const [argv] = calls(r.argv);
  for (const flag of ["--scanner", "--rules", "--tiers", "--known", "--only-new", "--context", "--scope", "--policy", "--skill", "--allow-partial", "--fail-on", "--diff", "--model"]) assert.ok(!argv.includes(flag), flag);
});

const BAD = [
  ["scanner", { SCANNER: "foxguard;id" }],
  ["scanner", { SCANNER: "nope" }],
  ["scanner", { SCANNER: "-x" }],
  ["scanner", { SCANNER: "foxguard,,semgrep" }],
  ["scanner", { SCANNER: "foxguard semgrep" }],
  ["scanner", { SCANNER: "foxguard\nsemgrep" }],
  ["rules", { SCANNER: "semgrep", RULES: "rules; id" }],
  ["rules", { SCANNER: "semgrep", RULES: "rules\nx" }],
  ["rules", { SCANNER: "semgrep", RULES: "-rules" }],
  ["rules", { SCANNER: "semgrep", RULES: "../outside" }],
  ["rules", { SCANNER: "semgrep", RULES: "/etc/passwd" }],
  ["rules", { SCANNER: "semgrep", RULES: "missing" }],
  ["rules", { SCANNER: "semgrep", RULES: "rules,-x" }],
  ["rules", { RULES: "rules" }],
  ["rules", { SCANNER: "foxguard", RULES: "rules" }],
  ["tiers", { TIERS: "cfg/nope.yaml" }],
  ["tiers", { TIERS: "$(touch pwned)" }],
  ["known-sarif", { KNOWN_SARIF: "cfg/known.sarif ,x" }],
  ["only-new", { ONLY_NEW: "true" }],
  ["only-new", { ONLY_NEW: "yes", KNOWN_SARIF: "cfg/known.sarif" }],
  ["context", { CONTEXT: "`id`" }],
  ["scope", { SCOPE: "cfg/missing.md" }],
  ["scope", { SCOPE: "../outside.md" }],
  ["scope", { SCOPE: "/etc/passwd" }],
  ["scope", { SCOPE: "$(touch pwned)" }],
  ["scope", { SCOPE: "-x" }],
  ["policy", { POLICY: "cfg/*" }],
  ["allow-partial", { ALLOW_PARTIAL: "yes" }],
  ["allow-partial", { ALLOW_PARTIAL: "true --force" }],
  ["skill", { SKILL: "-x" }],
  ["skill", { SKILL: "a b" }],
  ["model", { MODEL: "--model=x" }],
  ["model", { MODEL: "a\nb" }],
  ["budget", { BUDGET: "5; id" }],
  ["budget", { BUDGET: "-1" }],
  ["passes", { PASSES: "9" }],
  ["fail-on", { FAIL_ON: "urgent" }],
  ["diff-base", { DIFF_BASE: "--output=x" }],
  ["diff-base", { DIFF_BASE: "main; id" }],
  ["target", { TARGET: ".." }],
  ["target", { TARGET: "/etc" }],
  ["upload", { UPLOAD: "1" }],
];
for (const [name, env] of BAD) {
  test(`rejects bad ${name}: ${JSON.stringify(env)}`, () => {
    const f = fixture();
    const r = f.run("scan", env);
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /::error::/);
    assert.equal(r.argv, "", "0 must not run");
    assert.ok(!existsSync(join(f.ws, "pwned")));
  });
}

test("a link that leaves the workspace is refused", () => {
  const f = fixture();
  symlinkSync("/etc", join(f.ws, "link"));
  const r = f.run("scan", { SCANNER: "semgrep", RULES: "link" });
  assert.equal(r.status, 2);
  assert.match(r.stdout, /inside the workspace/);
});

test("error messages do not echo the value", () => {
  const f = fixture();
  const r = f.run("scan", { SCANNER: "::set-output name=x::y" });
  assert.equal(r.status, 2);
  assert.ok(!r.stdout.includes("set-output"));
});

function git(cwd, ...args) {
  const r = spawnSync("git", ["-c", "user.email=a@b.c", "-c", "user.name=t", ...args], { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
}

test("rules from the pull request's own code are refused for forks and pull_request_target", () => {
  const f = fixture();
  git(f.ws, "init", "-q", "-b", "main");
  git(f.ws, "add", "-A");
  git(f.ws, "commit", "-qm", "init");
  const head = git(f.ws, "rev-parse", "HEAD");
  const base = { SCANNER: "semgrep", RULES: "rules", HEAD_SHA: head, GITHUB_REPOSITORY: "o/r" };
  let r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "pull_request", HEAD_REPO: "fork/r" });
  assert.equal(r.status, 2, r.stdout);
  r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "pull_request_target", HEAD_REPO: "o/r" });
  assert.equal(r.status, 2, r.stdout);
  r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "pull_request", HEAD_REPO: "o/r" });
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /::warning::/);
  r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "push" });
  assert.equal(r.status, 0);
  assert.ok(!r.stdout.includes("::warning::"));
  // A checkout of the base branch (head sha differs) is trusted even in pull_request_target.
  r = f.run("scan", { ...base, HEAD_SHA: "a".repeat(40), GITHUB_EVENT_NAME: "pull_request_target", HEAD_REPO: "fork/r" });
  assert.equal(r.status, 0, r.stdout);
});

test("a scope file from the pull request's own code is refused for forks and pull_request_target, and warned about otherwise", () => {
  const f = fixture();
  writeFileSync(join(f.ws, "SECURITY.md"), "## Scope\n### Out of scope\n- denial of service: gateway\n");
  git(f.ws, "init", "-q", "-b", "main");
  git(f.ws, "add", "-A");
  git(f.ws, "commit", "-qm", "init");
  const head = git(f.ws, "rev-parse", "HEAD");
  const base = { SCOPE: "SECURITY.md", HEAD_SHA: head, GITHUB_REPOSITORY: "o/r" };
  let r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "pull_request", HEAD_REPO: "fork/r" });
  assert.equal(r.status, 2, r.stdout);
  assert.equal(r.argv, "", "0 must not run");
  r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "pull_request_target", HEAD_REPO: "o/r" });
  assert.equal(r.status, 2, r.stdout);
  r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "pull_request", HEAD_REPO: "o/r" });
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /::warning::Input scope/);
  r = f.run("scan", { ...base, GITHUB_EVENT_NAME: "push" });
  assert.equal(r.status, 0);
  assert.ok(!r.stdout.includes("::warning::"));
  // The base branch's copy, checked out apart from the pull request, is trusted.
  const sep = join(f.ws, "base");
  mkdirSync(sep, { recursive: true });
  writeFileSync(join(sep, "SECURITY.md"), "## Scope\n");
  git(sep, "init", "-q", "-b", "main");
  r = f.run("scan", { ...base, SCOPE: "base/SECURITY.md", GITHUB_EVENT_NAME: "pull_request_target", HEAD_REPO: "fork/r" });
  assert.equal(r.status, 0, r.stdout);
});

test("rules from a separate checkout are accepted for a fork pull request", () => {
  const f = fixture();
  git(f.ws, "init", "-q", "-b", "main");
  git(f.ws, "add", "-A");
  git(f.ws, "commit", "-qm", "init");
  const head = git(f.ws, "rev-parse", "HEAD");
  const sep = join(f.ws, "base-rules");
  mkdirSync(join(sep, "r"), { recursive: true });
  writeFileSync(join(sep, "r/x.yaml"), "rules: []\n");
  git(sep, "init", "-q", "-b", "main");
  const r = f.run("scan", { SCANNER: "semgrep", RULES: "base-rules/r", HEAD_SHA: head, GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request", HEAD_REPO: "fork/r" });
  assert.equal(r.status, 0, r.stdout);
});

test("status, coverage and summary come from the report and are neutralised", { skip: !hasJq }, () => {
  const f = fixture();
  const result = (severity, known) => ({ ruleId: "x", level: "error", message: { text: "RAW MODEL TEXT @alice #12 <img src=x>" }, properties: { severity, ...(known ? { knownStatus: known } : {}) } });
  writeFileSync(f.sarif, JSON.stringify({ runs: [{ results: [result("high", "new"), result("medium", "already-known"), result("medium"), { ruleId: "review-check/a", properties: { advisory: true } }],
    properties: { status: "budget_exhausted", failure: { cause: "provider_connection", message: "The model provider dropped the connection @bob #7 <script>" }, coverage: { complete: false, statement: "reviewed 3 of 9 entry points; 6 not reached (budget) @bob #7 <script>" }, tier: { name: "standard", source: "glob" }, known: { tools: ["codeql"], total: 4, findings: { new: 1, alreadyKnown: 2, confirmedIndependently: 1 }, hidden: 1 } } }] }));
  const r = f.run("scan", { FAIL_ON: "high" });
  assert.equal(r.status, 0);
  assert.equal(r.outputs.status, "partial");
  assert.equal(r.outputs.coverage, "reviewed 3 of 9 entry points; 6 not reached (budget) bob 7 script");
  assert.match(r.summary, /Findings: 3 \(critical 0, high 1, medium 2, low 0, info 0\)/);
  assert.match(r.summary, /Why it stopped: The model provider dropped the connection bob 7 script/);
  assert.match(r.summary, /Tier: standard \(glob\)/);
  assert.match(r.summary, /Second opinion: 1 new, 2 already known, 1 left out/);
  const body = r.summary.replace(/^## .*$/m, "");
  for (const bad of ["RAW", "@", "#", "<"]) assert.ok(!body.includes(bad) && !r.outputs.coverage.includes(bad), bad);
});

test("out-of-scope results are counted apart in the summary", { skip: !hasJq }, () => {
  const f = fixture();
  const result = (severity, scope) => ({ ruleId: "x", level: "error", message: { text: "t" }, properties: { severity, ...(scope ? { scope } : {}) } });
  writeFileSync(f.sarif, JSON.stringify({ runs: [{ results: [result("high"), result("medium", "in-scope"), result("high", "out-of-scope"), result("low", "out-of-scope")], properties: { status: "complete" } }] }));
  const r = f.run("scan", { FAIL_ON: "high" });
  assert.match(r.summary, /Findings: 2 \(critical 0, high 1, medium 1, low 0, info 0\)/);
  assert.match(r.summary, /Outside declared scope: 2 \(listed in the report, not counted above/);
});

test("a missing report is status failed", () => {
  const f = fixture();
  const r = f.run("scan", { FAKE_SARIF: "/nonexistent", FAKE_EXIT: "2" });
  assert.equal(r.outputs.status, "failed");
  assert.equal(r.outputs.code, "2");
});

test("status maps skipped and prepass_only", { skip: !hasJq }, () => {
  const f = fixture();
  for (const status of ["skipped", "prepass_only", "complete", "failed"]) {
    writeFileSync(f.sarif, JSON.stringify({ runs: [{ results: [], properties: { status } }] }));
    assert.equal(f.run("scan", {}).outputs.status, status);
  }
});

test("result step: partial fails unless allow-partial lets the scan exit 0", () => {
  const f = fixture();
  let r = f.run("result", { CODE: "3", STATUS: "partial", MODE: "scan" });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /allow-partial/);
  r = f.run("result", { CODE: "0", STATUS: "partial", MODE: "scan" });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /::warning::/);
  r = f.run("result", { CODE: "1", STATUS: "complete", MODE: "scan" });
  assert.equal(r.status, 1);
  r = f.run("result", { CODE: "0", STATUS: "complete", MODE: "scan" });
  assert.equal(r.status, 0);
  r = f.run("result", { CODE: "0", STATUS: "skipped", MODE: "scan" });
  assert.equal(r.status, 0);
});

test("sbom mode generates, checks and applies the license preset", () => {
  const f = fixture();
  const r = f.run("sbom", { LICENSES_PRESET: "no-copyleft" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const c = calls(r.argv);
  assert.deepEqual(c.map(a => a.slice(0, 2)), [["sbom", "generate"], ["sbom", "check"], ["sbom", "licenses"]]);
  assert.ok(c[1].includes("sarif") && c[2].includes("no-copyleft"));
  assert.ok(r.outputs.sbom.endsWith("sbom.cdx.json"));
  assert.equal(r.outputs.status, "complete");
});

test("sbom mode result: advisories warn unless fail-on is set; license violations fail", () => {
  const f = fixture();
  assert.equal(f.run("sbom", { FAKE_CHECK_EXIT: "1" }).outputs["advisories-code"], "1");
  let r = f.run("result", { MODE: "sbom", CODE: "1", ADVISORIES_CODE: "1" });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /::warning::/);
  r = f.run("result", { MODE: "sbom", CODE: "1", ADVISORIES_CODE: "1", FAIL_ON: "high" });
  assert.equal(r.status, 1);
  r = f.run("result", { MODE: "sbom", CODE: "1", LICENSES_CODE: "1" });
  assert.equal(r.status, 1);
  r = f.run("sbom", { LICENSES_PRESET: "gpl" });
  assert.equal(r.status, 2);
  r = f.run("sbom", { FAKE_GEN_EXIT: "2" });
  assert.equal(r.outputs.code, "2");
});

test("a base branch that is already fetched needs no network or credentials", () => {
  const f = fixture();
  git(f.ws, "init", "-q", "-b", "main");
  git(f.ws, "add", "-A");
  git(f.ws, "commit", "-qm", "init");
  git(f.ws, "update-ref", "refs/remotes/origin/main", "HEAD");
  const r = f.run("scan", { GITHUB_BASE_REF: "main", GITHUB_EVENT_NAME: "pull_request" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const [argv] = calls(r.argv);
  assert.equal(argv[argv.indexOf("--diff") + 1], "origin/main");
  const bad = f.run("scan", { GITHUB_BASE_REF: "--upload-pack=x" });
  assert.equal(bad.status, 2);
});
