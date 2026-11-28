// Tests for the CI recipes in ci/: the two shell scripts run for real with a stand-in `0security` that records its
// arguments, and the pipeline templates are checked for pins, secret placement and agreement with the docs.
// No network, no model, no Bitbucket.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { digestPins, findStaleDigests } from "./bump-docs-pins.mjs";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const repo = new URL("..", import.meta.url).pathname;
const scan = join(repo, "ci/scripts/0-ci-scan.sh");
const publish = join(repo, "ci/scripts/0-ci-publish.sh");
const { parse } = createRequire(join(repo, "packages/cli/package.json"))("yaml");
const cliVersion = JSON.parse(readFileSync(join(repo, "packages/cli/package.json"), "utf8")).version;
const read = (path) => readFileSync(join(repo, path), "utf8");

const gitEnv = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" };
const git = (cwd, ...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], { cwd, env: gitEnv, encoding: "utf8" }).trim();

/** A stand-in for `0security`: logs its arguments and the token it saw, exits with FAKE_EXIT (default 0), writes the -o file for scans. */
function fakeBin(dir) {
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "0security"), [
    "#!/bin/sh",
    'printf "%s\\n" "$*" >> "$FAKE_LOG"',
    'printf "token=%s\\n" "${BITBUCKET_TOKEN:-none}" >> "$FAKE_LOG"',
    'if [ "$1" = scan ]; then while [ $# -gt 0 ]; do [ "$1" = "-o" ] && echo \'{"findings":[]}\' > "$2"; shift; done; exit "${FAKE_SCAN_EXIT:-0}"; fi',
    'exit "${FAKE_UPLOAD_EXIT:-0}"',
  ].join("\n"));
  chmodSync(join(bin, "0security"), 0o755);
  return bin;
}

/** A clone whose origin has `main`, with the checkout on a feature commit or on a merge commit. */
function checkout({ merge = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "0-ci-test-"));
  const origin = join(root, "origin");
  git(root, "init", "-q", "-b", "main", origin);
  writeFileSync(join(origin, "a.txt"), "a\n");
  git(origin, "add", ".");
  git(origin, "commit", "-q", "-m", "base");
  const work = join(root, "work");
  git(root, "clone", "-q", origin, work);
  git(work, "checkout", "-q", "-b", "feature");
  writeFileSync(join(work, "b.txt"), "b\n");
  git(work, "add", ".");
  git(work, "commit", "-q", "-m", "feature");
  const head = git(work, "rev-parse", "HEAD");
  let mergeCommit;
  if (merge) {
    // What a CI that builds the merge of the pull request with its target checks out.
    git(work, "checkout", "-q", "--detach", "origin/main");
    git(work, "merge", "-q", "--no-ff", "-m", "merge", "feature");
    mergeCommit = git(work, "rev-parse", "HEAD");
  }
  return { root, work, head, mergeCommit, bin: fakeBin(root), log: join(root, "log.txt") };
}

const run = (script, env, cwd) => spawnSync("sh", [script], { cwd, env: { ...gitEnv, ...env }, encoding: "utf8" });
const logOf = (path) => (existsSync(path) ? readFileSync(path, "utf8") : "");

test("scan writes the report files and passes the right arguments", () => {
  const c = checkout();
  const out = join(c.root, "out");
  const result = run(scan, { PATH: `${c.bin}:${process.env.PATH}`, FAKE_LOG: c.log, ZEROCI_BASE_BRANCH: "main", ZEROCI_OUT_DIR: out, ZEROCI_FAIL_ON: "medium", ZEROCI_BUDGET: "1.5" }, c.work);
  assert.equal(result.status, 0, result.stderr);
  assert.match(logOf(c.log), new RegExp(`scan \\. --diff origin/main --format json -o ${out}/scan.json --fail-on medium --budget 1.5`));
  assert.equal(readFileSync(join(out, "scan.exit"), "utf8").trim(), "0");
  assert.equal(readFileSync(join(out, "scan.commit"), "utf8").trim(), c.head);
  assert.ok(existsSync(join(out, "scan.json")));
});

test("scan keeps the scan's exit code in a file and still exits 0, unless asked to pass it on", () => {
  for (const [code, passed] of [["1", "1"], ["3", "0"], ["0", "0"]]) {
    const c = checkout();
    const out = join(c.root, "out");
    const base = { PATH: `${c.bin}:${process.env.PATH}`, FAKE_LOG: c.log, ZEROCI_BASE_BRANCH: "main", ZEROCI_OUT_DIR: out, FAKE_SCAN_EXIT: code };
    assert.equal(run(scan, base, c.work).status, 0);
    assert.equal(readFileSync(join(out, "scan.exit"), "utf8").trim(), code);
    assert.equal(run(scan, { ...base, ZEROCI_EXIT_WITH_RESULT: "1" }, c.work).status, Number(passed), `exit ${code}`);
  }
});

test("scan reports the pull request's own commit when the checkout is a merge commit", () => {
  const c = checkout({ merge: true });
  assert.notEqual(c.mergeCommit, c.head);
  const out = join(c.root, "out");
  assert.equal(run(scan, { PATH: `${c.bin}:${process.env.PATH}`, FAKE_LOG: c.log, ZEROCI_BASE_BRANCH: "main", ZEROCI_OUT_DIR: out }, c.work).status, 0);
  assert.equal(readFileSync(join(out, "scan.commit"), "utf8").trim(), c.head);
  // An explicit commit wins.
  const explicit = "e".repeat(40);
  assert.equal(run(scan, { PATH: `${c.bin}:${process.env.PATH}`, FAKE_LOG: c.log, ZEROCI_BASE_BRANCH: "main", ZEROCI_OUT_DIR: out, ZEROCI_COMMIT: explicit }, c.work).status, 0);
  assert.equal(readFileSync(join(out, "scan.commit"), "utf8").trim(), explicit);
});

test("scan refuses unsafe settings before it runs anything", () => {
  const c = checkout();
  const env = { PATH: `${c.bin}:${process.env.PATH}`, FAKE_LOG: c.log, ZEROCI_OUT_DIR: join(c.root, "out") };
  const cases = [
    [{}, "ZEROCI_BASE_BRANCH"],
    [{ ZEROCI_BASE_BRANCH: "--upload-pack=x" }, "characters"],
    [{ ZEROCI_BASE_BRANCH: "main; echo hi" }, "characters"],
    [{ ZEROCI_BASE_BRANCH: "a..b" }, "characters"],
    [{ ZEROCI_BASE_BRANCH: "main", ZEROCI_FAIL_ON: "severe" }, "ZEROCI_FAIL_ON"],
    [{ ZEROCI_BASE_BRANCH: "main", ZEROCI_BUDGET: "1;2" }, "ZEROCI_BUDGET"],
    [{ ZEROCI_BASE_BRANCH: "main", ZEROCI_TARGET: "../outside" }, "ZEROCI_TARGET"],
    [{ ZEROCI_BASE_BRANCH: "main", ZEROCI_COMMIT: "abc" }, "40-character"],
  ];
  for (const [extra, message] of cases) {
    const result = run(scan, { ...env, ...extra }, c.work);
    assert.equal(result.status, 2, JSON.stringify(extra));
    assert.ok(result.stderr.includes(message), `${JSON.stringify(extra)}: ${result.stderr}`);
  }
  assert.equal(logOf(c.log), "");
});

function published(files, env) {
  const root = mkdtempSync(join(tmpdir(), "0-ci-publish-"));
  const out = join(root, "out");
  mkdirSync(out);
  for (const [name, content] of Object.entries(files)) writeFileSync(join(out, name), content);
  const bin = fakeBin(root);
  const log = join(root, "log.txt");
  const result = run(publish, { PATH: `${bin}:${process.env.PATH}`, FAKE_LOG: log, ZEROCI_OUT_DIR: out, ...env }, root);
  return { result, log: logOf(log), out };
}
const COMMIT = "c".repeat(40);
const good = { "scan.json": '{"findings":[]}', "scan.exit": "0\n", "scan.commit": `${COMMIT}\n` };

test("publish sends the report for the recorded commit", () => {
  const cloud = published(good, { BITBUCKET_TOKEN: "t".repeat(20), ZEROCI_REPO: "ws/repo" });
  assert.equal(cloud.result.status, 0, cloud.result.stderr);
  assert.match(cloud.log, new RegExp(`findings upload ${cloud.out}/scan.json --to bitbucket-cloud --commit ${COMMIT} --repo ws/repo`));
  const dc = published(good, { BITBUCKET_TOKEN: "t".repeat(20), ZEROCI_UPLOAD_TO: "bitbucket-dc", ZEROCI_REPO: "PROJ/repo", BITBUCKET_URL: "https://bitbucket.example.com" });
  assert.match(dc.log, /--to bitbucket-dc .* --repo PROJ\/repo --url https:\/\/bitbucket.example.com/);
  assert.ok(!cloud.result.stdout.includes("t".repeat(20)) && !cloud.result.stderr.includes("t".repeat(20)));
});

test("publish exits with the scan's result, and 3 (partial) passes", () => {
  for (const [code, want] of [["0", 0], ["1", 1], ["3", 0]]) {
    const run1 = published({ ...good, "scan.exit": `${code}\n` }, { BITBUCKET_TOKEN: "t".repeat(20) });
    assert.equal(run1.result.status, want, `scan exit ${code}`);
    assert.match(run1.log, /findings upload/, `scan exit ${code} still publishes`);
  }
});

test("publish sends nothing after a usage error, or without a token", () => {
  const usage = published({ ...good, "scan.exit": "2\n" }, { BITBUCKET_TOKEN: "t".repeat(20) });
  assert.equal(usage.result.status, 2);
  assert.equal(usage.log, "");
  const none = published({ ...good, "scan.exit": "1\n" }, {});
  assert.equal(none.result.status, 1);
  assert.equal(none.log, "");
  assert.match(none.result.stderr, /BITBUCKET_TOKEN is not set/);
});

test("publish refuses files it did not expect, and fails when the upload fails", () => {
  assert.equal(published({ ...good, "scan.commit": "main\n" }, { BITBUCKET_TOKEN: "t".repeat(20) }).result.status, 2);
  assert.equal(published({ ...good, "scan.exit": "9\n" }, { BITBUCKET_TOKEN: "t".repeat(20) }).result.status, 2);
  assert.equal(published({ "scan.json": "{}" }, { BITBUCKET_TOKEN: "t".repeat(20) }).result.status, 2);
  assert.equal(published(good, { BITBUCKET_TOKEN: "t".repeat(20), ZEROCI_UPLOAD_TO: "github" }).result.status, 2);
  assert.notEqual(published(good, { BITBUCKET_TOKEN: "t".repeat(20), FAKE_UPLOAD_EXIT: "1" }).result.status, 0);
});

test("both scripts are valid POSIX shell", () => {
  for (const script of [scan, publish]) assert.equal(spawnSync("sh", ["-n", script]).status, 0, script);
});

// ---- the templates ----

const templates = ["ci/bitbucket-pipelines.yml", "ci/azure-pipelines.yml", "ci/gitlab-ci.yml", "ci/Jenkinsfile"];

test("every template pins the CLI to this release and fetches only that tag", () => {
  for (const file of templates) {
    const text = read(file);
    assert.ok(new RegExp(`${cliVersion.replaceAll(".", "\\.")}['"]?\\s*(?:#|//) Pin the CLI`).test(text), `${file} pins ${cliVersion}`);
    for (const url of text.match(/https:\/\/[^\s"']+/g) ?? []) {
      assert.ok(/^https:\/\/(raw\.githubusercontent\.com\/0sec-labs\/0security\/v\$\{VERSION\}|github\.com\/0sec-labs\/0security\/releases\/download\/v\$\{VERSION\}|bitbucket\.example\.com)/.test(url), `${file}: ${url}`);
    }
    assert.ok(!/releases\/latest|\/main\//.test(text), `${file} does not follow latest or main`);
    assert.ok(!text.includes("${{"), `${file} has no expression interpolation`);
  }
});

test("the Bitbucket token is in the publish step only and the model key in the scan step only", () => {
  const pipelines = parse(read("ci/bitbucket-pipelines.yml"));
  const [scanStep, publishStep] = pipelines.pipelines["pull-requests"]["**"].map((entry) => entry.step);
  assert.equal(publishStep.deployment, "security-report");
  assert.ok(!JSON.stringify(scanStep).includes("BITBUCKET_TOKEN"));
  assert.ok(!JSON.stringify(publishStep).includes("OPENAI_API_KEY"));

  const azure = parse(read("ci/azure-pipelines.yml"));
  const [, azureScan, azurePublish] = azure.steps;
  assert.ok(azureScan.env.OPENAI_API_KEY && !azureScan.env.BITBUCKET_TOKEN);
  assert.ok(azurePublish.env.BITBUCKET_TOKEN && !azurePublish.env.OPENAI_API_KEY);
  assert.equal(azure.steps[0].persistCredentials, false);
  assert.equal(azurePublish.condition, "always()");
  assert.equal(azureScan.env.TARGET_BRANCH, "$(System.PullRequest.TargetBranch)");

  const jenkins = read("ci/Jenkinsfile");
  const [scanStage, publishStage] = [jenkins.slice(jenkins.indexOf("stage('scan')"), jenkins.indexOf("stage('publish')")), jenkins.slice(jenkins.indexOf("stage('publish')"))];
  assert.ok(scanStage.includes("openai-api-key") && !scanStage.includes("bitbucket-token"));
  assert.ok(publishStage.includes("bitbucket-token") && !publishStage.includes("openai-api-key"));
  assert.ok(!jenkins.includes('sh """'), "single-quoted sh keeps secrets out of Groovy interpolation");
});

test("templates call only scripts that exist, and the publish step does not run the checkout", () => {
  for (const file of templates) {
    for (const name of read(file).match(/ci\/scripts\/[\w.-]+\.sh/g) ?? []) assert.ok(existsSync(join(repo, name)), `${file} uses ${name}`);
  }
  for (const file of ["ci/bitbucket-pipelines.yml", "ci/azure-pipelines.yml", "ci/Jenkinsfile"]) {
    assert.ok(!/(?:^|\s)(?:\.\/|sh \.\/)/.test(read(file).split("0-ci-publish.sh")[1] ?? ""), `${file}: nothing from the checkout runs after publish starts`);
  }
});

test("the docs show every template as it is in ci/", () => {
  const docs = read("docs/src/content/docs/ci.md");
  for (const file of templates) {
    const body = read(file).trimEnd();
    assert.ok(docs.includes(`\n${body}\n`), `docs/src/content/docs/ci.md shows ${file} unchanged`);
  }
});

// ---- the test environment and the rehearsal ----

test("the test environment pins versions, binds to this machine and takes secrets from the environment", () => {
  const compose = parse(read("ci/test-env/docker-compose.yml"));
  for (const [name, service] of Object.entries(compose.services)) {
    assert.ok(/:[\w.-]+$/.test(service.image) && !service.image.endsWith(":latest"), `${name} pins an image tag`);
    for (const port of service.ports ?? []) assert.ok(String(port).startsWith("127.0.0.1:"), `${name} port ${port} is loopback only`);
  }
  assert.match(compose.services.bitbucket.image, /^atlassian\/bitbucket:9\./);
  assert.match(compose.services.jenkins.image, /^jenkins\/jenkins:\d+\.\d+\.\d+-lts/);
  const env = compose.services.bitbucket.environment;
  for (const name of ["SETUP_LICENSE", "SETUP_SYSADMIN_PASSWORD", "JDBC_PASSWORD"]) assert.match(env[name], /^\$\{[A-Z_]+:\?/, `${name} must come from the environment`);
});

/** `0security` and `curl` stand-ins; curl answers like Bitbucket Cloud would for a report with some annotations. */
function rehearsalBin(root, { annotations = 3 } = {}) {
  const bin = fakeBin(root);
  writeFileSync(join(bin, "curl"), [
    "#!/bin/sh",
    "cat > /dev/null",
    "for last; do :; done",
    'printf "%s\\n" "$last" >> "$FAKE_LOG"',
    `case "$last" in *annotations*) i=0; printf '{"values":['; while [ $i -lt ${annotations} ]; do [ $i -gt 0 ] && printf ','; printf '{"external_id":"x%s"}' $i; i=$((i+1)); done; printf ']}';; *) echo '{"result":"FAILED","report_type":"SECURITY"}';; esac`,
  ].join("\n"));
  chmodSync(join(bin, "curl"), 0o755);
  return bin;
}
const rehearse = (env, args = [], opts) => {
  const root = mkdtempSync(join(tmpdir(), "0-rehearsal-"));
  const bin = rehearsalBin(root, opts);
  const log = join(root, "log.txt");
  const result = spawnSync("sh", [join(repo, "ci/rehearsal/bitbucket-cloud.sh"), ...args], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_LOG: log, ...env }, encoding: "utf8" });
  return { result, log: logOf(log) };
};
const rehearsalEnv = { BITBUCKET_TOKEN: "r".repeat(20), REHEARSAL_REPO: "ws/test", REHEARSAL_COMMIT: "d".repeat(40) };

test("the rehearsal fixture holds three findings", () => {
  assert.equal(JSON.parse(read("ci/rehearsal/fixture-scan.json")).findings.length, 3);
});

test("the rehearsal passes when Bitbucket answers as documented, and fails when annotations are missing or doubled", () => {
  const pass = rehearse(rehearsalEnv);
  assert.equal(pass.result.status, 0, pass.result.stdout + pass.result.stderr);
  assert.match(pass.result.stdout, /Automatic checks: 5 passed, 0 failed/);
  assert.match(pass.result.stdout, /^Bitbucket Cloud rehearsal$/m);
  assert.doesNotMatch(pass.result.stdout, /not yet run against a live workspace/, "the script was validated against Bitbucket Cloud, so it must not claim otherwise");
  assert.match(pass.log, /findings upload .*fixture-scan.json --to bitbucket-cloud --repo ws\/test --commit d{40} --report-id 0-rehearsal/);
  assert.ok(!pass.result.stdout.includes("r".repeat(20)) && !pass.log.split("\n").filter((line) => !line.startsWith("token=")).join("\n").includes("r".repeat(20)), "the token is never printed or put in an argument");
  for (const annotations of [0, 6]) assert.equal(rehearse(rehearsalEnv, [], { annotations }).result.status, 1, `${annotations} annotations`);
});

test("the rehearsal checks its settings and can run dry", () => {
  assert.equal(rehearse({ ...rehearsalEnv, BITBUCKET_TOKEN: "" }).result.status, 2);
  assert.equal(rehearse({ ...rehearsalEnv, REHEARSAL_REPO: "norepo" }).result.status, 2);
  assert.equal(rehearse({ ...rehearsalEnv, REHEARSAL_COMMIT: "abc" }).result.status, 2);
  const dry = rehearse(rehearsalEnv, ["--dry-run"]);
  assert.equal(dry.result.status, 0);
  assert.equal(dry.log, "");
  assert.equal(spawnSync("sh", ["-n", join(repo, "ci/rehearsal/bitbucket-cloud.sh")]).status, 0);
});

// ---- pinned script digests ----

test("templates download scripts only through the checksummed fetch, and the pins match the files at the tag", () => {
  for (const file of templates) {
    const text = read(file);
    const curls = text.split("\n").filter((l) => /\bcurl\b/.test(l) && !l.includes("fetch() {"));
    assert.deepEqual(curls, [], `${file}: every download goes through fetch`);
    const pins = digestPins(text);
    assert.ok(pins.length >= 2, `${file} pins install.sh and a helper`);
    for (const pin of pins) assert.equal(pin.version, cliVersion, `${file}: ${pin.path} is pinned for the tag the template fetches`);
  }
  assert.deepEqual(findStaleDigests(repo), []);
});

test("fetch keeps a script whose digest matches and exits non-zero on a different one", () => {
  const fn = read("ci/gitlab-ci.yml").split("\n").find((l) => l.includes("fetch() {")).replace(/^\s*- /, "");
  const work = mkdtempSync(join(tmpdir(), "fetch-"));
  const bin = join(work, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "curl"), '#!/bin/sh\nwhile [ "$1" != -o ]; do shift; done\nprintf "script body\\n" > "$2"\n');
  chmodSync(join(bin, "curl"), 0o755);
  const good = createHash("sha256").update("script body\n").digest("hex");
  const run = (hex) => spawnSync("sh", ["-c", `${fn}\nRAW=https://example.invalid tools="${work}"\nfetch ci/scripts/x.sh ${hex}`], { encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
  assert.equal(run(good).status, 0);
  const bad = run("0".repeat(64));
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /checksum mismatch for ci\/scripts\/x\.sh/);
});
