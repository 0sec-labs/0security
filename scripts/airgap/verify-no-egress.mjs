#!/usr/bin/env node
/**
 * Checks that 0 makes no outbound connection with ZERO_ENTERPRISE=1, by running the real CLI.
 *
 *   node scripts/airgap/verify-no-egress.mjs [--cli packages/cli/dist/index.js] [--json]
 *
 * A recorder is preloaded into every run (scripts/airgap/egress-recorder.cjs). It records and
 * refuses any socket, name lookup, fetch or network launcher that is not loopback. The model
 * endpoint is a stub server on 127.0.0.1, so a one-shot prompt completes without leaving the host.
 *
 * The run fails when
 *  - a run with ZERO_ENTERPRISE=1 attempts any non-loopback connection;
 *  - a command that the switch must refuse does not refuse;
 *  - the control run (switch off) records no attempt, which would mean the recorder sees nothing.
 *
 * It needs the Node build of the CLI. The compiled standalone binary does not read NODE_OPTIONS.
 * For the strongest check, also run it in a container with no network: see docs, "Air-gapped".
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const cli = resolve(option("--cli", join(here, "..", "..", "packages", "cli", "dist", "index.js")));
const recorder = join(here, "egress-recorder.cjs");
const TIMEOUT_MS = Number(option("--timeout", "90000"));

if (!existsSync(cli)) {
  console.error(`CLI not found at ${cli}. Build it first: pnpm --filter @0/engine build && pnpm --filter @0/cli build`);
  process.exit(2);
}

const work = mkdtempSync(join(tmpdir(), "0-airgap-"));
const fixture = join(work, "project");
mkdirSync(fixture);
writeFileSync(join(fixture, "package.json"), JSON.stringify({ name: "airgap-fixture", version: "1.0.0", dependencies: { left: "1.0.0" } }));
writeFileSync(join(fixture, "package-lock.json"), JSON.stringify({
  name: "airgap-fixture", version: "1.0.0", lockfileVersion: 3, requires: true,
  packages: { "": { name: "airgap-fixture", version: "1.0.0", dependencies: { left: "1.0.0" } }, "node_modules/left": { version: "1.0.0" } },
}));

// Stub model endpoint on loopback. Answers chat completions and responses with a fixed reply.
let modelRequests = 0;
const stub = createServer((req, res) => {
  modelRequests += 1;
  let body = "";
  req.on("data", (chunk) => { body += chunk; });
  req.on("end", () => {
    let wantsStream = false;
    try { wantsStream = JSON.parse(body).stream === true; } catch {}
    const responses = req.url?.endsWith("/responses");
    const usage = responses ? { input_tokens: 5, output_tokens: 1, total_tokens: 6 } : { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 };
    if (wantsStream) {
      res.setHeader("Content-Type", "text/event-stream");
      const send = (event, data) => res.write(`${event ? `event: ${event}\n` : ""}data: ${JSON.stringify(data)}\n\n`);
      if (responses) {
        const message = { id: "m1", type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "ready" }] };
        send("response.output_text.delta", { type: "response.output_text.delta", item_id: "m1", output_index: 0, content_index: 0, delta: "ready" });
        send("response.output_item.done", { type: "response.output_item.done", output_index: 0, item: message });
        send("response.completed", { type: "response.completed", response: { id: "r1", object: "response", status: "completed", model: "stub", output: [message], usage } });
      } else {
        send("", { id: "c1", object: "chat.completion.chunk", model: "stub", choices: [{ index: 0, delta: { role: "assistant", content: "ready" }, finish_reason: null }] });
        send("", { id: "c1", object: "chat.completion.chunk", model: "stub", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage });
        res.write("data: [DONE]\n\n");
      }
      res.end();
      return;
    }
    res.setHeader("Content-Type", "application/json");
    if (responses) {
      res.end(JSON.stringify({ id: "r1", object: "response", status: "completed", model: "stub",
        output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "ready" }] }], usage }));
    } else {
      res.end(JSON.stringify({ id: "c1", object: "chat.completion", model: "stub",
        choices: [{ index: 0, message: { role: "assistant", content: "ready" }, finish_reason: "stop" }], usage }));
    }
  });
});
await new Promise((ready) => stub.listen(0, "127.0.0.1", ready));
const port = stub.address().port;

function baseEnv(label, enterprise) {
  const home = join(work, `home-${label}`);
  mkdirSync(home, { recursive: true });
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    USERPROFILE: home,
    NODE_OPTIONS: `--require ${recorder}`,
    AIRGAP_LOG: join(work, `${label}.jsonl`),
    OPENAI_API_KEY: "synthetic-airgap-key",
    OPENAI_BASE_URL: `http://127.0.0.1:${port}/v1`,
    ZERO_SELECTED_PROVIDER: "openai",
    ZERO_MODEL: "stub",
    CI: "1",
  };
  if (enterprise) env.ZERO_ENTERPRISE = "1";
  return env;
}

function run(label, argv, { enterprise = true } = {}) {
  const env = baseEnv(label, enterprise);
  return new Promise((done) => {
    const child = spawn(process.execPath, [cli, ...argv], { env, cwd: fixture, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), TIMEOUT_MS);
    child.on("close", (status, signal) => {
      clearTimeout(timer);
      const log = existsSync(env.AIRGAP_LOG) ? readFileSync(env.AIRGAP_LOG, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
      done({ label, status, signal, output, attempts: log });
    });
  });
}

const scenarios = [
  { label: "version", argv: ["--version"], expect: (r) => r.status === 0 },
  { label: "sbom-generate", argv: ["sbom", "generate", ".", "--format", "cyclonedx", "--output", join(work, "sbom.json")], expect: (r) => r.status === 0 && existsSync(join(work, "sbom.json")) },
  { label: "one-shot-prompt", argv: ["-p", "Reply with the word ready"], expect: (r) => r.status === 0 && modelRequests > 0 },
  { label: "sbom-check-refused", argv: ["sbom", "check", join(work, "sbom.json")], expect: (r) => r.status !== 0 && /ZERO_ENTERPRISE/.test(r.output) },
  { label: "upgrade-refused", argv: ["doctor", "upgrade"], expect: (r) => r.status !== 0 && /disabled|ZERO_ENTERPRISE/i.test(r.output) },
];

const rows = [];
let failed = false;
for (const scenario of scenarios) {
  const result = await run(scenario.label, scenario.argv);
  const leaked = result.attempts.filter((attempt) => attempt.blocked);
  const behaved = scenario.expect(result);
  if (leaked.length > 0 || !behaved) failed = true;
  rows.push({ scenario: scenario.label, exit: result.status, behaved, attempts: leaked.map((a) => `${a.kind} ${a.target}`), tail: behaved ? "" : result.output.split("\n").slice(-6).join("\n") });
}

// Control: the same advisory lookup with the switch off must be seen by the recorder.
const control = await run("control", ["sbom", "check", join(work, "sbom.json")], { enterprise: false });
const controlSeen = control.attempts.some((attempt) => attempt.blocked);
if (!controlSeen) failed = true;
stub.close();

if (flag("--json")) {
  console.log(JSON.stringify({ ok: !failed, rows, control: { seen: controlSeen, attempts: control.attempts } }, null, 2));
} else {
  console.log("No-egress check with ZERO_ENTERPRISE=1 (non-loopback attempts are recorded and refused)\n");
  for (const row of rows) {
    const verdict = row.attempts.length === 0 && row.behaved ? "ok  " : "FAIL";
    console.log(`${verdict} ${row.scenario.padEnd(20)} exit ${String(row.exit).padEnd(4)} attempts: ${row.attempts.length === 0 ? "none" : row.attempts.join(", ")}`);
    if (row.tail) console.log(row.tail.replace(/^/gm, "     "));
  }
  console.log(`${controlSeen ? "ok  " : "FAIL"} control (switch off)   recorder saw ${control.attempts.length} attempt(s): ${control.attempts.map((a) => `${a.kind} ${a.target}`).join(", ") || "none"}`);
  console.log(failed ? "\nFAILED: 0 attempted a connection that the switch should have prevented, or a check did not run as expected." : "\nPASSED: no non-loopback connection was attempted with ZERO_ENTERPRISE=1.");
}
process.exit(failed ? 1 : 0);
