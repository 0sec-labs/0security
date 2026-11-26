#!/usr/bin/env node
// Executed-PoC probe (not an A/B): does `findings reproduce` label a real model finding as executed-proven in Docker?
//   node scripts/bench/code-index/poc-probe.mjs --image node:24-bookworm-slim@sha256:<64 hex> [--fixture vulnerable|fixed] [--model gpt-6-luna]
// It copies scripts/bench/repro-fixtures/path-traversal/<fixture> into a scratch git repository, scans it with the real
// model, then runs `findings reproduce` on the path-traversal finding. Prints one JSON line. Needs a running Docker.
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultCli, git, isolatedEnv, repoRoot } from "../lib.mjs";

const arg = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : fallback; };
const image = arg("image"); const fixture = arg("fixture", "vulnerable"); const model = arg("model", "gpt-6-luna");
if (!image || !/@sha256:[0-9a-f]{64}$/.test(image)) { console.error("--image must be pinned by digest: name@sha256:<64 hex>"); process.exit(2); }
const docker = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" });
const root = mkdtempSync(join(tmpdir(), "0-poc-"));
const app = join(root, "app"); const home = join(root, "home");
cpSync(join(repoRoot, "scripts/bench/repro-fixtures/path-traversal", fixture), app, { recursive: true });
git(app, ["init", "-q"]); git(app, ["add", "-A"]); git(app, ["commit", "-q", "-m", "fixture"]);
const env = isolatedEnv(home);
env.ZERO_CODEX_AUTH_JSON_PATH = process.env.ZERO_CODEX_AUTH_JSON_PATH ?? join(process.env.HOME, ".codex", "auth.json");
const run = (args, t = 900) => spawnSync(process.execPath, [defaultCli, ...args], { env, cwd: repoRoot, encoding: "utf8", timeout: t * 1000 });
const out = join(root, "report.json");
const started = Date.now();
const scan = run(["scan", app, "--budget", "1", "--prepass", "off", "--model", model, "--format", "json", "-o", out]);
let report; try { report = JSON.parse(readFileSync(out, "utf8")); } catch { /* none */ }
const finding = (report?.findings ?? []).find((f) => /traversal/i.test(`${f.category} ${f.title}`));
const result = { dockerServer: docker.status === 0 ? docker.stdout.trim() : null, image, fixture, scanStatus: report?.status ?? `no-report (exit ${scan.status})`, scanSeconds: (Date.now() - started) / 1000, findings: (report?.findings ?? []).map((f) => ({ title: f.title, category: f.category, hasProposedSteps: Boolean(f.pocSteps ?? f.reproductionSteps ?? f.poc) })), traversalFinding: Boolean(finding) };
if (finding) {
  const list = run(["findings", "list", "--format", "json"], 60);
  let id; try { id = JSON.parse(list.stdout).findings.find((f) => /traversal/i.test(`${f.category} ${f.title}`))?.id; } catch { /* below */ }
  if (id) {
    const rep = run(["findings", "reproduce", id, "--image", image, "--folder", app, "--format", "json"], 600);
    result.reproduceExit = rep.status;
    try { result.reproduce = JSON.parse(rep.stdout); } catch { result.reproduceText = `${rep.stdout}${rep.stderr}`.replace(/\s+/g, " ").slice(0, 600); }
    // The second route to an executed label: verify runs the proposed steps itself when ZERO_POC_IMAGE names the image.
    const verifyEnv = { ...env, ZERO_POC_IMAGE: image };
    const ver = spawnSync(process.execPath, [defaultCli, "findings", "verify", id, "--folder", app, "--model", model, "--no-variants", "--format", "json"], { env: verifyEnv, cwd: repoRoot, encoding: "utf8", timeout: 900000 });
    result.verifyExit = ver.status;
    try { const v = JSON.parse(ver.stdout); result.verify = { verdicts: v.results ?? v.findings ?? undefined, keys: Object.keys(v) }; } catch { result.verifyText = `${ver.stdout}${ver.stderr}`.replace(/\s+/g, " ").slice(0, 500); }
    const shown = run(["findings", "show", id, "--format", "json"], 60);
    try { const s = JSON.parse(shown.stdout); result.executedPoc = s.executedPoc ?? null; result.reproduction = s.reproduction ?? null; } catch { /* none */ }
  } else result.note = "finding not found in the findings database";
}
writeFileSync(join(root, "poc-result.json"), JSON.stringify(result));
console.log(JSON.stringify(result));
