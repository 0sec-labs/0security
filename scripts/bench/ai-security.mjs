#!/usr/bin/env node
// Deterministic AI-security detection benchmark: agent-config rules over a planted folder and its clean twin. No model call, no cost.
//   node scripts/bench/ai-security.mjs --detect            build the folders, scan them, print the score; exit 1 on a miss or a false positive
// The model-judged part runs through the normal runner: node scripts/bench/run.mjs --run --fixtures llm-app-2 --repeat 3
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "./fixtures/agent-config-repo/build.mjs";
import { renderDetection, scoreClean, scorePlanted } from "./ai-security-score.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
export const MANIFEST = join(here, "fixtures/agent-config-repo/manifest.json");

/** Builds the folders in a fresh temp directory and scans both with the compiled CLI. */
export function detect({ cli = join(repoRoot, "packages/cli/dist/index.js") } = {}) {
  const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
  const out = mkdtempSync(join(tmpdir(), "0-ai-bench-"));
  const made = build(join(out, "fixture"));
  const scan = (folder) => {
    const run = spawnSync(process.execPath, [cli, "sbom", "agent-config", folder, "--format", "json"], { encoding: "utf8", timeout: 120000 });
    if (run.status !== 0 && run.status !== 1) throw new Error(`sbom agent-config failed (exit ${run.status}): ${(run.stderr || "").slice(-300)}. Build the CLI first.`);
    // The text line before the JSON is not part of the report.
    const text = run.stdout;
    return JSON.parse(text.slice(text.indexOf("{"))).findings;
  };
  return { manifest, planted: scorePlanted(manifest, scan(made.planted)), clean: scoreClean(scan(made.clean)), folder: out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv.includes("--detect")) { console.error("usage: node scripts/bench/ai-security.mjs --detect"); process.exit(2); }
  const r = detect();
  console.log(renderDetection(r.planted, r.clean));
  process.exit(r.planted.recall === 1 && r.planted.falsePositives === 0 && r.clean.falsePositives === 0 ? 0 : 1);
}
