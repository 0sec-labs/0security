#!/usr/bin/env node
// Release pins in the docs (image tags, the GitHub Action `version:`, the compose example) must equal the CLI
// version in packages/cli/package.json, or use `latest`. The release commit runs `node scripts/bump-docs-pins.mjs <version>`
// to rewrite them; `--check` (wired into `pnpm docs:check`) fails when one lags behind.
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, relative } from "node:path";

const SKIP_FILES = new Set(["changelog.md"]);
// Each rule captures a prefix, then a version of `parts` numeric components (3 = X.Y.Z, 2 = the X.Y image tag).
const RULES = [
  { re: /(0sec-labs\/0security:v?)(\d+\.\d+\.\d+)(?![\d.])/g, parts: 3 },
  { re: /(0sec-labs\/0security:v?)(\d+\.\d+)(?![\d.])/g, parts: 2 },
  { re: /(ZERO_IMAGE_TAG=v?)(\d+\.\d+\.\d+)(?![\d.])/g, parts: 3 },
  { re: /(version:\s*v?)(\d+\.\d+\.\d+)(?=\s*#\s*Pin the CLI)/g, parts: 3 },
  { re: /(\bVERSION\s*[=:]\s*['"]?)(\d+\.\d+\.\d+)(?=['"]?\s*(?:#|\/\/)\s*Pin the CLI)/g, parts: 3 },
  { re: /(0sec-labs\/0security@v)(\d+\.\d+\.\d+)(?![\d.])/g, parts: 3 },
];

export function cliVersion(root) {
  return JSON.parse(readFileSync(join(root, "packages/cli/package.json"), "utf8")).version;
}

export function pinFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.mdx?$/.test(name) && !SKIP_FILES.has(name.toLowerCase())) out.push(path);
    }
  };
  walk(join(root, "docs/src/content/docs"));
  for (const name of ["bitbucket-pipelines.yml", "azure-pipelines.yml", "gitlab-ci.yml", "Jenkinsfile"]) {
    if (existsSync(join(root, "ci", name))) out.push(join(root, "ci", name));
  }
  for (const extra of ["README.md", "packages/cli/README.md", "deploy/compose/.env.example", "deploy/compose/README.md"]) {
    if (existsSync(join(root, extra))) out.push(join(root, extra));
  }
  return out;
}

const wanted = (version, parts) => version.split(".").slice(0, parts).join(".");

export function rewrite(text, version) {
  let next = text;
  for (const { re, parts } of RULES) next = next.replace(re, (_, prefix) => `${prefix}${wanted(version, parts)}`);
  return next;
}

export function findStale(root, version = cliVersion(root)) {
  const stale = [];
  for (const file of pinFiles(root)) {
    const text = readFileSync(file, "utf8");
    if (rewrite(text, version) === text) continue;
    text.split("\n").forEach((line, i) => { if (rewrite(line, version) !== line) stale.push(`${relative(root, file)}:${i + 1}: ${line.trim()}`); });
  }
  return stale;
}

// CI templates fetch install.sh and the helper scripts by release tag and check each against a SHA-256 written in the
// template (`fetch <path> <sha256>`, or `echo "<sha256>  $RUNNER_TEMP/install.sh"`). checksums.txt covers only binaries.
const DIGEST_LINES = [
  /^(\s*(?:- )?fetch )([\w./-]+)( )([0-9a-f]{64})(\s*)$/,
  /^(\s*echo ")([0-9a-f]{64})(  \$RUNNER_TEMP\/)(install\.sh)(" \| sha256sum --check -\s*)$/,
];
const digestOf = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Every pinned digest in a text: { line (0-based), path, hex, version (nearest VERSION pin above, if any) }. */
export function digestPins(text) {
  const pins = []; let version = null;
  text.split("\n").forEach((line, line_) => {
    const v = line.match(/\bVERSION\s*[=:]\s*['"]?(\d+\.\d+\.\d+)/); if (v) version = v[1];
    let m = line.match(DIGEST_LINES[0]); if (m) return pins.push({ line: line_, path: m[2], hex: m[4], version });
    m = line.match(DIGEST_LINES[1]); if (m) pins.push({ line: line_, path: m[4], hex: m[2], version });
  });
  return pins;
}

function rewriteDigests(text, digest) {
  const lines = text.split("\n");
  for (const pin of digestPins(text)) lines[pin.line] = lines[pin.line].replaceAll(pin.hex, digest(pin.path));
  return lines.join("\n");
}

/** The bytes of `path` at tag v<version>; falls back to the working tree only for the version being released. */
function fileAtTag(root, path, version, current) {
  try {
    return execFileSync("git", ["show", `v${version}:${path}`], { cwd: root, stdio: ["ignore", "pipe", "ignore"], maxBuffer: 1 << 26 });
  } catch {
    if (version === current) return readFileSync(join(root, path));
    return null;
  }
}

export function findStaleDigests(root, current = cliVersion(root)) {
  const stale = [];
  for (const file of pinFiles(root)) {
    for (const pin of digestPins(readFileSync(file, "utf8"))) {
      const where = `${relative(root, file)}:${pin.line + 1}: ${pin.path}`;
      const bytes = pin.version ? fileAtTag(root, pin.path, pin.version, current) : null;
      if (!bytes) stale.push(`${where}: tag v${pin.version} not available locally (git fetch --tags)`);
      else if (digestOf(bytes) !== pin.hex) stale.push(`${where}: pinned ${pin.hex.slice(0, 12)}, file at v${pin.version} is ${digestOf(bytes).slice(0, 12)}`);
    }
  }
  return stale;
}

export function bump(root, version) {
  const changed = [];
  const digest = (path) => digestOf(readFileSync(join(root, path)));
  for (const file of pinFiles(root)) {
    const text = readFileSync(file, "utf8"), next = rewriteDigests(rewrite(text, version), digest);
    if (next !== text) { writeFileSync(file, next); changed.push(relative(root, file)); }
  }
  return changed;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const root = join(import.meta.dirname, "..");
  const args = process.argv.slice(2);
  if (args.includes("--check")) {
    const version = cliVersion(root), stale = findStale(root, version), badDigests = findStaleDigests(root, version);
    if (badDigests.length) {
      console.error("pinned script digests in the CI templates and docs must equal the file at the pinned tag; after a release run: node scripts/bump-docs-pins.mjs " + version);
      for (const line of badDigests) console.error(`  ${line}`);
      process.exit(1);
    }
    if (stale.length) {
      console.error(`docs pins must equal the CLI version ${version} (or use latest); run: node scripts/bump-docs-pins.mjs ${version}`);
      for (const line of stale) console.error(`  ${line}`);
      process.exit(1);
    }
    console.log(`bump-docs-pins: ok (${version})`);
  } else {
    const version = args[0]?.replace(/^v/, "");
    if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) { console.error("usage: node scripts/bump-docs-pins.mjs <x.y.z> | --check"); process.exit(2); }
    const changed = bump(root, version);
    console.log(changed.length ? `updated ${version} pins in:\n${changed.map((f) => `  ${f}`).join("\n")}` : `pins already at ${version}`);
  }
}
