#!/usr/bin/env node
/**
 * Keeps the outbound-network inventory honest.
 *
 *   node scripts/check-egress-inventory.mjs
 *
 * Fails when
 *  - (Rust) a Rust file under the crates folders builds an HTTP client and is not listed;
 *  - a non-test source file under packages/engine, packages/cli or packages/bench matches an outbound pattern
 *    (fetch, node:http(s) request/get, gh/curl/ssh processes, git network subcommands, sockets) and is not listed
 *    under `files` in scripts/egress-inventory.json;
 *  - an inventory file no longer exists or no longer matches a pattern (stale entry);
 *  - a source file contains an https:// host literal that is not in `knownHosts`;
 *  - a destination host in the inventory, or any entry in `knownHosts` marked as contacted, is missing from the
 *    data-flow docs page.
 * Add the call site to the inventory, and its destination to the docs page, in the same change.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const INVENTORY = "scripts/egress-inventory.json";
const DOCS_PAGE = "docs/src/content/docs/data-flow.md";
const PACKAGES = ["engine", "cli", "bench"];

export const OUTBOUND_PATTERNS = {
  fetch: /(?<![\w.#])(?:fetch|fetchImpl|doFetch|fetcher|fetchScoped|createPolicyFetch)\((?!\))|\?\? fetch\b|\bglobalThis\.fetch\b|this\.#?(?:fetchImpl|fetch)\(|\.fetchImpl\(/,
  nodeHttp: /import\s+(?!type)[^;]*\b(?:request|get)\b[^;]*from "node:https?"/,
  socket: /\bnet\.connect|createConnection|new WebSocket|new EventSource|XMLHttpRequest/,
  process: /(?:spawn|execFile|execFileSync|spawnSync|execute|run|exec)\w*\(\s*"(?:gh|curl|wget|ssh|scp|mvn|gradle|docker)"/,
  gitNetwork: /"(?:clone|ls-remote|fetch|push|pull)"/,
  scannerProcess: /\bnucleiArguments\(/,
  // A connection to a database server the operator names (enterprise/src/ha).
  database: /import\s+(?!type)[^;]*from "pg"/,
  // An HTTP client built in the Rust crates (crates/*/src).
  rustHttp: /reqwest::(?:blocking::)?(?:Client::(?:builder|new)\(|get\()/,
};

const isSource = path => /\.(ts|tsx|mjs)$/.test(path) && !/\.test\.|\.d\.ts|\.generated\.|[\\/](?:__tests__|test|tests|scripts)[\\/]/.test(path);

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist" || name.startsWith(".")) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (isSource(path)) out.push(path);
  }
  return out;
}

export function sourceFiles(root = ROOT) {
  return PACKAGES.flatMap(pkg => walk(join(root, "packages", pkg, "src"))).map(path => relative(root, path).split(sep).join("/"));
}

/** Outbound calls are also looked for in the key-gated folder. Its XML namespace URLs are not hosts that are contacted, so hosts are not scanned there. */
function walkRust(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walkRust(path, out);
    else if (name.endsWith(".rs")) out.push(path);
  }
  return out;
}

function outboundFiles(root = ROOT) {
  const rust = existsSync(join(root, "crates")) ? readdirSync(join(root, "crates")).flatMap(crate => walkRust(join(root, "crates", crate, "src"))) : [];
  const rel = path => relative(root, path).split(sep).join("/");
  return [...sourceFiles(root), ...walk(join(root, "enterprise", "src")).map(rel), ...rust.map(rel)];
}

const strip = text => text.split("\n").filter(line => !/^\s*(?:\/\/|\*|\/\*)/.test(line)).join("\n");

/** Files with an outbound pattern, mapped to the pattern names that matched. */
export function scanOutbound(root = ROOT) {
  const found = new Map();
  for (const file of outboundFiles(root)) {
    const text = strip(readFileSync(join(root, file), "utf8"));
    // Rust files carry rule patterns written as text, so only the Rust client pattern applies to them.
    const patterns = file.endsWith(".rs") ? Object.entries(OUTBOUND_PATTERNS).filter(([name]) => name === "rustHttp") : Object.entries(OUTBOUND_PATTERNS).filter(([name]) => name !== "rustHttp");
    const hits = patterns.filter(([, re]) => re.test(text)).map(([name]) => name);
    if (hits.length) found.set(file, hits);
  }
  return found;
}

const HOST_LITERAL = /https?:\/\/([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?=[/:"'`?#\s)]|$)/gi;

/** Hosts written as string literals in code (comments skipped). */
export function scanHosts(root = ROOT) {
  const hosts = new Map();
  for (const file of sourceFiles(root)) {
    for (const match of strip(readFileSync(join(root, file), "utf8")).matchAll(HOST_LITERAL)) {
      const host = match[1].toLowerCase();
      if (/\.(?:invalid|test|example)$|^(?:[\w-]+\.)?example\.(?:com|org)$/.test(host)) continue; // reserved names used in fixtures and examples
      if (!hosts.has(host)) hosts.set(host, new Set());
      hosts.get(host).add(file);
    }
  }
  return hosts;
}

const hostsIn = text => [...text.matchAll(/[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,}/gi)].map(m => m[0].toLowerCase());

export function checkInventory(root = ROOT) {
  const problems = [];
  const inventory = JSON.parse(readFileSync(join(root, INVENTORY), "utf8"));
  const registered = new Set();
  for (const entry of inventory.entries) for (const file of entry.files) registered.add(file);
  const found = scanOutbound(root);

  for (const [file, hits] of found) {
    if (!registered.has(file)) problems.push(`${file} makes an outbound call (${hits.join(", ")}) but is not in ${INVENTORY}. Add it with its destination, trigger, payload and how ZERO_NO_EGRESS (alias ZERO_ENTERPRISE) treats it.`);
  }
  for (const file of registered) {
    if (!existsSync(join(root, file))) problems.push(`${INVENTORY} lists ${file}, which does not exist.`);
    else if (!found.has(file)) problems.push(`${INVENTORY} lists ${file}, but it no longer matches an outbound pattern. Remove the stale entry.`);
  }

  const known = new Set(inventory.knownHosts.map(host => host.toLowerCase()));
  for (const [host, files] of scanHosts(root)) {
    if (!known.has(host)) problems.push(`Host ${host} appears in code (${[...files].slice(0, 2).join(", ")}) but not in knownHosts of ${INVENTORY}. Decide whether it is contacted; if so register the call site and document it.`);
  }

  const docs = existsSync(join(root, DOCS_PAGE)) ? readFileSync(join(root, DOCS_PAGE), "utf8").toLowerCase() : "";
  if (!docs) problems.push(`${DOCS_PAGE} is missing.`);
  for (const entry of inventory.entries) {
    if (!docs.includes(`\`${entry.id}\``)) problems.push(`${DOCS_PAGE} does not mention inventory entry \`${entry.id}\`.`);
    for (const host of entry.destinations.flatMap(hostsIn)) {
      if (!docs.includes(host)) problems.push(`${DOCS_PAGE} does not list ${host} (entry ${entry.id}).`);
    }
  }
  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const problems = checkInventory();
  if (problems.length) {
    console.error(problems.map(p => `egress inventory: ${p}`).join("\n"));
    process.exit(1);
  }
  console.log("egress inventory check passed");
}
