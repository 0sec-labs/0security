#!/usr/bin/env node
// Guard for the key-gated enterprise/ folder. Plain node, no dependencies.
//
//   1. Nothing outside enterprise/ imports from it, except the bridge files listed in ALLOWED_BRIDGES.
//   2. Every source file in enterprise/ starts with the license header line.
//   3. enterprise/package.json says "SEE LICENSE IN LICENSE", is private and has no publish settings;
//      enterprise/LICENSE exists.
//   4. No package manifest outside enterprise/ lists enterprise/ in "files", and no .npmignore or
//      .npmrc rule could pull it into an npm tarball.
//   6. No environment variable, outside tests, can add a trusted license signing key. The only variables the license
//      code may read are ZERO_LICENSE and ZERO_LICENSE_FILE, and no source file reads a variable whose name pairs
//      license, enterprise or trust with key, public or anchor.
//   5. The root LICENSE-MIT and LICENSE-APACHE do not mention enterprise/ (they must stay the plain
//      standard texts so GitHub keeps showing the Apache-2.0 license).
//   6. The lockfile resolves one @xmldom/xmldom line (major.minor) only. enterprise/src/saml/ guards
//      responses with the same XML parser that @node-saml/node-saml and xml-crypto verify signatures
//      with. Two parser versions would let the guard and the verifier read one text as two documents,
//      which is how signature-wrapping bypasses work. Move all of them together or none.
//   7. Released free features stay ungated. scripts/released-free-features.json lists features that shipped free
//      and the files that implement them. None of those files may call a license gate (requireFeature,
//      hasFeature, assertFeature, featureMode or a bridge wrapper such as evidenceSigningRefusal). Wrappers are
//      found by scanning the bridge files, so a new one is covered without editing this script.
//
// npm decision: enterprise/ is not published to npm. 0 ships as release binaries, install.sh and the
// container image; enterprise/ is compiled into those. Every manifest is private and `files` is
// forbidden everywhere (check-no-npm-publish.mjs), so no npm tarball exists to carry it.
//
// Usage: node scripts/check-enterprise-boundary.mjs [repo-root]
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

export const HEADER_MARKER = "enterprise/LICENSE";
export const LICENSE_FIELD = "SEE LICENSE IN LICENSE";

/**
 * Repo-relative files outside enterprise/ that may import it. Each one is a thin bridge that gates a
 * feature behind the license. Keep this list short; every entry is a place the licensed code meets
 * the open code.
 */
export const ALLOWED_BRIDGES = [
  "packages/cli/src/enterprise-bridge.ts", // `0security config get license`
  "packages/cli/vitest.setup.ts", // test setup: mocks the enterprise module so tests can trust throwaway keys
  "packages/cli/src/enterprise-bridge.test.ts", // checks the real module trusts only its compiled-in keys
  "packages/cli/src/findings-server-bridge.ts", // the shared findings server: ingest, write keys, org dashboard
  "packages/cli/src/ha-bridge.ts", // high availability: the shared database for server replicas
  "packages/cli/src/commands/__tests__/redteam-generate.test.ts", // test only: mocks the license loader to check the brain audience rule with throwaway keys
];

/** The only environment variables the license code reads, plus the unrelated no-egress switch. */
export const ALLOWED_LICENSE_ENV = new Set(["ZERO_LICENSE", "ZERO_LICENSE_FILE", "ZERO_NO_EGRESS", "ZERO_ENTERPRISE"]);

export const FREE_FEATURES_FILE = "scripts/released-free-features.json";

/** The functions in enterprise/src/license.ts that decide whether a licensed feature is on. */
export const BASE_GATES = ["requireFeature", "hasFeature", "assertFeature", "featureMode", "licenseHasFeature", "licenseFeatureMode"];

const SKIP_DIRS = new Set(["node_modules", "dist", "dist-bin", ".git", ".astro", ".claude", ".worktrees", ".cache", "vendor"]);
const CODE_EXT = /\.(?:[cm]?[jt]sx?)$/;
// This script and its test describe the rules and contain the strings they look for.
const SELF = new Set(["scripts/check-enterprise-boundary.mjs", "scripts/check-enterprise-boundary.test.mjs"]);

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) yield* walk(full);
    else if (st.isFile()) yield full;
  }
}

const toPosix = (p) => p.split(sep).join("/");

/** Module specifiers named by import, export-from, dynamic import and require. */
export function moduleSpecifiers(text) {
  const out = [];
  const re = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*(["'`])([^"'`\n]+)\1/g;
  for (let m = re.exec(text); m; m = re.exec(text)) out.push(m[2]);
  return out;
}

/** Distinct @xmldom/xmldom major.minor lines named anywhere in a pnpm lockfile text, sorted. */
export function xmldomLines(lockText) {
  const lines = new Set();
  for (const m of lockText.matchAll(/@xmldom\/xmldom'?(?:@|: )(\d+)\.(\d+)\.\d+/g)) lines.add(`${m[1]}.${m[2]}`);
  return [...lines].sort();
}

const stripComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
const isTestFile = (rel) => /\.test\.[cm]?[jt]sx?$/.test(rel) || rel.includes("__tests__/") || rel.includes("__fixtures__/");

/** Every license gate name: the base functions plus each function a bridge exports whose body calls one. */
export function gateNames(root, bridges = ALLOWED_BRIDGES) {
  const names = new Set(BASE_GATES);
  for (const bridge of bridges) {
    const file = join(root, bridge);
    if (!existsSync(file) || isTestFile(bridge) || /vitest\.setup/.test(bridge)) continue;
    const text = stripComments(readFileSync(file, "utf8"));
    for (const part of text.split(/^(?=export (?:async )?function )/m)) {
      const m = /^export (?:async )?function (\w+)/.exec(part);
      if (!m) continue;
      const end = part.search(/^}/m);
      const body = end < 0 ? part : part.slice(0, end + 1);
      if (BASE_GATES.some((g) => new RegExp(`\\b${g}\\b`).test(body))) names.add(m[1]);
    }
  }
  return names;
}

/** Errors for files of released free features that call a license gate. */
export function checkFreeFeatures(root, listPath = join(root, FREE_FEATURES_FILE), bridges = ALLOWED_BRIDGES) {
  const errors = [];
  if (!existsSync(listPath)) return [`${FREE_FEATURES_FILE} is missing. It lists the released free features and must exist.`];
  let list;
  try {
    list = JSON.parse(readFileSync(listPath, "utf8"));
  } catch (err) {
    return [`${FREE_FEATURES_FILE}: not valid JSON (${err.message}).`];
  }
  if (!Array.isArray(list.features) || list.features.length === 0) return [`${FREE_FEATURES_FILE}: "features" must be a non-empty array.`];
  const gates = gateNames(root, bridges);
  for (const feature of list.features) {
    const id = feature?.id ?? "(no id)";
    if (typeof feature?.id !== "string" || !Array.isArray(feature.paths) || feature.paths.length === 0) {
      errors.push(`${FREE_FEATURES_FILE}: feature ${id} needs an id and a non-empty paths array.`);
      continue;
    }
    const allowed = new Set(feature.allowedGates ?? []);
    for (const rel of feature.paths) {
      const target = join(root, rel);
      if (!existsSync(target)) {
        errors.push(`${FREE_FEATURES_FILE}: ${id} lists ${rel}, which does not exist. Fix the path; do not drop the feature from the list.`);
        continue;
      }
      const files = statSync(target).isDirectory() ? [...walk(target)] : [target];
      for (const file of files) {
        const fileRel = toPosix(relative(root, file));
        if (!CODE_EXT.test(fileRel) || isTestFile(fileRel)) continue;
        const text = stripComments(readFileSync(file, "utf8"));
        for (const gate of gates) {
          if (allowed.has(gate) || !new RegExp(`\\b${gate}\\b`).test(text)) continue;
          errors.push(`${fileRel}: calls the license gate ${gate}, but ${id} is a released free feature (${FREE_FEATURES_FILE}). Released free features must stay ungated; put the new paid behaviour in a separate module.`);
        }
      }
    }
  }
  return errors;
}

export function checkEnterpriseBoundary(root, allowedBridges = ALLOWED_BRIDGES) {
  const errors = [];
  const entDir = join(root, "enterprise");

  // 1. Imports from outside.
  for (const file of walk(root)) {
    const rel = toPosix(relative(root, file));
    if (rel.startsWith("enterprise/") || SELF.has(rel) || !CODE_EXT.test(rel)) continue;
    const text = readFileSync(file, "utf8");
    for (const spec of moduleSpecifiers(text)) {
      const isPackage = spec === "@0/enterprise" || spec.startsWith("@0/enterprise/");
      let isPath = false;
      if (spec.startsWith(".")) {
        const target = resolve(dirname(file), spec);
        isPath = target === entDir || target.startsWith(entDir + sep);
      }
      if (isPackage || isPath) {
        if (allowedBridges.includes(rel)) continue;
        errors.push(
          `${rel}: imports "${spec}" from enterprise/. Only bridge files in ALLOWED_BRIDGES (scripts/check-enterprise-boundary.mjs) may do that. ` +
            "Add a thin bridge and list it there, or keep the code outside enterprise/ independent of it.",
        );
      }
    }
  }
  for (const bridge of allowedBridges) {
    if (!existsSync(join(root, bridge))) errors.push(`${bridge}: listed in ALLOWED_BRIDGES but does not exist. Remove the entry.`);
  }

  // 2. Header on every enterprise source file; 3. manifest and LICENSE.
  if (existsSync(entDir)) {
    for (const file of walk(entDir)) {
      const rel = toPosix(relative(root, file));
      if (!CODE_EXT.test(rel)) continue;
      const lines = readFileSync(file, "utf8").split("\n");
      const first = lines[0].startsWith("#!") ? lines[1] ?? "" : lines[0];
      if (!first.startsWith("//") || !first.includes(HEADER_MARKER)) {
        errors.push(`${rel}: first line must be a comment pointing to ${HEADER_MARKER}.`);
      }
    }
    const manifestPath = join(entDir, "package.json");
    if (!existsSync(manifestPath)) errors.push("enterprise/package.json is missing.");
    else {
      const pkg = JSON.parse(readFileSync(manifestPath, "utf8"));
      if (pkg.license !== LICENSE_FIELD) errors.push(`enterprise/package.json: "license" must be "${LICENSE_FIELD}" (found ${JSON.stringify(pkg.license)}).`);
      if (pkg.private !== true) errors.push('enterprise/package.json: must set "private": true.');
      for (const key of ["publishConfig", "files", "prepublishOnly", "prepack"]) {
        if (key in pkg) errors.push(`enterprise/package.json: "${key}" is for npm publishing; enterprise/ is not published to npm.`);
      }
    }
    if (!existsSync(join(entDir, "LICENSE"))) errors.push("enterprise/LICENSE is missing.");
  }

  // 4. No npm tarball can include enterprise/.
  const manifests = [];
  for (const file of walk(root)) {
    const rel = toPosix(relative(root, file));
    if (rel.startsWith("enterprise/")) continue;
    if (rel.endsWith("package.json") && (rel === "package.json" || /^(packages|docs)\//.test(rel))) manifests.push(rel);
    if (/(^|\/)\.npmignore$/.test(rel) && /enterprise/.test(readFileSync(file, "utf8"))) errors.push(`${rel}: mentions enterprise/; enterprise/ is not part of any npm package.`);
  }
  for (const rel of manifests) {
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(join(root, rel), "utf8"));
    } catch {
      continue;
    }
    for (const entry of Array.isArray(pkg.files) ? pkg.files : []) {
      if (/(^|[\\/])enterprise([\\/]|$)/.test(String(entry))) errors.push(`${rel}: "files" includes "${entry}". enterprise/ is excluded from the npm tarball.`);
    }
  }

  // 5. Root licenses stay plain.
  for (const name of ["LICENSE-MIT", "LICENSE-APACHE"]) {
    const p = join(root, name);
    if (existsSync(p) && /enterprise/i.test(readFileSync(p, "utf8"))) {
      errors.push(`${name}: must not mention enterprise/. Put the carve-out in LICENSING.md and NOTICE so GitHub keeps detecting the license.`);
    }
  }
  // 6. No environment variable adds a trust anchor.
  for (const file of walk(root)) {
    const rel = toPosix(relative(root, file));
    if (SELF.has(rel) || !CODE_EXT.test(rel) || /\.test\.[cm]?[jt]sx?$/.test(rel) || rel.includes("__fixtures__/") || /(^|\/)vitest\.setup\.ts$/.test(rel)) continue;
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/(?:process\.env|\benv)\s*(?:\.\s*|\[\s*["'`])([A-Za-z0-9_]+)/g)) {
      const name = m[1];
      if (ALLOWED_LICENSE_ENV.has(name)) continue;
      if (/(LICENSE|ENTERPRISE|TRUST|ANCHOR|SIGNER)/i.test(name) && /(KEY|PUBLIC|ANCHOR|CERT)/i.test(name)) {
        errors.push(`${rel}: reads ${name}. No environment variable may add a trusted license signing key; that would be a one-line licensing bypass. Tests inject throwaway keys by mocking @0/enterprise.`);
      }
    }
  }
  const licenseSource = join(entDir, "src", "license.ts");
  if (existsSync(licenseSource)) {
    for (const m of readFileSync(licenseSource, "utf8").matchAll(/\benv\s*(?:\.\s*|\[\s*["'`])([A-Za-z0-9_]+)/g)) {
      if (!ALLOWED_LICENSE_ENV.has(m[1])) errors.push(`enterprise/src/license.ts: reads ${m[1]}. The license code may read only ZERO_LICENSE and ZERO_LICENSE_FILE.`);
    }
  }
  // 6. One XML parser version for the guard and the signature verifier.
  const lock = join(root, "pnpm-lock.yaml");
  if (existsSync(entDir) && existsSync(lock)) {
    const lines = xmldomLines(readFileSync(lock, "utf8"));
    if (lines.length > 1) {
      errors.push(`pnpm-lock.yaml: @xmldom/xmldom resolves to more than one line (${lines.join(", ")}). The SAML guard in enterprise/src/saml/ and the signature library (@node-saml/node-saml, xml-crypto) must parse with the same copy. Keep one version; do not add an override that splits them.`);
    }
  }
  // 7. Released free features stay ungated (only when the list exists; the command line below requires it).
  if (existsSync(join(root, FREE_FEATURES_FILE))) errors.push(...checkFreeFeatures(root, join(root, FREE_FEATURES_FILE), allowedBridges));
  return errors;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const root = resolve(process.argv[2] ?? join(import.meta.dirname, ".."));
  const errors = checkEnterpriseBoundary(root);
  if (!existsSync(join(root, FREE_FEATURES_FILE))) errors.push(`${FREE_FEATURES_FILE} is missing. It lists the released free features and must exist.`);
  if (errors.length) {
    for (const e of errors) console.error(`check-enterprise-boundary: ${e}`);
    process.exit(1);
  }
  console.log("check-enterprise-boundary: ok");
}
