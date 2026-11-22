import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { detectAi, type AiComponent, type AiService } from "./ai.js";
import { LOCKFILES, type Component, type Hash } from "./parsers.js";
import { SPDX_LICENSE_IDS } from "./spdx-ids.js";

const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const MAX_DEPTH = 6;
const SKIP = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".venv", "venv", "__pycache__", ".next", ".turbo", "coverage"]);

export interface Bom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: { timestamp: string; tools: { components: Array<{ type: "application"; author: string; name: string; version: string }> }; component: { type: "application"; name: string } };
  components: Array<LibraryComponent | AiComponent>;
  services?: AiService[];
  dependencies?: Array<{ ref: string; dependsOn: string[] }>;
}
export type LicenseChoice = { license: { id: string } } | { license: { name: string } } | { expression: string };
export interface LibraryComponent { type: "library"; "bom-ref": string; name: string; version: string; purl: string; scope?: "excluded"; hashes?: Hash[]; licenses?: LicenseChoice[]; properties?: Array<{ name: string; value: string }> }

/**
 * How one stated license is written: a valid SPDX id as `id`, an SPDX expression (valid ids joined by AND, OR, WITH, with
 * optional `+` and parentheses) as `expression`, anything else (`UNLICENSED`, `SEE LICENSE IN ...`, a misspelling) as the
 * `name` the lockfile gave, unchanged. Nothing is corrected or guessed.
 */
export function classifyLicense(value: string): LicenseChoice {
  if (SPDX_LICENSE_IDS.has(value)) return { license: { id: value } };
  const tokens = value.replace(/([()])/g, " $1 ").split(/\s+/).filter(Boolean);
  const operand = (token: string) => SPDX_LICENSE_IDS.has(token.replace(/\+$/, "")) || /^LicenseRef-[A-Za-z0-9.-]+$/.test(token);
  let valid = tokens.length > 1 && /\b(AND|OR|WITH)\b/.test(value);
  let depth = 0; let expectOperand = true;
  for (let index = 0; valid && index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token === "(") { if (!expectOperand) valid = false; depth += 1; }
    else if (token === ")") { depth -= 1; if (expectOperand || depth < 0) valid = false; }
    else if (expectOperand) { if (operand(token)) expectOperand = false; else valid = false; }
    else if (token === "AND" || token === "OR") expectOperand = true;
    else if (token === "WITH") { const exception = tokens[index + 1]; if (exception && SPDX_LICENSE_IDS.has(exception)) index += 1; else valid = false; }
    else valid = false;
  }
  if (valid && depth === 0 && !expectOperand) return { expression: value };
  return { license: { name: value } };
}
/** A CycloneDX `licenses` array allows either license objects or a single expression, never both. */
function licenseChoices(values: string[]): LicenseChoice[] {
  const choices = values.map(classifyLicense);
  const expression = choices.find(choice => "expression" in choice);
  if (expression && choices.length === 1) return [expression];
  // Several stated licenses (Composer's list), or an expression mixed with others: keep each as a named license.
  return values.map(value => { const choice = classifyLicense(value); return "expression" in choice ? { license: { name: value } } : choice; });
}
export interface SbomResult { bom: Bom; lockfiles: Array<{ path: string; label: string; components: number }>; truncated: boolean }

/** The package URL for a component: how every SBOM consumer and advisory database names it. */
export function packageUrl(component: Component): string {
  const encode = (value: string) => encodeURIComponent(value).replace(/%2F/gi, "/").replace(/%40/g, "%40");
  switch (component.ecosystem) {
    case "npm": {
      const name = component.name.toLowerCase();
      const scoped = name.startsWith("@") ? `%40${encode(name.slice(1))}` : encode(name);
      return `pkg:npm/${scoped}@${encode(component.version)}`;
    }
    case "pypi": return `pkg:pypi/${encode(component.name.toLowerCase().replace(/[._]+/g, "-"))}@${encode(component.version)}`;
    case "cargo": return `pkg:cargo/${encode(component.name)}@${encode(component.version)}`;
    case "gem": return `pkg:gem/${encode(component.name)}@${encode(component.version)}`;
    case "nuget": return `pkg:nuget/${encode(component.name)}@${encode(component.version)}`;
    case "pub": return `pkg:pub/${encode(component.name.toLowerCase())}@${encode(component.version)}`;
    case "hex": return `pkg:hex/${encode(component.name)}@${encode(component.version)}`;
    case "composer": return `pkg:composer/${component.name.toLowerCase().split("/").map(encodeURIComponent).join("/")}@${encode(component.version)}`;
    case "maven": return `pkg:maven/${component.name.split("/").map(encodeURIComponent).join("/")}@${encode(component.version)}`;
    case "golang": return `pkg:golang/${component.name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(component.version)}`;
  }
}

function findLockfiles(folder: string): Array<{ path: string; label: string; parse: (source: string) => Component[] }> {
  const found: Array<{ path: string; label: string; parse: (source: string) => Component[] }> = [];
  const walk = (dir: string, depth: number): void => {
    let entries: string[];
    try { entries = readdirSync(dir).sort(); } catch { return; }
    for (const name of entries) {
      const path = join(dir, name);
      let info; try { info = statSync(path); } catch { continue; }
      if (info.isDirectory()) { if (depth < MAX_DEPTH && !SKIP.has(name) && !name.startsWith(".")) walk(path, depth + 1); continue; }
      const lock = LOCKFILES.find(candidate => candidate.file === name);
      if (lock && info.size <= MAX_LOCKFILE_BYTES) found.push({ path, label: lock.label, parse: lock.parse });
    }
  };
  walk(folder, 0);
  return found;
}

/** Fold what a second lockfile says about the same package into the first: edges are unioned, a hash is kept only where lockfiles agree, licenses come from the first that states them. */
function mergeFacts(into: Component, from: Component): void {
  if (from.dependsOn) into.dependsOn = [...(into.dependsOn ?? []), ...from.dependsOn];
  if (!into.licenses?.length && from.licenses?.length) into.licenses = from.licenses;
  if (from.hashes) {
    const kept = [...(into.hashes ?? [])];
    for (const hash of from.hashes) {
      const same = kept.findIndex(other => other.alg === hash.alg);
      if (same < 0) kept.push(hash); else if (kept[same]!.content !== hash.content) kept.splice(same, 1);
    }
    into.hashes = kept;
  }
}

/** Build a CycloneDX 1.5 SBOM from the lockfiles under a folder. Sorted and de-duplicated, so the same lockfiles give the same SBOM. */
export function generateSbom(folder: string, options: { name?: string; toolVersion: string; now?: Date; ai?: boolean }): SbomResult {
  const locks = findLockfiles(folder);
  // A pinned requirements.txt next to a lock that already covers the same ecosystem adds noise, not facts.
  const byPurl = new Map<string, { component: Component; purl: string; source: string }>();
  const refs = new Map<string, string>();  // "ecosystem:name@version" -> purl, to turn a lockfile's edges into bom-refs
  const summary: SbomResult["lockfiles"] = [];
  for (const lock of locks) {
    let source: string;
    try { source = readFileSync(lock.path, "utf8"); } catch { continue; }
    const components = lock.parse(source);
    const lockPath = relative(folder, lock.path) || lock.path;
    summary.push({ path: lockPath, label: lock.label, components: components.length });
    for (const component of components) {
      const purl = packageUrl(component);
      const existing = byPurl.get(purl);
      // A component is development-only only if every lockfile that lists it says so.
      if (!existing) byPurl.set(purl, { component: { ...component, ...(component.dependsOn ? { dependsOn: [...component.dependsOn] } : {}) }, purl, source: lockPath.split("\\").join("/") });
      else {
        if (existing.component.dev && !component.dev) delete existing.component.dev;
        mergeFacts(existing.component, component);
      }
      refs.set(`${component.ecosystem}:${component.name}@${component.version}`, purl);
    }
  }
  const ai = options.ai ? detectAi(folder) : { components: [], services: [] };
  const sorted = [...byPurl.values()].sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
  const digest = createHash("sha256").update([...sorted.map(item => item.purl), ...ai.components.map(item => item["bom-ref"]), ...ai.services.map(item => item["bom-ref"])].join("\n")).digest("hex");
  const serial = `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
  const bom: Bom = {
    bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: serial, version: 1,
    metadata: {
      timestamp: (options.now ?? new Date()).toISOString(),
      tools: { components: [{ type: "application", author: "0sec-labs", name: "0", version: options.toolVersion }] },
      component: { type: "application", name: options.name ?? (folder.split(/[\\/]/).filter(Boolean).pop() ?? "application") },
    },
    components: [...sorted.map(({ component, purl, source }): LibraryComponent => ({
      type: "library", "bom-ref": purl, name: component.name, version: component.version, purl,
      ...(component.dev ? { scope: "excluded" as const } : {}),
      ...(component.hashes?.length ? { hashes: [...component.hashes].sort((a, b) => (a.alg < b.alg ? -1 : 1)) } : {}),
      ...(component.licenses?.length ? { licenses: licenseChoices(component.licenses) } : {}),
      properties: [{ name: "0:source", value: source }],
    })), ...ai.components],
    ...(ai.services.length ? { services: ai.services } : {}),
  };
  // Only components whose lockfile records a graph get an entry (an empty `dependsOn` says "a leaf"; no entry says "unknown").
  const dependencies = sorted.filter(({ component }) => component.dependsOn).map(({ component, purl }) => ({
    ref: purl,
    dependsOn: [...new Set(component.dependsOn!.flatMap(target => { const ref = refs.get(`${component.ecosystem}:${target.name}@${target.version}`); return ref && ref !== purl ? [ref] : []; }))].sort(),
  }));
  if (dependencies.length) bom.dependencies = dependencies;
  return { bom, lockfiles: summary.sort((a, b) => (a.path < b.path ? -1 : 1)), truncated: false };
}
