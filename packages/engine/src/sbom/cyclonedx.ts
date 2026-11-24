import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { detectAi, type AiComponent, type AiService } from "./ai.js";
import { parseGradleBuild, parseVersionCatalog } from "./gradle.js";
import { analyzeMaven, type Unresolved } from "./maven.js";
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
  metadata: { timestamp: string; tools: { components: Array<{ type: "application"; author: string; name: string; version: string }> }; component: { type: "application"; name: string }; properties?: Array<{ name: string; value: string }> };
  components: Array<LibraryComponent | AiComponent>;
  services?: AiService[];
  dependencies?: Array<{ ref: string; dependsOn: string[] }>;
}
/** Metadata property naming one declared dependency, profile, module, parent or BOM that was not analysed, and why. */
export const UNRESOLVED_PROPERTY = "0:unresolved";
/** Component property set to `true` when a build tool resolved the component (`0 sbom generate --resolve`). */
export const RESOLVED_PROPERTY = "0:resolved";
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
export interface SbomResult { bom: Bom; lockfiles: Array<{ path: string; label: string; components: number }>; truncated: boolean; unresolved: Unresolved[] }

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

interface Found { path: string; label: string; parse: (source: string) => Component[] }
/** Every file under the folder that the SBOM reader may use, in sorted order, skipping dependency and build folders. */
function listFiles(folder: string): Array<{ path: string; size: number }> {
  const found: Array<{ path: string; size: number }> = [];
  const walk = (dir: string, depth: number): void => {
    let entries: string[];
    try { entries = readdirSync(dir).sort(); } catch { return; }
    for (const name of entries) {
      const path = join(dir, name);
      let info; try { info = statSync(path); } catch { continue; }
      if (info.isDirectory()) { if (depth < MAX_DEPTH && !SKIP.has(name) && !name.startsWith(".")) walk(path, depth + 1); continue; }
      if (info.size <= MAX_LOCKFILE_BYTES) found.push({ path, size: info.size });
    }
  };
  walk(folder, 0);
  return found;
}
const GRADLE_SCRIPTS = new Set(["build.gradle", "build.gradle.kts"]);

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
export function generateSbom(folder: string, options: { name?: string; toolVersion: string; now?: Date; ai?: boolean; resolved?: Component[] }): SbomResult {
  const files = listFiles(folder);
  const locks: Found[] = [];
  for (const file of files) { const lock = LOCKFILES.find(candidate => candidate.file === basename(file.path)); if (lock) locks.push({ path: file.path, label: lock.label, parse: lock.parse }); }
  // A pinned requirements.txt next to a lock that already covers the same ecosystem adds noise, not facts.
  const byPurl = new Map<string, { component: Component; purl: string; source: string }>();
  const refs = new Map<string, string>();  // "ecosystem:name@version" -> purl, to turn a lockfile's edges into bom-refs
  const summary: SbomResult["lockfiles"] = [];
  const add = (component: Component, source: string): void => {
    const purl = packageUrl(component);
    const existing = byPurl.get(purl);
    // A component is development-only only if every lockfile that lists it says so.
    if (!existing) byPurl.set(purl, { component: { ...component, ...(component.dependsOn ? { dependsOn: [...component.dependsOn] } : {}) }, purl, source });
    else {
      if (existing.component.dev && !component.dev) delete existing.component.dev;
      mergeFacts(existing.component, component);
    }
    refs.set(`${component.ecosystem}:${component.name}@${component.version}`, purl);
  };
  const locked = new Set<string>();
  for (const lock of locks) {
    let source: string;
    try { source = readFileSync(lock.path, "utf8"); } catch { continue; }
    const components = lock.parse(source);
    const lockPath = relative(folder, lock.path) || lock.path;
    summary.push({ path: lockPath, label: lock.label, components: components.length });
    for (const component of components) { add(component, lockPath.split("\\").join("/")); if (component.ecosystem === "maven") locked.add(component.name); }
  }
  // Maven and Gradle declarations: read as text, resolved only from what the repository itself says.
  const unresolved: Unresolved[] = [];
  const read = (path: string): string | undefined => { try { return readFileSync(path, "utf8"); } catch { return undefined; } };
  const rel = (path: string) => (relative(folder, path) || path).split("\\").join("/");
  const poms = files.filter(file => basename(file.path) === "pom.xml").flatMap(file => { const source = read(file.path); return source === undefined ? [] : [{ path: file.path, rel: rel(file.path), source }]; });
  const jvm: Array<{ path: string; label: string; components: Component[] }> = [];
  if (poms.length) { const maven = analyzeMaven(poms); jvm.push(...maven.files); unresolved.push(...maven.unresolved); }
  for (const file of files) {
    const name = basename(file.path);
    const isCatalog = name === "libs.versions.toml" && basename(join(file.path, "..")) === "gradle";
    if (!isCatalog && !GRADLE_SCRIPTS.has(name)) continue;
    const source = read(file.path);
    if (source === undefined) continue;
    const parsed = isCatalog ? parseVersionCatalog(source, rel(file.path)) : parseGradleBuild(source, rel(file.path));
    // A Gradle lockfile pins what the build resolved, so it wins over a version declared in a script or catalog.
    jvm.push({ path: file.path, label: isCatalog ? "Gradle (version catalog)" : "Gradle (build script)", components: parsed.components.filter(component => !locked.has(component.name)) });
    unresolved.push(...parsed.unresolved.filter(item => !locked.has(item.name.replace(":", "/"))));
  }
  for (const file of jvm) {
    summary.push({ path: relative(folder, file.path) || file.path, label: file.label, components: file.components.length });
    for (const component of file.components) add(component, (relative(folder, file.path) || file.path).split("\\").join("/"));
  }
  // Components a build tool resolved replace what the declarations said about the same package: the tool saw the parents, BOMs and profiles.
  const resolvedNames = new Set((options.resolved ?? []).map(component => component.name));
  if (options.resolved?.length) {
    const carried = new Map<string, { component: Component; source: string }>();
    for (const [purl, entry] of byPurl) if (entry.component.ecosystem === "maven" && resolvedNames.has(entry.component.name)) { carried.set(purl, entry); byPurl.delete(purl); }
    const declarationsByName = new Map<string, Array<{ component: Component; source: string; purl: string }>>();
    for (const file of jvm) {
      const source = (relative(folder, file.path) || file.path).split("\\").join("/");
      for (const component of file.components) {
        if (component.ecosystem === "maven" && resolvedNames.has(component.name)) {
          const purl = packageUrl(component);
          const list = declarationsByName.get(component.name);
          if (list) list.push({ component, source, purl });
          else declarationsByName.set(component.name, [{ component, source, purl }]);
        }
      }
    }
    for (const [purl, entry] of carried) {
      const list = declarationsByName.get(entry.component.name);
      if (!list?.some(d => d.source === entry.source && d.purl === purl)) {
        if (list) list.push({ component: entry.component, source: entry.source, purl });
        else declarationsByName.set(entry.component.name, [{ component: entry.component, source: entry.source, purl }]);
      }
    }
    // A resolved component keeps the file that declared it; a transitive one points at the project's top build file.
    const top = files.map(file => rel(file.path)).filter(path => /(^|\/)(pom\.xml|build\.gradle(\.kts)?)$/.test(path)).sort((a, b) => a.split("/").length - b.split("/").length || (a < b ? -1 : 1))[0] ?? "pom.xml";
    for (const component of options.resolved) {
      const purl = packageUrl(component);
      const decls = declarationsByName.get(component.name) ?? [];
      const exact = decls.filter(d => d.purl === purl);
      const exactSources = new Set(exact.map(d => d.source));
      const allSources = new Set(decls.map(d => d.source));

      let matchedSource: string | undefined;
      let before: { component: Component; source: string } | undefined;
      let sameVersion = true;

      if (exactSources.size === 1) {
        matchedSource = exact[0]!.source;
        before = carried.get(purl) ?? exact[0];
      } else if (exact.length === 0 && allSources.size === 1) {
        matchedSource = decls[0]!.source;
        before = carried.get(decls[0]!.purl) ?? decls[0];
        sameVersion = false;
      }

      add({ ...component, resolved: true }, matchedSource ?? top);
      // Hashes belong to one exact version; never carry them onto a resolved component of another version.
      if (before) mergeFacts(byPurl.get(purl)!.component, { ...before.component, dependsOn: undefined, ...(sameVersion ? {} : { hashes: undefined }) });
    }
  }
  const seenUnresolved = new Set<string>();
  const unresolvedSorted = unresolved.filter(item => !resolvedNames.has(item.name.replace(":", "/"))).filter(item => { const key = `${item.source}\n${item.name}\n${item.reason}`; if (seenUnresolved.has(key)) return false; seenUnresolved.add(key); return true; })
    .sort((a, b) => (a.source !== b.source ? (a.source < b.source ? -1 : 1) : a.name !== b.name ? (a.name < b.name ? -1 : 1) : a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : 0));
  const ai = options.ai ? detectAi(folder) : { components: [], services: [] };
  const sorted = [...byPurl.values()].sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
  const digest = createHash("sha256").update([...sorted.map(item => item.purl), ...ai.components.map(item => item["bom-ref"]), ...ai.services.map(item => item["bom-ref"]), ...unresolvedSorted.map(item => `${item.source} ${item.name}`)].join("\n")).digest("hex");
  const serial = `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
  const bom: Bom = {
    bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: serial, version: 1,
    metadata: {
      timestamp: (options.now ?? new Date()).toISOString(),
      tools: { components: [{ type: "application", author: "0sec-labs", name: "0", version: options.toolVersion }] },
      component: { type: "application", name: options.name ?? (folder.split(/[\\/]/).filter(Boolean).pop() ?? "application") },
      ...(unresolvedSorted.length ? { properties: unresolvedSorted.map(item => ({ name: UNRESOLVED_PROPERTY, value: `${item.name} (${item.reason}) in ${item.source}` })) } : {}),
    },
    components: [...sorted.map(({ component, purl, source }): LibraryComponent => ({
      type: "library", "bom-ref": purl, name: component.name, version: component.version, purl,
      ...(component.dev ? { scope: "excluded" as const } : {}),
      ...(component.hashes?.length ? { hashes: [...component.hashes].sort((a, b) => (a.alg < b.alg ? -1 : 1)) } : {}),
      ...(component.licenses?.length ? { licenses: licenseChoices(component.licenses) } : {}),
      properties: [{ name: "0:source", value: source }, ...(component.resolved ? [{ name: RESOLVED_PROPERTY, value: "true" }] : [])],
    })), ...ai.components],
    ...(ai.services.length ? { services: ai.services } : {}),
  };
  // Only components whose lockfile records a graph get an entry (an empty `dependsOn` says "a leaf"; no entry says "unknown").
  const dependencies = sorted.filter(({ component }) => component.dependsOn).map(({ component, purl }) => ({
    ref: purl,
    dependsOn: [...new Set(component.dependsOn!.flatMap(target => { const ref = refs.get(`${component.ecosystem}:${target.name}@${target.version}`); return ref && ref !== purl ? [ref] : []; }))].sort(),
  }));
  if (dependencies.length) bom.dependencies = dependencies;
  return { bom, lockfiles: summary.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.label < b.label ? -1 : 1)), truncated: false, unresolved: unresolvedSorted };
}
