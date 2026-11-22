/**
 * Gradle declarations, read as text: `gradle/libs.versions.toml` (version catalog) and the dependency lines of
 * `build.gradle` / `build.gradle.kts`. Only a literal version is reported. A variable, a dynamic version (`1.+`, a range,
 * `latest.release`), a missing version or a platform/BOM is listed as unresolved. Nothing is run and no build script is evaluated.
 */
import type { Component } from "./parsers.js";
import type { Unresolved } from "./maven.js";

const LITERAL = /^[0-9A-Za-z][0-9A-Za-z._-]*$/;
const isLiteral = (version: string) => LITERAL.test(version) && !/^latest\./i.test(version);
const dynamicReason = (version: string) => /[$]/.test(version) ? `version '${version}' is a variable, not a literal` : `version '${version}' is dynamic or a range, not one release`;

type TomlValue = string | { [key: string]: TomlValue };
function stripTomlComment(line: string): string {
  let quote = "";
  for (let index = 0; index < line.length; index += 1) {
    const ch = line[index]!;
    if (quote) { if (ch === "\\" && quote === "\"") index += 1; else if (ch === quote) quote = ""; } else if (ch === "\"" || ch === "'") quote = ch; else if (ch === "#") return line.slice(0, index);
  }
  return line;
}
function splitTop(value: string): string[] {
  const parts: string[] = []; let depth = 0; let quote = ""; let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const ch = value[index]!;
    if (quote) { if (ch === "\\" && quote === "\"") index += 1; else if (ch === quote) quote = ""; continue; }
    if (ch === "\"" || ch === "'") quote = ch; else if (ch === "{" || ch === "[") depth += 1; else if (ch === "}" || ch === "]") depth -= 1;
    else if (ch === "," && depth === 0) { parts.push(value.slice(start, index)); start = index + 1; }
  }
  parts.push(value.slice(start));
  return parts.map(part => part.trim()).filter(Boolean);
}
const braceDepth = (value: string): number => { let depth = 0; let quote = ""; for (const ch of value) { if (quote) { if (ch === quote) quote = ""; } else if (ch === "\"" || ch === "'") quote = ch; else if (ch === "{") depth += 1; else if (ch === "}") depth -= 1; } return depth; };
/** `a.b = v` sets `{ a: { b: v } }`. */
function setPath(table: { [key: string]: TomlValue }, dotted: string, value: TomlValue): void {
  const path = dotted.replace(/^"|"$/g, "").split(".");
  let target = table;
  for (const segment of path.slice(0, -1)) { const next = target[segment]; target = typeof next === "object" ? next : (target[segment] = {}); }
  target[path[path.length - 1]!] = value;
}
function tomlValue(raw: string): TomlValue {
  const value = raw.trim();
  if (value.startsWith("{")) {
    const table: { [key: string]: TomlValue } = {};
    for (const part of splitTop(value.slice(1, value.lastIndexOf("}") >= 0 ? value.lastIndexOf("}") : undefined))) {
      const pair = /^("[^"]+"|[A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(part);
      if (!pair) continue;
      setPath(table, pair[1]!, tomlValue(pair[2]!));
    }
    return table;
  }
  return value.replace(/^(["'])(.*)\1$/, "$2");
}
/** The `[versions]` and `[libraries]` tables of a version catalog. */
export function parseCatalog(source: string): { versions: Record<string, TomlValue>; libraries: Record<string, TomlValue> } {
  const tables: Record<string, Record<string, TomlValue>> = { versions: {}, libraries: {} };
  const lines = source.split("\n");
  let section = ""; let sub = "";
  for (let index = 0; index < lines.length; index += 1) {
    const line = stripTomlComment(lines[index]!).trim();
    if (!line) continue;
    const head = /^\[([^\]]+)\]$/.exec(line);
    if (head) { const [name, ...rest] = head[1]!.split("."); section = name!.trim(); sub = rest.join(".").trim(); continue; }
    const pair = /^("[^"]+"|[A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if (!pair || !tables[section]) continue;
    let value = pair[2]!;
    while (braceDepth(value) > 0 && index + 1 < lines.length) value += ` ${stripTomlComment(lines[++index]!).trim()}`;
    const key = pair[1]!.replace(/^"|"$/g, "");
    if (sub) { const holder = tables[section]![sub]; const table = typeof holder === "object" ? holder : (tables[section]![sub] = {}); setPath(table, key, tomlValue(value)); } else tables[section]![key] = tomlValue(value);
  }
  return { versions: tables.versions!, libraries: tables.libraries! };
}

/** One declared dependency from a catalog or a build script, or why it could not be read. */
export function parseVersionCatalog(source: string, rel: string): { components: Component[]; unresolved: Unresolved[] } {
  const { versions, libraries } = parseCatalog(source);
  const components: Component[] = []; const unresolved: Unresolved[] = [];
  const pick = (value: TomlValue | undefined): string | undefined => {
    if (typeof value === "string") return value;
    if (value && typeof value === "object") { for (const field of ["strictly", "require", "prefer"]) { const item = value[field]; if (typeof item === "string") return item; } }
    return undefined;
  };
  for (const [alias, entry] of Object.entries(libraries).sort(([a], [b]) => (a < b ? -1 : 1))) {
    let group = ""; let artifact = ""; let version: string | undefined; let ref = "";
    if (typeof entry === "string") { const [g, a, v] = entry.split(":"); group = g ?? ""; artifact = a ?? ""; version = v; }
    else {
      const module = typeof entry.module === "string" ? entry.module.split(":") : [];
      group = module[0] ?? (typeof entry.group === "string" ? entry.group : ""); artifact = module[1] ?? (typeof entry.name === "string" ? entry.name : "");
      const declared = entry.version;
      if (declared && typeof declared === "object" && typeof declared.ref === "string") { ref = declared.ref; version = pick(versions[ref]); } else version = pick(declared);
    }
    const name = `${group}:${artifact}`;
    if (!group || !artifact) continue;
    if (ref && version === undefined) { unresolved.push({ source: rel, name, reason: `version.ref '${ref}' is not in [versions]` }); continue; }
    if (version === undefined || version === "") { unresolved.push({ source: rel, name, reason: `catalog entry '${alias}' declares no version: it is managed by a platform or BOM elsewhere` }); continue; }
    if (!isLiteral(version)) { unresolved.push({ source: rel, name, reason: dynamicReason(version) }); continue; }
    components.push({ ecosystem: "maven", name: `${group}/${artifact}`, version });
  }
  return { components, unresolved };
}

function stripGradleComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").split("\n").map(line => line.replace(/(^|\s)\/\/.*$/, "$1")).join("\n");
}
const CONFIGURATION = /(?<![\w.$])((?:[a-z][A-Za-z]*?)?(?:Implementation|Api|CompileOnly|RuntimeOnly|Compile|Runtime|AnnotationProcessor|Kapt|Ksp)|implementation|api|compileOnly|compileOnlyApi|runtimeOnly|compile|runtime|annotationProcessor|kapt|ksp|classpath)\s*\(?\s*(.*)$/;
const isTestConfiguration = (configuration: string) => /^(test|androidTest)/i.test(configuration) || /Test(?:Implementation|Compile|Runtime|Api)/.test(configuration);

/** The dependency lines of one `build.gradle` or `build.gradle.kts`. A version that is a literal in the script is reported; the rest is unresolved. */
export function parseGradleBuild(source: string, rel: string): { components: Component[]; unresolved: Unresolved[] } {
  const components: Component[] = []; const unresolved: Unresolved[] = [];
  for (const line of stripGradleComments(source).split("\n")) {
    const found = CONFIGURATION.exec(line);
    if (!found) continue;
    const configuration = found[1]!; const rest = found[2]!.trim();
    const dev = isTestConfiguration(configuration);
    const add = (group: string, artifact: string, version: string | undefined, raw: string) => {
      const name = `${group}:${artifact}`;
      if (!group || !artifact || /[$]/.test(group + artifact)) { unresolved.push({ source: rel, name: raw, reason: "group or artifact is not a literal" }); return; }
      if (version === undefined || version === "") { unresolved.push({ source: rel, name, reason: "no version: managed by a platform, BOM or plugin" }); return; }
      if (!isLiteral(version)) { unresolved.push({ source: rel, name, reason: dynamicReason(version) }); return; }
      components.push({ ecosystem: "maven", name: `${group}/${artifact}`, version, ...(dev ? { dev: true } : {}) });
    };
    const platform = /^(?:enforcedPlatform|platform)\s*\(\s*(["'])([^"']+)\1/.exec(rest);
    if (platform) { unresolved.push({ source: rel, name: platform[2]!.split(":").slice(0, 2).join(":"), reason: "platform/BOM is not expanded: the versions it manages are unresolved" }); continue; }
    const text = /^(["'])((?:(?!\1).)*)\1/.exec(rest);
    if (text) { const [group, artifact, version] = text[2]!.replace(/@\w+$/, "").split(":"); add(group ?? "", artifact ?? "", version, text[2]!); continue; }
    const map = /^group\s*[:=]\s*(["'])(.*?)\1\s*,\s*name\s*[:=]\s*(["'])(.*?)\3(?:\s*,\s*version\s*[:=]\s*(?:(["'])(.*?)\5|([^\s,)]+)))?/.exec(rest);
    if (map) add(map[2]!, map[4]!, map[6] ?? (map[7] !== undefined ? `$${map[7]}` : undefined), `${map[2]}:${map[4]}`);
  }
  return { components, unresolved };
}
