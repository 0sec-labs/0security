/**
 * Lockfile parsers. Each takes the text of one lockfile and returns the packages it pins. They read text only:
 * nothing is executed, installed or fetched, and a file that does not parse gives no packages rather than a guess.
 */
import { parse as parseYaml } from "yaml";

export interface Component {
  ecosystem: "npm" | "cargo" | "golang" | "pypi" | "gem" | "composer" | "nuget" | "maven" | "pub" | "hex";
  name: string;
  version: string;
  /** Marked as a development-only dependency by the lockfile, so not part of what ships. */
  dev?: boolean;
  /** Checksums of the published artifact, as the lockfile states them (hex digests of a known algorithm). */
  hashes?: Hash[];
  /** Components this one depends on, as the lockfile resolves them. Absent: the lockfile does not record a graph. Empty: it does, and this is a leaf. */
  dependsOn?: Array<{ name: string; version: string }>;
  /** Licenses exactly as the lockfile states them (an SPDX expression or free text); classified when the SBOM is written. */
  licenses?: string[];
  /** Not from the public registry: a workspace member, a local path, or a package the lockfile resolves from another registry. */
  local?: "workspace" | "private-registry";
  /** Resolved by running the project's own build tool (`0 sbom generate --resolve`), not read from a declaration. */
  resolved?: boolean;
}
export interface Hash { alg: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"; content: string }

const SRI_ALGS: Record<string, { alg: Hash["alg"]; bytes: number }> = { sha1: { alg: "SHA-1", bytes: 20 }, sha256: { alg: "SHA-256", bytes: 32 }, sha384: { alg: "SHA-384", bytes: 48 }, sha512: { alg: "SHA-512", bytes: 64 } };
/** A Subresource Integrity string (`sha512-<base64>`, possibly several, space separated) to hex hashes. A value whose length does not match its algorithm is dropped, not guessed at. */
export function sriToHashes(value: unknown): Hash[] {
  if (typeof value !== "string") return [];
  const found: Hash[] = [];
  for (const token of value.trim().split(/\s+/)) {
    const match = /^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})(?:\?.*)?$/.exec(token);
    const spec = match && SRI_ALGS[match[1]!];
    if (!match || !spec) continue;
    const bytes = Buffer.from(match[2]!, "base64");
    // Round-trip check: the string must be canonical base64 of exactly the digest length.
    if (bytes.length === spec.bytes && bytes.toString("base64") === match[2]) found.push({ alg: spec.alg, content: bytes.toString("hex") });
  }
  return found;
}
/** A hex digest of a known algorithm, or nothing when it is the wrong length or not hex. */
export function hexHash(alg: Hash["alg"], value: unknown): Hash[] {
  const length = { "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128 }[alg];
  return typeof value === "string" && value.length === length && /^[0-9a-fA-F]+$/.test(value) ? [{ alg, content: value.toLowerCase() }] : [];
}

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): string => typeof value === "string" ? value : "";

/** The `name` an npm lockfile path installs: the last `node_modules/` segment. */
const npmNameOf = (path: string, entry: Record<string, unknown>): string => text(entry.name) || path.split("node_modules/").pop() || "";
const licenseList = (value: unknown): string[] => typeof value === "string" && value.trim() ? [value.trim()] : Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && !!item.trim()).map(item => item.trim()) : [];

/** `local` for a resolved URL or path that is not the public npm registry. */
function npmLocalOf(resolved: string): Component["local"] {
  if (!resolved) return undefined;
  if (/^(file|link|portal|workspace):/.test(resolved)) return "workspace";
  return /^https?:\/\//.test(resolved) && !/^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//.test(resolved) ? "private-registry" : undefined;
}

export function parseNpmLock(source: string): Component[] {
  let lock: unknown;
  try { lock = JSON.parse(source); } catch { return []; }
  if (!isObject(lock)) return [];
  const found: Component[] = [];
  if (isObject(lock.packages)) {
    const packages = lock.packages;
    // Node resolves a dependency from the package's own node_modules, then each parent's.
    const resolve = (from: string, dep: string): { name: string; version: string } | undefined => {
      let base = from;
      for (;;) {
        const path = `${base}${base ? "/" : ""}node_modules/${dep}`;
        const target = packages[path];
        if (isObject(target) && target.link !== true && text(target.version)) return { name: npmNameOf(path, target), version: text(target.version) };
        if (!base) return undefined;
        const cut = base.lastIndexOf("/node_modules/");
        base = cut >= 0 ? base.slice(0, cut) : "";
      }
    };
    for (const [path, entry] of Object.entries(packages)) {
      if (!path || !isObject(entry) || entry.link === true) continue;
      const name = npmNameOf(path, entry);
      const version = text(entry.version);
      if (!name || !version) continue;
      const dependsOn: Array<{ name: string; version: string }> = [];
      for (const field of ["dependencies", "optionalDependencies"]) {
        if (!isObject(entry[field])) continue;
        for (const dep of Object.keys(entry[field] as object)) { const target = resolve(path, dep); if (target) dependsOn.push(target); }
      }
      const hashes = sriToHashes(entry.integrity);
      const licenses = licenseList(entry.license);
      const resolvedUrl = text(entry.resolved);
      const local = !path.includes("node_modules/") ? "workspace" as const : npmLocalOf(resolvedUrl);
      found.push({ ecosystem: "npm", name, version, ...(local ? { local } : {}), ...(entry.dev === true ? { dev: true } : {}), ...(hashes.length ? { hashes } : {}), dependsOn, ...(licenses.length ? { licenses } : {}) });
    }
    return found;
  }
  const walk = (dependencies: unknown): void => {
    if (!isObject(dependencies)) return;
    for (const [name, entry] of Object.entries(dependencies)) {
      if (!isObject(entry)) continue;
      const version = text(entry.version);
      if (version && !/^(file:|link:|git|https?:)/.test(version)) { const hashes = sriToHashes(entry.integrity); const local = npmLocalOf(text(entry.resolved)); found.push({ ecosystem: "npm", name, version, ...(local ? { local } : {}), ...(entry.dev === true ? { dev: true } : {}), ...(hashes.length ? { hashes } : {}) }); }
      walk(entry.dependencies);
    }
  };
  walk(lock.dependencies);
  return found;
}

/** `name@1.2.3`, `@scope/name@1.2.3(peer@2)`, `/name@1.2.3`, or the older `/name/1.2.3`. */
function pnpmKey(raw: string): { name: string; version: string } | undefined {
  let key = raw.replace(/^\//, "").replace(/\(.*$/, "").replace(/_.*$/, (match) => (match.includes("@") ? "" : match));
  const at = key.lastIndexOf("@");
  if (at > 0) return { name: key.slice(0, at), version: key.slice(at + 1) };
  const slash = key.lastIndexOf("/");
  if (slash > 0) return { name: key.slice(0, slash), version: key.slice(slash + 1) };
  return undefined;
}
/** A pnpm dependency value: a bare version (`1.2.3`, `1.2.3(peer@1)`, v5 `1.2.3_peer`), or `name@version` / `/name@version` for aliases and v6. `link:` and other non-registry values give nothing. */
function pnpmDependency(name: string, value: unknown): { name: string; version: string } | undefined {
  const raw = text(value);
  if (!raw || /^(link:|file:|workspace:|https?:|git)/.test(raw)) return undefined;
  if (/^\d/.test(raw)) return { name, version: raw.replace(/\(.*$/, "").replace(/_.*$/, "") };
  const parsed = pnpmKey(raw);
  return parsed && /^\d/.test(parsed.version) ? parsed : undefined;
}
export function parsePnpmLock(source: string): Component[] {
  let lock: unknown;
  try { lock = parseYaml(source, { schema: "core" }); } catch { return []; }
  if (!isObject(lock) || !isObject(lock.packages)) return [];
  // v9 keeps the graph in `snapshots` (one per peer-dependency variant); v5 and v6 keep it on the package itself.
  const graphSource = isObject(lock.snapshots) ? lock.snapshots : lock.packages;
  const edges = new Map<string, Map<string, { name: string; version: string }>>();
  const identity = (parsed: { name: string; version: string }) => `${parsed.name}@${parsed.version}`;
  for (const [key, entry] of Object.entries(graphSource)) {
    const parsed = pnpmKey(key);
    if (!parsed || !/^\d/.test(parsed.version)) continue;
    const list = edges.get(identity(parsed)) ?? new Map();
    edges.set(identity(parsed), list);
    if (!isObject(entry)) continue;
    for (const field of ["dependencies", "optionalDependencies"]) {
      if (!isObject(entry[field])) continue;
      for (const [name, value] of Object.entries(entry[field] as Record<string, unknown>)) { const target = pnpmDependency(name, value); if (target) list.set(identity(target), target); }
    }
  }
  const found = new Map<string, Component>();
  for (const [key, entry] of Object.entries(lock.packages)) {
    const parsed = pnpmKey(key);
    if (!parsed || !/^\d/.test(parsed.version)) continue;
    const resolution = isObject(entry) && isObject(entry.resolution) ? entry.resolution : {};
    const hashes = sriToHashes(resolution.integrity);
    const dev = isObject(entry) && entry.dev === true;
    const local = npmLocalOf(text(resolution.tarball)) ?? (text(resolution.directory) ? "workspace" as const : undefined);
    const previous = found.get(identity(parsed));
    if (previous) { if (!previous.hashes?.length && hashes.length) previous.hashes = hashes; continue; }
    found.set(identity(parsed), { ecosystem: "npm", name: parsed.name, version: parsed.version, ...(local ? { local } : {}), ...(dev ? { dev: true } : {}), ...(hashes.length ? { hashes } : {}), ...(edges.has(identity(parsed)) ? { dependsOn: [...edges.get(identity(parsed))!.values()] } : {}) });
  }
  return [...found.values()];
}

/**
 * yarn.lock, classic (`version "1"`, `integrity sha512-...`, `dependencies:` blocks) and Berry (`version: 1`).
 * Berry's `checksum` is a hash of Yarn's own cache archive, not of the published tarball, so it is not reported.
 */
export function parseYarnLock(source: string): Component[] {
  interface Block { specs: string[]; name: string; version: string; integrity: string; resolved: string; deps: Array<[string, string]> }
  const blocks: Block[] = [];
  let block: Block | undefined;
  let inDeps = false;
  const unquote = (value: string) => value.trim().replace(/^"|"$/g, "");
  for (const line of source.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      inDeps = false; block = undefined;
      if (!line.endsWith(":")) continue;
      const specs = line.slice(0, -1).split(",").map(unquote).filter(Boolean);
      const names = specs.map(spec => { const at = spec.lastIndexOf("@"); return at > 0 ? spec.slice(0, at) : ""; }).filter(Boolean);
      if (names.length) { block = { specs, name: names[0]!, version: "", integrity: "", resolved: "", deps: [] }; blocks.push(block); }
      continue;
    }
    if (!block) continue;
    const indent = /^\s*/.exec(line)![0].length;
    if (indent <= 2) {
      inDeps = /^\s+(dependencies|optionalDependencies):\s*$/.test(line);
      const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
      if (version && !block.version) block.version = version[1]!;
      const integrity = /^\s+integrity:?\s+"?([^"\s]+)"?/.exec(line);
      if (integrity) block.integrity = integrity[1]!;
      const resolved = /^\s+resolved:?\s+"?([^"\s]+)"?/.exec(line) ?? /^\s+resolution:\s+"[^"]*@((?:workspace|file|portal|link):[^"]*)"/.exec(line);
      if (resolved) block.resolved = resolved[1]!;
      continue;
    }
    if (inDeps) {
      const dep = /^\s+("[^"]+"|[^\s:"]+):?\s+"?([^"]*?)"?\s*$/.exec(line);
      if (dep) block.deps.push([unquote(dep[1]!), dep[2]!]);
    }
  }
  const bySpec = new Map<string, { name: string; version: string }>();
  for (const item of blocks) if (item.version) for (const spec of item.specs) bySpec.set(spec, { name: item.name, version: item.version });
  const found: Component[] = [];
  for (const item of blocks) {
    if (!item.version) continue;
    const hashes = sriToHashes(item.integrity);
    const dependsOn = new Map<string, { name: string; version: string }>();
    for (const [name, range] of item.deps) {
      const target = bySpec.get(`${name}@${range}`) ?? bySpec.get(`${name}@npm:${range}`);
      if (target) dependsOn.set(`${target.name}@${target.version}`, target);
    }
    const local = npmLocalOf(item.resolved);
    found.push({ ecosystem: "npm", name: item.name, version: item.version, ...(local ? { local } : {}), ...(hashes.length ? { hashes } : {}), dependsOn: [...dependsOn.values()] });
  }
  return found;
}

/** `[[package]]` tables with `name = "..."` and `version = "..."`, as in Cargo.lock and poetry.lock. */
interface PackageTable { fields: Record<string, string>; dependencies: string[]; sections: Record<string, string[]>; files: string[] }
function parsePackageTables(source: string): PackageTable[] {
  const tables: PackageTable[] = [];
  let current: PackageTable | undefined;
  let section = "";
  let array: string[] | undefined;
  for (const line of source.split(/\r?\n/)) {
    if (array) {
      if (/^\s*\]/.test(line)) { array = undefined; continue; }
      const item = /^\s*"([^"]*)"/.exec(line) ?? /^\s*\{.*\bhash\s*=\s*"([^"]*)"/.exec(line);
      if (item) array.push(item[1]!);
      continue;
    }
    if (line.trim() === "[[package]]") { current = { fields: {}, dependencies: [], sections: {}, files: [] }; tables.push(current); section = ""; continue; }
    if (line.startsWith("[")) { section = line.trim().replace(/^\[|\]$/g, ""); if (!section.startsWith("package.")) current = undefined; continue; }
    if (!current) continue;
    if (section === "package.dependencies") { const pair = /^("[^"]+"|[A-Za-z0-9_.-]+)\s*=/.exec(line); if (pair) current.sections["dependencies"] = [...(current.sections["dependencies"] ?? []), pair[1]!.replace(/^"|"$/g, "")]; continue; }
    if (section === "package.source") { const type = /^type\s*=\s*"([^"]*)"/.exec(line); if (type) current.fields["sourceType"] = type[1]!; continue; }
    if (section) continue;
    const pair = /^(\w+)\s*=\s*"([^"]*)"/.exec(line);
    if (pair) { current.fields[pair[1]!] = pair[2]!; continue; }
    const open = /^(dependencies|files)\s*=\s*\[\s*(.*)$/.exec(line);
    if (open) {
      const target = open[1] === "files" ? current.files : current.dependencies;
      array = target;
      // A one-line array: `dependencies = ["a", "b"]`.
      if (open[2]!.includes("]")) { for (const item of open[2]!.matchAll(/"([^"]*)"/g)) target.push(item[1]!); array = undefined; }
    }
  }
  return tables.filter(table => table.fields.name && table.fields.version);
}

/** Cargo.lock: registry crates only. Each `dependencies` entry is `name`, `name version` or `name version (source)`; `checksum` is the SHA-256 of the .crate file. */
export function parseCargoLock(source: string): Component[] {
  const tables = parsePackageTables(source);
  const crates = tables.filter(table => !!table.fields.source);
  const byName = new Map<string, PackageTable[]>();
  for (const table of crates) byName.set(table.fields.name!, [...(byName.get(table.fields.name!) ?? []), table]);
  return crates.map(table => {
    const dependsOn = new Map<string, { name: string; version: string }>();
    for (const entry of table.dependencies) {
      const [name, version] = entry.split(" ");
      const candidates = (byName.get(name!) ?? []).filter(candidate => !version || candidate.fields.version === version);
      // A bare name is only resolved when exactly one version of that crate is locked.
      if (candidates.length === 1) dependsOn.set(`${name}@${candidates[0]!.fields.version}`, { name: name!, version: candidates[0]!.fields.version! });
    }
    const hashes = hexHash("SHA-256", table.fields.checksum);
    return { ecosystem: "cargo" as const, name: table.fields.name!, version: table.fields.version!, ...(hashes.length ? { hashes } : {}), dependsOn: [...dependsOn.values()] };
  });
}
/**
 * poetry.lock. A package lists one hash per file (each wheel, the sdist), and a component has one hash, so a hash is
 * reported only for a package with exactly one file. Poetry records no licenses.
 */
export function parsePoetryLock(source: string): Component[] {
  const tables = parsePackageTables(source);
  const normalise = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");
  const byName = new Map<string, PackageTable[]>();
  for (const table of tables) byName.set(normalise(table.fields.name!), [...(byName.get(normalise(table.fields.name!)) ?? []), table]);
  return tables.map(table => {
    const dependsOn = new Map<string, { name: string; version: string }>();
    for (const name of table.sections["dependencies"] ?? []) {
      const candidates = byName.get(normalise(name)) ?? [];
      if (candidates.length === 1) dependsOn.set(`${candidates[0]!.fields.name}@${candidates[0]!.fields.version}`, { name: candidates[0]!.fields.name!, version: candidates[0]!.fields.version! });
    }
    const only = table.files.length === 1 ? /^sha256:([0-9a-fA-F]{64})$/.exec(table.files[0]!) : null;
    return { ecosystem: "pypi" as const, name: table.fields.name!, version: table.fields.version!, ...(table.fields.sourceType ? { local: "private-registry" as const } : {}), ...(only ? { hashes: hexHash("SHA-256", only[1]) } : {}), dependsOn: [...dependsOn.values()] };
  });
}

export function parseGoMod(source: string): Component[] {
  const found: Component[] = [];
  let block = false;
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (line === "require (") { block = true; continue; }
    if (block && line === ")") { block = false; continue; }
    const match = block ? /^(\S+)\s+(v\S+)$/.exec(line) : /^require\s+(\S+)\s+(v\S+)$/.exec(line);
    if (match) found.push({ ecosystem: "golang", name: match[1]!, version: match[2]! });
  }
  return found;
}

export function parsePipfileLock(source: string): Component[] {
  let lock: unknown;
  try { lock = JSON.parse(source); } catch { return []; }
  if (!isObject(lock)) return [];
  const found: Component[] = [];
  for (const [section, dev] of [["default", false], ["develop", true]] as const) {
    const packages = lock[section];
    if (!isObject(packages)) continue;
    for (const [name, entry] of Object.entries(packages)) {
      const version = isObject(entry) ? text(entry.version).replace(/^==/, "") : "";
      const index = isObject(entry) ? text(entry.index) : "";
      if (version) found.push({ ecosystem: "pypi", name, version, ...(index && index !== "pypi" ? { local: "private-registry" as const } : {}), ...(dev ? { dev: true } : {}) });
    }
  }
  return found;
}

export function parseRequirements(source: string): Component[] {
  const found: Component[] = [];
  // Any index or find-links option other than the public index may serve private packages: mark every package local.
  const custom = [...source.matchAll(/^\s*(?:-i|--index-url|--extra-index-url|-f|--find-links)(?:\s+|=)(\S+)/gm)].some(match => !/^https:\/\/pypi\.org\//.test(match[1]!));
  const local = custom ? { local: "private-registry" as const } : {};
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").replace(/\s*\\$/, "").split(";")[0]!.trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$/.exec(line);
    if (match) found.push({ ecosystem: "pypi", name: match[1]!, version: match[2]!, ...local });
  }
  return found;
}

/**
 * Gemfile.lock: the `specs:` lists, where each gem is `    name (1.2.3)` (four spaces) and its dependencies follow at six.
 * Hashes come from the `CHECKSUMS` section (Bundler 2.5+) and only for a gem with a single platform variant, since each
 * platform build has its own checksum.
 */
export function parseGemfileLock(source: string): Component[] {
  const specLine = /^ {4}([A-Za-z0-9_.-]+) \((\d[\w.]*?)(?:-(?:x86|x64|arm|aarch|java|ruby|mingw|mswin|universal|darwin|linux|musl)[\w.-]*)?\)$/;
  const gems = new Map<string, { name: string; version: string; deps: Set<string> }>();
  const order: string[] = [];
  let current: { deps: Set<string> } | undefined;
  let section = "";
  const checksums = new Map<string, string[]>();
  for (const line of source.split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) { section = line.trim(); current = undefined; continue; }
    if (section === "CHECKSUMS") {
      const match = /^ {2}([A-Za-z0-9_.-]+) \((\d[\w.]*?)(?:-[\w.-]+)?\)(?: sha256=([0-9a-f]{64}))?$/.exec(line);
      if (match) checksums.set(`${match[1]}@${match[2]}`, [...(checksums.get(`${match[1]}@${match[2]}`) ?? []), match[3] ?? ""]);
      continue;
    }
    const spec = specLine.exec(line);
    if (spec) {
      const key = `${spec[1]}@${spec[2]}`;
      if (!gems.has(key)) { gems.set(key, { name: spec[1]!, version: spec[2]!, deps: new Set() }); order.push(key); }
      current = gems.get(key); continue;
    }
    const dep = /^ {6}([A-Za-z0-9_.-]+)(?: \(.*\))?$/.exec(line);
    if (dep && current) current.deps.add(dep[1]!);
    else if (!/^ {6}/.test(line)) current = undefined;
  }
  const byName = new Map<string, Array<{ name: string; version: string }>>();
  for (const gem of gems.values()) byName.set(gem.name, [...(byName.get(gem.name) ?? []), gem]);
  return order.map(key => {
    const gem = gems.get(key)!;
    const dependsOn = [...gem.deps].flatMap(name => { const candidates = byName.get(name) ?? []; return candidates.length === 1 ? [{ name, version: candidates[0]!.version }] : []; });
    const sums = checksums.get(key);
    const hashes = sums && sums.length === 1 && sums[0] ? hexHash("SHA-256", sums[0]) : [];
    return { ecosystem: "gem" as const, name: gem.name, version: gem.version, ...(hashes.length ? { hashes } : {}), dependsOn };
  });
}

export function parseComposerLock(source: string): Component[] {
  let lock: unknown;
  try { lock = JSON.parse(source); } catch { return []; }
  if (!isObject(lock)) return [];
  const entries: Array<{ entry: Record<string, unknown>; dev: boolean }> = [];
  for (const [section, dev] of [["packages", false], ["packages-dev", true]] as const) {
    for (const entry of Array.isArray(lock[section]) ? lock[section] as unknown[] : []) if (isObject(entry) && text(entry.name) && text(entry.version)) entries.push({ entry, dev });
  }
  const version = (entry: Record<string, unknown>) => text(entry.version).replace(/^v(?=\d)/, "");
  const byName = new Map<string, { name: string; version: string }>();
  for (const { entry } of entries) byName.set(text(entry.name).toLowerCase(), { name: text(entry.name), version: version(entry) });
  return entries.map(({ entry, dev }) => {
    // `php`, `ext-*` and `lib-*` requirements are the platform, not packages.
    const dependsOn = isObject(entry.require) ? Object.keys(entry.require).flatMap(name => { const target = byName.get(name.toLowerCase()); return target ? [target] : []; }) : [];
    const hashes = isObject(entry.dist) ? hexHash("SHA-1", entry.dist.shasum) : [];
    const licenses = licenseList(entry.license);
    return { ecosystem: "composer" as const, name: text(entry.name), version: version(entry), ...(dev ? { dev: true } : {}), ...(hashes.length ? { hashes } : {}), dependsOn, ...(licenses.length ? { licenses } : {}) };
  });
}

/** NuGet `packages.lock.json`: every target framework lists its dependencies with a resolved version. */
export function parseNugetLock(source: string): Component[] {
  let lock: unknown;
  try { lock = JSON.parse(source); } catch { return []; }
  if (!isObject(lock) || !isObject(lock.dependencies)) return [];
  const found: Component[] = [];
  for (const framework of Object.values(lock.dependencies)) {
    if (!isObject(framework)) continue;
    for (const [name, entry] of Object.entries(framework)) if (isObject(entry) && text(entry.resolved) && entry.type !== "Project") found.push({ ecosystem: "nuget", name, version: text(entry.resolved) });
  }
  return found;
}

/** Gradle dependency locking: `group:artifact:version=configuration,...`. */
export function parseGradleLock(source: string): Component[] {
  const found: Component[] = [];
  for (const raw of source.split(/\r?\n/)) {
    const match = /^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^=\s:]+)=/.exec(raw.trim());
    if (match) found.push({ ecosystem: "maven", name: `${match[1]}/${match[2]}`, version: match[3]! });
  }
  return found;
}

export function parsePubspecLock(source: string): Component[] {
  let lock: unknown;
  try { lock = parseYaml(source, { schema: "core" }); } catch { return []; }
  if (!isObject(lock) || !isObject(lock.packages)) return [];
  const found: Component[] = [];
  for (const [name, entry] of Object.entries(lock.packages)) if (isObject(entry) && text(entry.version) && (entry.source === "hosted" || entry.source === undefined)) found.push({ ecosystem: "pub", name, version: text(entry.version), ...(entry.dependency === "direct dev" ? { dev: true } : {}) });
  return found;
}

/** mix.lock: `"name": {:hex, :name, "1.2.3", ...}`. */
export function parseMixLock(source: string): Component[] {
  const found: Component[] = [];
  for (const line of source.split(/\r?\n/)) {
    const match = /^\s*"([A-Za-z0-9_]+)":\s*\{:hex,\s*:[A-Za-z0-9_]+,\s*"([^"]+)"/.exec(line);
    if (match) found.push({ ecosystem: "hex", name: match[1]!, version: match[2]! });
  }
  return found;
}

/** Lockfile name to parser, with the ecosystem label shown to the user. */
export const LOCKFILES: ReadonlyArray<{ file: string; label: string; parse: (source: string) => Component[] }> = [
  { file: "package-lock.json", label: "npm", parse: parseNpmLock },
  { file: "npm-shrinkwrap.json", label: "npm", parse: parseNpmLock },
  { file: "pnpm-lock.yaml", label: "pnpm", parse: parsePnpmLock },
  { file: "yarn.lock", label: "yarn", parse: parseYarnLock },
  { file: "Cargo.lock", label: "Cargo", parse: parseCargoLock },
  { file: "go.mod", label: "Go", parse: parseGoMod },
  { file: "poetry.lock", label: "Poetry", parse: parsePoetryLock },
  { file: "Pipfile.lock", label: "Pipenv", parse: parsePipfileLock },
  { file: "requirements.txt", label: "pip (pinned)", parse: parseRequirements },
  { file: "Gemfile.lock", label: "Bundler", parse: parseGemfileLock },
  { file: "composer.lock", label: "Composer", parse: parseComposerLock },
  { file: "packages.lock.json", label: "NuGet", parse: parseNugetLock },
  { file: "gradle.lockfile", label: "Gradle", parse: parseGradleLock },
  { file: "pubspec.lock", label: "Dart/Flutter", parse: parsePubspecLock },
  { file: "mix.lock", label: "Mix", parse: parseMixLock },
];
