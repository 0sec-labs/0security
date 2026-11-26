/**
 * Which Maven components does the application's own source import? Reads `.java`, `.kt`, `.scala` and `.groovy` files as
 * text and matches each `import` against a component's Maven group and artifact. Nothing runs and nothing is downloaded.
 *
 * An import is not a call and a package name is not a coordinate: a library may publish classes under a package that has
 * nothing to do with its group id. So the answer is evidence, never a reachability verdict: `imported` and
 * `imported-by-group` mean source lines name the package, `no-import-found` means this scan found none (it does not mean
 * the component is unused: a transitive dependency has no import of its own).
 */
import { opendirSync, readFileSync, statSync, type Dirent } from "node:fs";
import { join, relative } from "node:path";

export type JavaUsageVerdict = "imported" | "imported-by-group" | "no-import-found";
export interface JavaImport { path: string; line: number; import: string; test: boolean }
export interface JavaUsage { purl: string; name: string; version: string; verdict: JavaUsageVerdict; imports: JavaImport[] }
/** A place a vulnerable class or symbol that an advisory lists appears in source: in an import, or written out in full. */
export interface JavaSymbolHit { symbol: string; path: string; line: number; test: boolean; kind: "import" | "qualified" }
export interface JavaUsageReport { usage: JavaUsage[]; filesScanned: number; truncated: boolean; /** Source files or links that were not read: over the size cap, unreadable, or a symbolic link. */ skipped: number; symbolHits?: JavaSymbolHit[] }
export interface JavaUsageOptions {
  /** Fully qualified classes or symbols to look for in imports and in fully qualified uses. */ symbols?: string[];
  /** Lower limits than the defaults, for tests of a hostile tree. */ limits?: { maxFiles?: number; maxTotalBytes?: number; maxSymbols?: number; maxEntries?: number; maxSymbolChecks?: number; maxMatchWork?: number };
}

const SOURCE = /\.(?:java|kt|kts|scala|groovy)$/;
/** Folders of tools and dependencies: never application source. */
const TOOL_FOLDERS = new Set(["node_modules", ".git", ".gradle", ".idea", ".mvn"]);
/** Build output and vendored folders: not read, and reported when one holds a `src` tree. Hidden folders are read. */
const SKIP = new Set(["dist", "build", "target", "vendor", "out"]);
/** A bounded look (at most 200 entries, four levels, no links) in a folder that is not read. True when it holds a source file, and also when the look could not finish: an unfinished look proves nothing. */
function holdsSource(root: string): boolean {
  let budget = 200;
  const look = (dir: string, depth: number): boolean => {
    let handle;
    try { handle = opendirSync(dir); } catch { return true; }
    try {
      for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
        budget -= 1;
        if (budget < 0) return true;
        if (entry.isSymbolicLink()) continue;
        if (entry.isFile() && SOURCE.test(entry.name)) return true;
        if (entry.isDirectory()) { if (depth >= 4 || look(join(dir, entry.name), depth + 1)) return true; }
      }
    } catch { return true; } finally { handle.closeSync(); }
    return false;
  };
  return look(root, 0);
}
const MAX_FILES = 20000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_IMPORTS_PER_COMPONENT = 50;
const MAX_DEPTH = 40;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_SYMBOLS = 200;
const MAX_HITS_PER_SYMBOL = 20;
/** Directory entries looked at in one scan, and imports kept (in total and per file), so a hostile tree cannot use unbounded time or memory. */
const MAX_ENTRIES = 300_000;
const MAX_IMPORTS_TOTAL = 400_000;
const MAX_IMPORTS_PER_FILE = 5000;
/** Line-by-symbol comparisons in one scan (lines times symbols), so many symbols over a large tree cannot run unbounded. */
const MAX_SYMBOL_CHECKS = 50_000_000;
/** Imports compared with components (and sorted) in one scan; a component past this gets no answer and the scan is incomplete. */
const MAX_MATCH_WORK = 200_000_000;
/** A line longer than this is minified or hostile text: it is not searched for symbols. */
const MAX_LINE_CHARS = 4000;

/** Libraries whose classes live under a package that differs from group and artifact. Only well-known ones; the rest match by group. */
const KNOWN_PACKAGES: Record<string, string[]> = {
  "com.google.guava/guava": ["com.google.common"],
  "junit/junit": ["org.junit", "junit.framework"],
  "org.junit.jupiter/junit-jupiter-api": ["org.junit.jupiter.api"],
  "org.apache.logging.log4j/log4j-core": ["org.apache.logging.log4j"],
  "org.apache.logging.log4j/log4j-api": ["org.apache.logging.log4j"],
  "org.apache.commons/commons-lang3": ["org.apache.commons.lang3"],
  "org.apache.commons/commons-text": ["org.apache.commons.text"],
  "commons-io/commons-io": ["org.apache.commons.io"],
  "commons-codec/commons-codec": ["org.apache.commons.codec"],
  "commons-collections/commons-collections": ["org.apache.commons.collections"],
  "commons-fileupload/commons-fileupload": ["org.apache.commons.fileupload"],
  "org.yaml/snakeyaml": ["org.yaml.snakeyaml"],
  "ch.qos.logback/logback-classic": ["ch.qos.logback"],
  "org.apache.httpcomponents/httpclient": ["org.apache.http"],
  "com.squareup.okhttp3/okhttp": ["okhttp3"],
  "org.springframework.boot/spring-boot-starter-web": ["org.springframework.web", "org.springframework.boot"],
};

/** `import a.b.C;`, Kotlin and Scala `import a.b.C`, Scala `import a.b.{C, D}`, Java `import static a.b.C.m;`. */
export function parseImports(text: string): Array<{ line: number; name: string }> {
  const found: Array<{ line: number; name: string }> = [];
  let block = false;
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    let line = lines[index]!;
    if (block) { const end = line.indexOf("*/"); if (end < 0) continue; line = line.slice(end + 2); block = false; }
    line = line.replace(/\/\*.*?\*\//g, " ");
    const open = line.indexOf("/*");
    if (open >= 0) { line = line.slice(0, open); block = true; }
    const match = /^\s*import\s+(?:static\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$*][\w$*]*)*)/.exec(line);
    if (match) found.push({ line: index + 1, name: match[1]! });
  }
  return found;
}

function walk(folder: string, limit: { left: number; truncated: boolean; skipped: number; entries: number }, maxEntries: number): string[] {
  const files: string[] = [];
  const visit = (dir: string, depth = 0): void => {
    if (limit.entries > maxEntries) { limit.truncated = true; return; }
    if (depth > MAX_DEPTH) { limit.truncated = true; limit.skipped += 1; return; }
    const entries: Dirent[] = [];
    try {
      const handle = opendirSync(dir);
      try {
        for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
          limit.entries += 1;
          if (limit.entries > maxEntries) { limit.truncated = true; break; }
          entries.push(entry);
        }
      } finally { handle.closeSync(); }
    } catch { limit.truncated = true; limit.skipped += 1; }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      if (limit.entries > maxEntries) { limit.truncated = true; return; }
      if (entry.isSymbolicLink()) { limit.skipped += 1; continue; }
      if (entry.isDirectory()) {
        // Tool, build-output and dependency folders are not read. One that holds a source file is reported as not scanned.
        if (TOOL_FOLDERS.has(entry.name) || SKIP.has(entry.name)) { if (holdsSource(join(dir, entry.name))) limit.skipped += 1; continue; }
        visit(join(dir, entry.name), depth + 1);
        continue;
      }
      if (!entry.isFile() || !SOURCE.test(entry.name)) continue;
      if (limit.left <= 0) { limit.truncated = true; limit.skipped += 1; continue; }
      limit.left -= 1;
      files.push(join(dir, entry.name));
    }
  };
  visit(folder);
  return files;
}

const isTestPath = (path: string): boolean => /(^|\/)(src\/(?:test|integrationTest|testFixtures)|test|tests)\//.test(path);

/** Prefixes that name this artifact exactly, and the group prefix that only suggests it. */
function prefixes(name: string): { artifact: string[]; group: string } {
  const [group = "", artifact = ""] = name.split("/");
  const dotted = artifact.replace(/-/g, ".");
  const joined = artifact.replace(/-/g, "");
  const known = KNOWN_PACKAGES[name] ?? [];
  return { artifact: [...new Set([...known, `${group}.${dotted}`, `${group}.${joined}`])], group };
}
const startsWithPackage = (name: string, prefix: string): boolean => name === prefix || name.startsWith(`${prefix}.`);

const isIdentChar = (char: string | undefined): boolean => char !== undefined && /[\w$]/.test(char);
/** True when `symbol` is written out in full on the line: not as the tail of a longer name, not as the head of a longer identifier. */
function mentionsQualified(line: string, symbol: string): boolean {
  let from = 0;
  for (;;) {
    const at = line.indexOf(symbol, from);
    if (at < 0) return false;
    const before = at > 0 ? line[at - 1] : undefined;
    const after = line[at + symbol.length];
    if (!isIdentChar(before) && before !== "." && !isIdentChar(after)) return true;
    from = at + 1;
  }
}
/** An import names the symbol when it is the symbol, a member of it, or the class that owns a method symbol. */
const importNames = (name: string, symbol: string): boolean => name === symbol || name.startsWith(`${symbol}.`) || symbol.startsWith(`${name}.`);

/** Match the Maven components (`group/artifact` names) against the imports of the sources under `folder`, and optionally look for fully qualified symbols. */
export function scanJavaUsage(folder: string, components: Array<{ name: string; version: string; purl: string }>, options: JavaUsageOptions = {}): JavaUsageReport {
  const limit = { left: options.limits?.maxFiles ?? MAX_FILES, truncated: false, skipped: 0, entries: 0 };
  const files = walk(folder, limit, options.limits?.maxEntries ?? MAX_ENTRIES);
  const wanted = [...new Set(options.symbols ?? [])];
  // Symbols beyond the cap are never searched, so the scan cannot call their advisories not imported.
  const maxSymbols = options.limits?.maxSymbols ?? MAX_SYMBOLS;
  const maxTotalBytes = options.limits?.maxTotalBytes ?? MAX_TOTAL_BYTES;
  if (wanted.length > maxSymbols) limit.truncated = true;
  const symbols = wanted.slice(0, maxSymbols);
  const symbolHits: JavaSymbolHit[] = [];
  const hitCount = new Map<string, number>();
  const addHit = (hit: JavaSymbolHit): void => {
    // Counted apart for test and application code, so test hits cannot crowd out an application hit.
    const key = `${hit.symbol}\u0000${hit.test}`;
    const count = hitCount.get(key) ?? 0;
    if (count >= MAX_HITS_PER_SYMBOL) return;
    hitCount.set(key, count + 1);
    symbolHits.push(hit);
  };
  const maxChecks = options.limits?.maxSymbolChecks ?? MAX_SYMBOL_CHECKS;
  let checks = 0;
  let searching = symbols.length > 0;
  let longLine = false;
  const imports: JavaImport[] = [];
  let scanned = 0;
  let bytes = 0;
  for (const [position, file] of files.entries()) {
    let text: string;
    try {
      const size = statSync(file).size;
      if (size > MAX_FILE_BYTES) { limit.truncated = true; limit.skipped += 1; continue; }
      bytes += size;
      if (bytes > maxTotalBytes) { limit.truncated = true; limit.skipped += files.length - position; break; }
      text = readFileSync(file, "utf8");
    } catch { limit.truncated = true; limit.skipped += 1; continue; }
    scanned += 1;
    const path = relative(folder, file).split("\\").join("/");
    const test = isTestPath(path);
    const found = parseImports(text);
    if (found.length > MAX_IMPORTS_PER_FILE) { limit.skipped += 1; limit.truncated = true; }
    for (const item of found.slice(0, MAX_IMPORTS_PER_FILE)) {
      if (imports.length >= MAX_IMPORTS_TOTAL) { limit.truncated = true; break; }
      imports.push({ path, line: item.line, import: item.name, test });
    }
    if (!searching) continue;
    const importLines = new Set(found.map(item => item.line));
    for (const item of found) {
      checks += symbols.length;
      if (checks > maxChecks) break;
      for (const symbol of symbols) if (importNames(item.name, symbol)) addHit({ symbol, path, line: item.line, test, kind: "import" });
    }
    if (checks > maxChecks) { searching = false; limit.truncated = true; limit.skipped += files.length - position; continue; }
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index]!;
      if (importLines.has(index + 1)) continue;
      // A line this long is not searched, and a symbol could hide in it: the scan is then incomplete, never a not-imported answer.
      if (line.length > MAX_LINE_CHARS) { if (!longLine) { longLine = true; limit.truncated = true; } limit.skipped += 1; continue; }
      checks += symbols.length;
      if (checks > maxChecks) { searching = false; limit.truncated = true; limit.skipped += files.length - position; break; }
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
      for (const symbol of symbols) if (line.includes(symbol) && mentionsQualified(line, symbol)) addHit({ symbol, path, line: index + 1, test, kind: "qualified" });
    }
  }
  const artifactPrefixes = components.flatMap(component => prefixes(component.name).artifact);
  // Do not credit an exact artifact import to every sibling with the same Maven group.
  const maxWork = options.limits?.maxMatchWork ?? MAX_MATCH_WORK;
  // The cross product of imports and component prefixes is bounded before it runs.
  const crossWork = imports.length * (artifactPrefixes.length + components.length * 4);
  if (crossWork > maxWork) limit.truncated = true;
  const groupCandidates = crossWork > maxWork ? [] : imports.filter(item => !artifactPrefixes.some(prefix => startsWithPackage(item.import, prefix)));
  let work = Math.min(crossWork, maxWork);
  const usage = components.map((component): JavaUsage => {
    work += imports.length * 8;
    if (work > maxWork) {
      limit.truncated = true;
      return { purl: component.purl, name: component.name, version: component.version, verdict: "no-import-found", imports: [] };
    }
    const { artifact, group } = prefixes(component.name);
    const exact = imports.filter(item => artifact.some(prefix => startsWithPackage(item.import, prefix)));
    const byGroup = exact.length || KNOWN_PACKAGES[component.name] ? [] : groupCandidates.filter(item => startsWithPackage(item.import, group));
    // Application code first, so the cap never hides the lines that matter behind test imports.
    work += (exact.length || byGroup.length) * 8;
    const hits = [...(exact.length ? exact : byGroup)].sort((a, b) => Number(a.test) - Number(b.test));
    return {
      purl: component.purl, name: component.name, version: component.version,
      verdict: exact.length ? "imported" : byGroup.length ? "imported-by-group" : "no-import-found",
      imports: hits.slice(0, MAX_IMPORTS_PER_COMPONENT),
    };
  });
  return { usage, filesScanned: scanned, truncated: limit.truncated, skipped: limit.skipped, ...(symbols.length ? { symbolHits } : {}) };
}

/** Text for a terminal: one block per component that is imported, then a count of the others. */
export function javaUsageToText(report: JavaUsageReport): string {
  const lines: string[] = [];
  const hit = report.usage.filter(item => item.verdict !== "no-import-found");
  for (const item of hit) {
    lines.push(`${item.name} ${item.version}  ${item.verdict === "imported" ? "imported" : "imported (matched by group only)"}`);
    for (const entry of item.imports.slice(0, 5)) lines.push(`  ${entry.path}:${entry.line}  ${entry.import}${entry.test ? "  (test code)" : ""}`);
    if (item.imports.length > 5) lines.push(`  and ${item.imports.length - 5} more`);
  }
  const none = report.usage.length - hit.length;
  lines.push(`${hit.length} of ${report.usage.length} Maven components are imported by the ${report.filesScanned} source files read; ${none} have no import in the application's own code (normal for a transitive dependency).`);
  lines.push("An import is not a call: this shows where a package is named, not that a vulnerable method runs.");
  if (report.truncated) lines.push(`Source evidence is incomplete (file, import or readability limit).`);
  return `${lines.join("\n")}\n`;
}
