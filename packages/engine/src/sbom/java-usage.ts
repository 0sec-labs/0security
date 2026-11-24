/**
 * Which Maven components does the application's own source import? Reads `.java`, `.kt`, `.scala` and `.groovy` files as
 * text and matches each `import` against a component's Maven group and artifact. Nothing runs and nothing is downloaded.
 *
 * An import is not a call and a package name is not a coordinate: a library may publish classes under a package that has
 * nothing to do with its group id. So the answer is evidence, never a reachability verdict: `imported` and
 * `imported-by-group` mean source lines name the package, `no-import-found` means this scan found none (it does not mean
 * the component is unused: a transitive dependency has no import of its own).
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export type JavaUsageVerdict = "imported" | "imported-by-group" | "no-import-found";
export interface JavaImport { path: string; line: number; import: string; test: boolean }
export interface JavaUsage { purl: string; name: string; version: string; verdict: JavaUsageVerdict; imports: JavaImport[] }
export interface JavaUsageReport { usage: JavaUsage[]; filesScanned: number; truncated: boolean }

const SOURCE = /\.(?:java|kt|kts|scala|groovy)$/;
const SKIP = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".gradle", ".idea", "out"]);
const MAX_FILES = 20000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_IMPORTS_PER_COMPONENT = 50;

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

function walk(folder: string, limit: { left: number; truncated: boolean }): string[] {
  const files: string[] = [];
  const visit = (dir: string): void => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1)); } catch { return; }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { if (!SKIP.has(entry.name) && !entry.name.startsWith(".")) visit(join(dir, entry.name)); continue; }
      if (!entry.isFile() || !SOURCE.test(entry.name)) continue;
      if (limit.left <= 0) { limit.truncated = true; return; }
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

/** Match the Maven components (`group/artifact` names) against the imports of the sources under `folder`. */
export function scanJavaUsage(folder: string, components: Array<{ name: string; version: string; purl: string }>): JavaUsageReport {
  const limit = { left: MAX_FILES, truncated: false };
  const files = walk(folder, limit);
  const imports: JavaImport[] = [];
  let scanned = 0;
  for (const file of files) {
    let text: string;
    try { if (statSync(file).size > MAX_FILE_BYTES) continue; text = readFileSync(file, "utf8"); } catch { continue; }
    scanned += 1;
    const path = relative(folder, file).split("\\").join("/");
    const test = isTestPath(path);
    for (const item of parseImports(text)) imports.push({ path, line: item.line, import: item.name, test });
  }
  const usage = components.map((component): JavaUsage => {
    const { artifact, group } = prefixes(component.name);
    const exact = imports.filter(item => artifact.some(prefix => startsWithPackage(item.import, prefix)));
    const byGroup = exact.length || KNOWN_PACKAGES[component.name] ? [] : imports.filter(item => startsWithPackage(item.import, group));
    const hits = exact.length ? exact : byGroup;
    return {
      purl: component.purl, name: component.name, version: component.version,
      verdict: exact.length ? "imported" : byGroup.length ? "imported-by-group" : "no-import-found",
      imports: hits.slice(0, MAX_IMPORTS_PER_COMPONENT),
    };
  });
  return { usage, filesScanned: scanned, truncated: limit.truncated };
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
  if (report.truncated) lines.push(`Stopped after ${MAX_FILES} files.`);
  return `${lines.join("\n")}\n`;
}
