/**
 * Bump one vulnerable Maven or Gradle dependency to the version an advisory says fixes it, by editing the place where the
 * version is set. Text only: nothing is run, downloaded or looked up, and the fixed version is always the one the caller
 * passes (the lowest fixed version from the advisory), never one this code picks.
 *
 * It edits only what the repository itself says:
 * - Maven: a literal `<version>`, a `<properties>` entry the version points at, or a `<dependencyManagement>` entry, in a
 *   `pom.xml` of the repository.
 * - Gradle: a literal `group:artifact:version` in `build.gradle` or `build.gradle.kts`, and a version catalog entry in
 *   `gradle/libs.versions.toml` (literal version or a `version.ref` into `[versions]`).
 * It never lowers a version, and it declines (with a reason) when the version comes from somewhere it cannot see: a parent POM
 * or BOM outside the repository, a Gradle variable, a range. The caller then hands the case to a person or a model.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { compareVersions } from "./advisory-facts.js";

export interface BumpRequest { name: string; fixedVersion: string; /** The version the finding names, to avoid editing another version of the same package. */ currentVersion?: string }
export interface BumpEdit { path: string; line: number; was: string; now: string; where: string }
export type BumpResult = { applied: true; edits: BumpEdit[] } | { applied: false; reason: string };

const SKIP = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".gradle", ".idea", "out"]);
const MAX_FILES = 200;
const VERSION = /^[0-9][0-9A-Za-z._+-]*$/;
const escape = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const lineOf = (text: string, index: number): number => text.slice(0, index).split("\n").length;
const lower = (current: string, fixed: string): boolean => compareVersions(current, fixed) < 0;

function files(folder: string, match: RegExp): string[] {
  const found: string[] = [];
  const visit = (dir: string, depth: number): void => {
    if (found.length >= MAX_FILES || depth > 6) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1)); } catch { return; }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) { if (!SKIP.has(entry.name) && !entry.name.startsWith(".")) visit(path, depth + 1); }
      else if (entry.isFile() && match.test(path.split("\\").join("/"))) found.push(path);
    }
  };
  visit(folder, 0);
  return found;
}

/** `<dependency>` blocks of a pom that name this package, with the position of the version text. */
function mavenBlocks(text: string, group: string, artifact: string): Array<{ start: number; block: string }> {
  const blocks: Array<{ start: number; block: string }> = [];
  const pattern = /<dependency>([\s\S]*?)<\/dependency>/g;
  for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
    const body = match[1]!;
    const g = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(body)?.[1];
    const a = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(body)?.[1];
    if (g === group && a === artifact) blocks.push({ start: match.index + "<dependency>".length, block: body });
  }
  return blocks;
}

function bumpMaven(folder: string, request: BumpRequest): BumpResult {
  const [group, artifact] = request.name.split("/");
  if (!group || !artifact) return { applied: false, reason: `'${request.name}' is not group/artifact.` };
  const poms = files(folder, /(^|\/)pom\.xml$/);
  const sources = new Map(poms.map(path => [path, readFileSync(path, "utf8")]));
  const edits = new Map<string, Array<{ index: number; length: number; now: string; edit: BumpEdit }>>();
  const add = (path: string, index: number, was: string, now: string, where: string): void => {
    const text = sources.get(path)!;
    const list = edits.get(path) ?? [];
    if (!list.some(item => item.index === index)) list.push({ index, length: was.length, now, edit: { path: relative(folder, path).split("\\").join("/"), line: lineOf(text, index), was, now, where } });
    edits.set(path, list);
  };
  const reasons: string[] = [];
  let found = false;
  for (const [path, text] of sources) {
    for (const { start, block } of mavenBlocks(text, group, artifact)) {
      found = true;
      const version = /<version>\s*([^<]*?)\s*<\/version>/.exec(block);
      if (!version) continue; // managed in a dependencyManagement entry: handled when that block is visited
      const at = start + version.index + version[0].indexOf(version[1]!);
      const value = version[1]!;
      const property = /^\$\{([^}]+)\}$/.exec(value)?.[1];
      if (!property) {
        if (!VERSION.test(value)) { reasons.push(`the version '${value}' in ${relative(folder, path)} is a range or placeholder`); continue; }
        if (request.currentVersion && value !== request.currentVersion) continue;
        if (lower(value, request.fixedVersion)) add(path, at, value, request.fixedVersion, "version");
        continue;
      }
      // A property: change its definition in a pom of the repository, never add a second version next to it.
      let defined = false;
      for (const [otherPath, other] of sources) {
        const definition = new RegExp(`<${escape(property)}>\\s*([^<]*?)\\s*</${escape(property)}>`).exec(other);
        if (!definition) continue;
        defined = true;
        const current = definition[1]!;
        if (!VERSION.test(current)) { reasons.push(`the property ${property} is '${current}'`); continue; }
        if (request.currentVersion && current !== request.currentVersion) continue;
        if (lower(current, request.fixedVersion)) add(otherPath, definition.index + definition[0].indexOf(current), current, request.fixedVersion, `property ${property}`);
      }
      if (!defined) reasons.push(`the property ${property} is not defined in the repository (a parent or BOM outside it sets it)`);
    }
  }
  if (!found) return { applied: false, reason: `${request.name} is not declared in any pom.xml of the repository (a transitive dependency, or set by a parent or BOM outside it).` };
  const all = [...edits.entries()];
  if (!all.length) return { applied: false, reason: reasons.length ? `Not changed: ${[...new Set(reasons)].join("; ")}.` : `${request.name} is already at ${request.fixedVersion} or newer.` };
  const applied: BumpEdit[] = [];
  for (const [path, list] of all) {
    let text = sources.get(path)!;
    for (const item of list.sort((a, b) => b.index - a.index)) text = `${text.slice(0, item.index)}${item.now}${text.slice(item.index + item.length)}`;
    writeFileSync(path, text);
    applied.push(...list.map(item => item.edit));
  }
  return { applied: true, edits: applied.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.line - b.line)) };
}

function bumpGradle(folder: string, request: BumpRequest): BumpResult {
  const [group, artifact] = request.name.split("/");
  if (!group || !artifact) return { applied: false, reason: `'${request.name}' is not group/artifact.` };
  const edits: BumpEdit[] = [];
  const reasons: string[] = [];
  let found = false;
  const coordinate = new RegExp(`(["'])${escape(group)}:${escape(artifact)}:([^"':\\s]+)\\1`, "g");
  for (const path of files(folder, /(^|\/)build\.gradle(\.kts)?$/)) {
    let text = readFileSync(path, "utf8");
    let changed = false;
    text = text.replace(coordinate, (whole, quote: string, version: string, offset: number) => {
      found = true;
      if (!VERSION.test(version)) { reasons.push(`the version '${version}' in ${relative(folder, path)} is a variable or a range`); return whole; }
      if (request.currentVersion && version !== request.currentVersion) return whole;
      if (!lower(version, request.fixedVersion)) return whole;
      changed = true;
      edits.push({ path: relative(folder, path).split("\\").join("/"), line: lineOf(text, offset), was: version, now: request.fixedVersion, where: "version" });
      return `${quote}${group}:${artifact}:${request.fixedVersion}${quote}`;
    });
    if (changed) writeFileSync(path, text);
  }
  for (const path of files(folder, /(^|\/)libs\.versions\.toml$/)) {
    let text = readFileSync(path, "utf8");
    const libraries = [...text.matchAll(/^([\w.-]+)\s*=\s*(\{[^}\n]*\}|"[^"\n]*")(?:\s*#[^\n]*)?\s*$/gm)];
    for (const library of libraries) {
      const body = library[2]!;
      const module = /module\s*=\s*"([^"]+)"/.exec(body)?.[1] ?? (/^"([^":]+:[^":]+):[^"]+"$/.exec(body)?.[1]);
      const g = /group\s*=\s*"([^"]+)"/.exec(body)?.[1];
      const a = /name\s*=\s*"([^"]+)"/.exec(body)?.[1];
      const split = g && a ? `${g}:${a}` : undefined;
      if ((module ?? split) !== `${group}:${artifact}`) continue;
      found = true;
      const ref = /version\.ref\s*=\s*"([^"]+)"/.exec(body)?.[1];
      let target: { was: string; index: number; where: string } | undefined;
      if (ref) {
        // `[ \t]` rather than `\s`: with `m`, `^\s*` runs across every blank line that follows, quadratic on a file of newlines.
        const section = /^[ \t]*\[versions\][ \t]*$/m.exec(text);
        if (section) {
          const start = section.index + section[0].length;
          const next = text.slice(start).search(/^[ \t]*\[/m);
          const end = next === -1 ? text.length : start + next;
          const block = text.slice(start, end);
          const match = new RegExp(`^(${escape(ref)}\\s*=\\s*")([^"]+)(")`, "m").exec(block);
          if (match) target = { was: match[2]!, index: start + match.index + match[1]!.length, where: `version ${ref}` };
        }
      } else {
        const vMatch = /version\s*=\s*"([^"]+)"/.exec(body);
        if (vMatch) {
          const at = library.index! + library[0]!.indexOf(body) + vMatch.index + vMatch[0].indexOf(vMatch[1]!);
          target = { was: vMatch[1]!, index: at, where: "version" };
        } else {
          const short = /^"[^":]+:[^":]+:([^"]+)"$/.exec(body);
          if (short) {
            const was = short[1]!;
            target = { was, index: library.index! + library[0]!.indexOf(body) + body.lastIndexOf(was), where: "version" };
          }
        }
      }
      if (!target) { reasons.push(`the catalog entry ${library[1]} has no version I can read`); continue; }
      if (!VERSION.test(target.was)) { reasons.push(`the catalog version '${target.was}' is a range`); continue; }
      if (request.currentVersion && target.was !== request.currentVersion) continue;
      if (!lower(target.was, request.fixedVersion)) continue;
      edits.push({ path: relative(folder, path).split("\\").join("/"), line: lineOf(text, target.index), was: target.was, now: request.fixedVersion, where: target.where });
      text = `${text.slice(0, target.index)}${request.fixedVersion}${text.slice(target.index + target.was.length)}`;
      writeFileSync(path, text);
      break;
    }
  }
  if (edits.length) return { applied: true, edits };
  if (!found) return { applied: false, reason: `${request.name} is not declared with a literal version in a build.gradle, build.gradle.kts or gradle/libs.versions.toml of the repository.` };
  return { applied: false, reason: reasons.length ? `Not changed: ${[...new Set(reasons)].join("; ")}.` : `${request.name} is already at ${request.fixedVersion} or newer.` };
}

/** Try Maven, then Gradle. The first build system that has the package decides; a package found in neither is not applied. */
export function bumpJavaDependency(folder: string, request: BumpRequest): BumpResult {
  if (!VERSION.test(request.fixedVersion)) return { applied: false, reason: `'${request.fixedVersion}' is not a version.` };
  const maven = bumpMaven(folder, request);
  if (maven.applied) return maven;
  const gradle = bumpGradle(folder, request);
  if (gradle.applied) return gradle;
  return { applied: false, reason: /is not declared/.test(maven.reason) ? gradle.reason : maven.reason };
}

/**
 * Read what a dependency finding says: `<group>/<artifact> <version> has <advisory>: ... Fixed in <version>.` (the text of
 * `0 sbom check` results imported as findings). Returns nothing for any other finding, so a model handles it.
 */
export function parseDependencyFinding(text: string): { name: string; currentVersion: string; fixedVersion: string } | undefined {
  const head = /(?:^|\s)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\s+([0-9][0-9A-Za-z._+-]*)\s+has\s+(?:GHSA|CVE|OSV|PYSEC|GO|RUSTSEC)-/.exec(text);
  const fixed = /Fixed in ([0-9][0-9A-Za-z._+-]*?)\.(?:\s|$)/.exec(text);
  return head && fixed ? { name: head[1]!, currentVersion: head[2]!, fixedVersion: fixed[1]! } : undefined;
}
