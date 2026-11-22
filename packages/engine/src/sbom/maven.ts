/**
 * Maven `pom.xml` reader. Files are read as text: nothing is run, nothing is downloaded, and no XML entity or DOCTYPE is
 * expanded. A version is reported only when it follows from the poms in the repository (literal, `<properties>`,
 * `<dependencyManagement>`, an in-repo parent, an in-repo imported BOM). Anything else is listed as unresolved, never guessed.
 */
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { Component } from "./parsers.js";

export interface Unresolved {
  /** The file the declaration is in, relative to the scanned folder. */
  source: string;
  /** Coordinates as written (`group:artifact`), or what was skipped (`profile:name`, `module:path`). */
  name: string;
  reason: string;
}
export interface JvmFile { path: string; label: string; components: Component[] }

interface XmlNode { name: string; text: string; children: XmlNode[] }
const MAX_XML_DEPTH = 64;
const ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: "\"", apos: "'" };
const decode = (value: string): string => value.replace(/&(lt|gt|amp|quot|apos);/g, (_, name: string) => ENTITIES[name]!);

/** A small non-validating XML reader: elements and text only. Attributes, comments, processing instructions and DOCTYPE are dropped; entities beyond the five predefined ones are left as written. */
export function parseXml(source: string): XmlNode | undefined {
  const token = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/([\w:.-]+)\s*>|<([\w:.-]+)(?:\s[^<>]*?)?(\/?)>|([^<]+)/g;
  const root: XmlNode = { name: "#root", text: "", children: [] };
  const stack: XmlNode[] = [root];
  for (const match of source.matchAll(token)) {
    const top = stack[stack.length - 1]!;
    if (match[1] !== undefined) top.text += match[1];
    else if (match[2] !== undefined) { if (stack.length > 1 && top.name === match[2].replace(/^.*:/, "")) stack.pop(); }
    else if (match[3] !== undefined) {
      const node: XmlNode = { name: match[3].replace(/^.*:/, ""), text: "", children: [] };
      top.children.push(node);
      if (!match[4]) { if (stack.length >= MAX_XML_DEPTH) return undefined; stack.push(node); }
    } else if (match[5] !== undefined) top.text += decode(match[5]);
  }
  return root.children[0];
}
const child = (node: XmlNode | undefined, name: string): XmlNode | undefined => node?.children.find(item => item.name === name);
const childText = (node: XmlNode | undefined, name: string): string => child(node, name)?.text.trim() ?? "";
const childrenOf = (node: XmlNode | undefined, name: string): XmlNode[] => node?.children.filter(item => item.name === name) ?? [];

interface RawDep { g: string; a: string; v: string; scope: string; type: string; classifier: string; source: string }
interface Pom {
  path: string; dir: string; rel: string;
  g: string; a: string; v: string;
  parent?: { g: string; a: string; v: string; relativePath: string | undefined };
  props: Map<string, string>;
  mgmt: RawDep[];
  deps: RawDep[];
  modules: string[];
  profiles: Array<{ id: string; deps: RawDep[]; other: boolean }>;
}

const dependency = (node: XmlNode, source: string): RawDep => ({
  g: childText(node, "groupId"), a: childText(node, "artifactId"), v: childText(node, "version"),
  scope: childText(node, "scope"), type: childText(node, "type") || "jar", classifier: childText(node, "classifier"), source,
});
const depKey = (dep: { g: string; a: string; type: string; classifier: string }) => `${dep.g}:${dep.a}:${dep.type}:${dep.classifier}`;

function readPom(path: string, rel: string, source: string): Pom | undefined {
  const project = parseXml(source);
  if (!project || project.name !== "project") return undefined;
  const parentNode = child(project, "parent");
  const parent = parentNode ? { g: childText(parentNode, "groupId"), a: childText(parentNode, "artifactId"), v: childText(parentNode, "version"), relativePath: child(parentNode, "relativePath") ? childText(parentNode, "relativePath") : undefined } : undefined;
  const a = childText(project, "artifactId");
  if (!a) return undefined;
  const props = new Map<string, string>();
  for (const node of child(project, "properties")?.children ?? []) props.set(node.name, node.text.trim());
  const list = (node: XmlNode | undefined) => childrenOf(child(node, "dependencies"), "dependency").map(item => dependency(item, rel));
  return {
    path, dir: dirname(path), rel,
    g: childText(project, "groupId") || parent?.g || "", a, v: childText(project, "version") || parent?.v || "",
    ...(parent ? { parent } : {}),
    props,
    mgmt: list(child(project, "dependencyManagement")),
    deps: list(project),
    modules: childrenOf(child(project, "modules"), "module").map(node => node.text.trim()).filter(Boolean),
    profiles: childrenOf(child(project, "profiles"), "profile").map(profile => ({
      id: childText(profile, "id") || "(unnamed)",
      deps: [...list(profile), ...list(child(profile, "dependencyManagement"))],
      other: !!child(profile, "properties")?.children.length,
    })),
  };
}

const PLACEHOLDER = /\$\{([^}]+)\}/g;
function interpolate(value: string, props: Map<string, string>): string {
  let current = value;
  for (let round = 0; round < 10 && current.includes("${"); round += 1) {
    const next = current.replace(PLACEHOLDER, (whole, name: string) => props.get(name.trim()) ?? whole);
    if (next === current) break;
    current = next;
  }
  return current;
}
const hasPlaceholder = (value: string) => value.includes("${");
/** A version that names exactly one release. A range, `LATEST` or `RELEASE` does not; `[1.2]` is a hard pin to 1.2. */
function pinnedVersion(version: string): string | undefined {
  const hard = /^\[([^,\]()[]+)\]$/.exec(version);
  const value = hard ? hard[1]! : version;
  if (!value || /[,[\]()\s]/.test(value) || /^(LATEST|RELEASE)$/.test(value) || hasPlaceholder(value)) return undefined;
  return value;
}

export interface MavenInput { path: string; rel: string; source: string }

/** Resolve every `pom.xml` among the inputs against the others. Returns one entry per readable pom, plus what could not be resolved. */
export function analyzeMaven(inputs: MavenInput[]): { files: JvmFile[]; unresolved: Unresolved[] } {
  const poms: Pom[] = [];
  for (const input of inputs) { const pom = readPom(resolve(input.path), input.rel, input.source); if (pom) poms.push(pom); }
  const byPath = new Map(poms.map(pom => [pom.path, pom]));
  const byCoord = new Map<string, Pom>();
  for (const pom of poms) if (pom.g && !byCoord.has(`${pom.g}:${pom.a}`)) byCoord.set(`${pom.g}:${pom.a}`, pom);

  const parentOf = (pom: Pom): Pom | undefined => {
    const wanted = pom.parent;
    if (!wanted) return undefined;
    const relative = wanted.relativePath ?? "../pom.xml";
    if (relative !== "") {
      let target = isAbsolute(relative) ? relative : resolve(pom.dir, relative);
      if (!target.endsWith(".xml")) target = join(target, "pom.xml");
      const found = byPath.get(target);
      if (found && found.a === wanted.a && found.g === wanted.g) return found;
    }
    const indexed = byCoord.get(`${wanted.g}:${wanted.a}`);
    return indexed && indexed !== pom ? indexed : undefined;
  };
  /** The pom and its in-repo ancestors, root first. Stops at a cycle. */
  const lineage = (pom: Pom): Pom[] => {
    const chain: Pom[] = [];
    const seen = new Set<Pom>();
    for (let current: Pom | undefined = pom; current && !seen.has(current); current = parentOf(current)) { seen.add(current); chain.unshift(current); }
    return chain;
  };
  const propsOf = (pom: Pom): Map<string, string> => {
    const props = new Map<string, string>();
    for (const member of lineage(pom)) {
      for (const [name, value] of member.props) props.set(name, value);
      for (const prefix of ["project", "pom"]) {
        props.set(`${prefix}.groupId`, member.g); props.set(`${prefix}.artifactId`, member.a); props.set(`${prefix}.version`, member.v);
        if (member.parent) { props.set(`${prefix}.parent.groupId`, member.parent.g); props.set(`${prefix}.parent.artifactId`, member.parent.a); props.set(`${prefix}.parent.version`, member.parent.v); }
      }
    }
    return props;
  };

  interface Managed { version: string; scope: string }
  const managedMemo = new Map<Pom, Map<string, Managed>>();
  const bomProblems: Unresolved[] = [];
  /** Versions this pom manages: its own and inherited `dependencyManagement`, then the BOMs it imports (never overriding a direct entry). */
  const managedOf = (pom: Pom, active = new Set<Pom>()): Map<string, Managed> => {
    const known = managedMemo.get(pom);
    if (known) return known;
    const result = new Map<string, Managed>();
    if (active.has(pom)) return result;
    active.add(pom);
    const props = propsOf(pom);
    const imports: RawDep[] = [];
    for (const member of lineage(pom)) {
      for (const entry of member.mgmt) {
        if (entry.scope === "import" && entry.type === "pom") { imports.push(entry); continue; }
        const g = interpolate(entry.g, props); const a = interpolate(entry.a, props);
        result.set(`${g}:${a}:${entry.type}:${entry.classifier}`, { version: interpolate(entry.v, props), scope: entry.scope });
      }
    }
    for (const entry of imports) {
      const g = interpolate(entry.g, props); const a = interpolate(entry.a, props); const v = interpolate(entry.v, props);
      const bom = byCoord.get(`${g}:${a}`);
      if (!bom || (pinnedVersion(v) && bom.v && !hasPlaceholder(bom.v) && bom.v !== v)) {
        bomProblems.push({ source: entry.source, name: `${g}:${a}`, reason: bom ? `imported BOM ${g}:${a}:${v} is not the version in the repository (${bom.v}); the versions it manages are unresolved` : `imported BOM ${g}:${a}:${v} is not in the repository; the versions it manages are unresolved` });
        continue;
      }
      for (const [key, value] of managedOf(bom, active)) if (!result.has(key)) result.set(key, value);
    }
    active.delete(pom);
    managedMemo.set(pom, result);
    return result;
  };

  const unresolved: Unresolved[] = [];
  const files: JvmFile[] = [];
  const modulePoms = new Set(poms.map(pom => pom.path));
  for (const pom of poms) {
    const chain = lineage(pom);
    const props = propsOf(pom);
    if (pom.parent && !parentOf(pom)) unresolved.push({ source: pom.rel, name: `parent:${pom.parent.g}:${pom.parent.a}:${pom.parent.v}`, reason: "parent POM is not in the repository; its properties, dependencyManagement and dependencies are not analysed" });
    managedOf(pom);
    for (const module of pom.modules) {
      const target = resolve(pom.dir, module);
      if (!modulePoms.has(target.endsWith(".xml") ? target : join(target, "pom.xml")) && !(existsSync(join(target, "pom.xml")))) unresolved.push({ source: pom.rel, name: `module:${module}`, reason: "module POM was not found in the repository" });
    }
    for (const profile of pom.profiles) {
      if (!profile.deps.length) { if (profile.other) unresolved.push({ source: pom.rel, name: `profile:${profile.id}`, reason: "profile is ignored: it only sets properties" }); continue; }
      for (const dep of profile.deps) unresolved.push({ source: pom.rel, name: `${dep.g}:${dep.a}`, reason: `declared in profile '${profile.id}', which is ignored` });
    }
    // Inherited dependencies first, a child's own entry for the same artifact replacing the parent's.
    const effective = new Map<string, RawDep>();
    for (const member of chain) for (const dep of member.deps) effective.set(`${dep.g}:${dep.a}:${dep.type}:${dep.classifier}`, dep);
    const managed = managedOf(pom);
    const components: Component[] = [];
    for (const raw of effective.values()) {
      const g = interpolate(raw.g, props); const a = interpolate(raw.a, props);
      const name = `${g}:${a}`;
      const scope = interpolate(raw.scope, props);
      if (scope === "system") continue;
      if (!g || !a || hasPlaceholder(g) || hasPlaceholder(a)) { unresolved.push({ source: raw.source, name: `${raw.g}:${raw.a}`, reason: "group or artifact is not a literal or known property" }); continue; }
      if (byCoord.has(name) && byCoord.get(name)!.path !== pom.path) continue; // another module of this repository
      const key = depKey({ g, a, type: interpolate(raw.type, props), classifier: interpolate(raw.classifier, props) });
      const declared = interpolate(raw.v, props);
      const inherited = raw.v ? declared : managed.get(key)?.version ?? managed.get(`${g}:${a}:jar:`)?.version ?? "";
      const via = raw.v ? "version" : "managed version";
      if (!inherited) { unresolved.push({ source: raw.source, name, reason: "no version: not managed by any parent or imported BOM in the repository" }); continue; }
      const version = pinnedVersion(inherited);
      if (!version) { unresolved.push({ source: raw.source, name, reason: hasPlaceholder(inherited) ? `${via} '${inherited}' uses a property that no pom in the repository defines (profile properties and the environment are ignored)` : `${via} '${inherited}' is a range or a moving version, not one release` }); continue; }
      components.push({ ecosystem: "maven", name: `${g}/${a}`, version, ...(scope === "test" ? { dev: true } : {}) });
    }
    files.push({ path: pom.path, label: "Maven", components });
  }
  const seen = new Set<string>();
  const all = [...unresolved, ...bomProblems].filter(item => { const key = `${item.source}\n${item.name}\n${item.reason}`; if (seen.has(key)) return false; seen.add(key); return true; });
  return { files, unresolved: all };
}
