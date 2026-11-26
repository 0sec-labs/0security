/**
 * Maven and Gradle dependency resolution by running the operator's own build tool. Opt-in only: `0 sbom generate --resolve`.
 *
 * This is the one place the SBOM code runs something. `mvn dependency:tree` and `gradle dependencies` evaluate the
 * project's build files, which can run arbitrary code, and they contact the repositories the project names. So the caller
 * must have the operator's explicit consent, ZERO_ENTERPRISE refuses it, and the tools are started with an argument
 * array (no shell), a timeout, a bounded output and an allow-listed environment. Only `mvn` and `gradle` from PATH are
 * used: never a `mvnw` or `gradlew` script from the scanned folder.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { assertEgressAllowed } from "../policy/enterprise.js";
import type { Component } from "./parsers.js";

export const RESOLVE_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_GRADLE_PROJECTS = 25;
const MAX_PROJECT_DEPTH = 4;
const SKIP = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".gradle", ".idea"]);

/** Only these variables reach the build tool: enough for a JDK, a home folder, mirrors and proxies, not the operator's API keys. */
const ENV_ALLOW = /^(?:PATH|HOME|USER|LOGNAME|SHELL|LANG|LC_[A-Z]+|TMPDIR|TEMP|TMP|JAVA_HOME|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|M2_HOME|MAVEN_[A-Z_]+|GRADLE_[A-Z_]+|(?:HTTPS?|NO|ALL)_PROXY|(?:https?|no|all)_proxy|SSL_CERT_FILE|SSL_CERT_DIR|SystemRoot|ProgramFiles|USERPROFILE|APPDATA|LOCALAPPDATA)$/;
export function buildToolEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const kept: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) if (value !== undefined && ENV_ALLOW.test(key)) kept[key] = value;
  return kept;
}

export class ResolveFailedError extends Error {}

export interface ResolveOptions {
  timeoutMs?: number;
  /** Environment to filter and pass to the tool (default: this process). */
  env?: NodeJS.ProcessEnv;
  /** Pass `-o` to Maven and `--offline` to Gradle: nothing is downloaded, so only what is cached resolves. */
  offline?: boolean;
  /** A Maven settings file (mirrors, proxies, credentials) passed as `mvn -s <file>`. The operator names it; the project cannot. */
  mavenSettings?: string;
  /** A Gradle init script (mirrors, proxies) passed as `gradle -I <file>`. The operator names it; the project cannot. */
  gradleInitScript?: string;
}
export interface ResolveResult {
  components: Component[];
  /** The tools that ran and produced a tree, such as `mvn` or `gradle (app)`. */
  tools: string[];
  warnings: string[];
}

/** Maven's text tree. Each module is a root line (`group:artifact:type:version`) followed by `+-` and `\-` lines, three characters per level. */
export function parseMavenTree(text: string): Component[] {
  const nodes = new Map<string, Component & { dev: boolean }>();
  const roots = new Set<string>();
  const edges: Array<[string, string]> = [];
  let stack: string[] = [];
  const key = (name: string, version: string) => `${name}@${version}`;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^\[INFO\] ?/, "");
    if (!line.trim()) continue;
    const branch = /^((?:[| ]{3})*)[+\\]- (\S.*)$/.exec(line);
    const token = (branch ? branch[2]! : line).trim().split(/\s+/)[0]!;
    const parts = token.split(":");
    if (parts.length < 4 || parts.length > 6 || parts.some(part => !part || /[\s"'<>]/.test(part))) { if (!branch) stack = []; continue; }
    if (!branch) {
      // A module's own coordinates: not a third-party component. Its children are its direct dependencies.
      roots.add(`${parts[0]}/${parts[1]}`);
      stack = [""];
      continue;
    }
    const depth = branch[1]!.length / 3 + 1;
    const [group, artifact] = parts;
    const scope = parts.length >= 5 ? parts[parts.length - 1]! : "compile";
    const version = parts.length >= 5 ? parts[parts.length - 2]! : parts[parts.length - 1]!;
    const name = `${group}/${artifact}`;
    const id = key(name, version);
    const parent = stack[depth - 1];
    stack.length = depth;
    stack[depth] = id;
    const dev = scope === "test" || scope === "provided" || scope === "system";
    const existing = nodes.get(id);
    if (existing) { if (existing.dev && !dev) existing.dev = false; }
    else nodes.set(id, { ecosystem: "maven", name, version, dev, dependsOn: [] });
    if (parent) edges.push([parent, id]);
  }
  for (const [from, to] of edges) {
    const source = nodes.get(from);
    const target = nodes.get(to);
    if (!source || !target || roots.has(target.name)) continue;
    if (!source.dependsOn!.some(edge => edge.name === target.name && edge.version === target.version)) source.dependsOn!.push({ name: target.name, version: target.version });
  }
  return [...nodes.values()].filter(node => !roots.has(node.name)).map(({ dev, ...node }) => ({ ...node, ...(dev ? { dev: true } : {}), dependsOn: node.dependsOn!.filter(edge => !roots.has(edge.name)) }));
}

/** Gradle's dependency tree for one configuration: `+---` and `\---` lines, five characters per level. */
export function parseGradleTree(text: string): Component[] {
  const nodes = new Map<string, Component>();
  const edges: Array<[string, string]> = [];
  const stack: Array<string | undefined> = [];
  for (const raw of text.split(/\r?\n/)) {
    const branch = /^((?:[| ]{5})*)[+\\]--- (\S.*)$/.exec(raw);
    if (!branch) continue;
    const depth = branch[1]!.length / 5;
    let body = branch[2]!.trim();
    const failed = /\sFAILED$/.test(body);
    body = body.replace(/\sFAILED$/, "");
    const marker = failed ? "n" : /\s\((\*|c|n)\)$/.exec(body)?.[1];
    body = body.replace(/\s\((?:\*|c|n)\)$/, "");
    stack.length = depth + 1;
    // A constraint, an unresolved dependency or a project reference is not a component; its children attach to the nearest component above.
    if (marker === "c" || marker === "n" || /^project\s/.test(body) || /\s->\s*project\s/.test(body)) { stack[depth] = stack[depth - 1]; continue; }
    const arrow = body.split(" -> ");
    const declared = arrow[0]!.replace(/:\{[^}]*\}$/, "").trim();
    const coordinates = declared.split(":");
    if (coordinates.length < 2 || coordinates.length > 4 || coordinates.some(part => !part || /\s/.test(part))) { stack[depth] = stack[depth - 1]; continue; }
    const version = arrow[1]?.trim() ?? (coordinates[2] ?? (/:\{([^};]*)/.exec(arrow[0]!)?.[1] ?? "")).trim();
    const finalVersion = /^[0-9A-Za-z][0-9A-Za-z._+-]*$/.test(version) ? version : "";
    if (!finalVersion) { stack[depth] = stack[depth - 1]; continue; }
    const name = `${coordinates[0]}/${coordinates[1]}`;
    const id = `${name}@${finalVersion}`;
    if (!nodes.has(id)) nodes.set(id, { ecosystem: "maven", name, version: finalVersion, dependsOn: [] });
    stack[depth] = id;
    const parent = stack[depth - 1];
    if (parent && parent !== id) edges.push([parent, id]);
  }
  for (const [from, to] of edges) {
    const source = nodes.get(from)!;
    const target = nodes.get(to)!;
    if (!source.dependsOn!.some(edge => edge.name === target.name && edge.version === target.version)) source.dependsOn!.push({ name: target.name, version: target.version });
  }
  return [...nodes.values()];
}

/**
 * Read the output of the build tool's own dependency report, run by someone else (`mvn dependency:tree -DoutputFile=...`,
 * `gradle dependencies`). Nothing runs and nothing is downloaded. The lines tell the shape: Maven prints `+- ` and
 * `\- `, Gradle prints `+--- ` and `\--- `. Text of neither shape gives no components.
 */
export function parseDependencyReport(text: string): { tool: "mvn" | "gradle" | "unknown"; components: Component[] } {
  const mark = (components: Component[]): Component[] => components.map(component => ({ ...component, resolved: true }));
  if (/^(?:[| ]{5})*[+\\]--- \S/m.test(text)) return { tool: "gradle", components: mark(parseGradleTree(text)) };
  if (/^(?:\[INFO\] ?)?(?:[| ]{3})*[+\\]- \S/m.test(text)) return { tool: "mvn", components: mark(parseMavenTree(text)) };
  return { tool: "unknown", components: [] };
}

/** Union what several trees say about one package: edges are joined, development-only holds only if every tree says so. */
export function mergeComponents(lists: Component[][]): Component[] {
  const byKey = new Map<string, Component>();
  for (const component of lists.flat()) {
    const key = `${component.name}@${component.version}`;
    const existing = byKey.get(key);
    if (!existing) { byKey.set(key, { ...component, dependsOn: [...(component.dependsOn ?? [])] }); continue; }
    if (existing.dev && !component.dev) delete existing.dev;
    for (const edge of component.dependsOn ?? []) if (!existing.dependsOn!.some(other => other.name === edge.name && other.version === edge.version)) existing.dependsOn!.push(edge);
  }
  return [...byKey.values()].sort((a, b) => (a.name !== b.name ? (a.name < b.name ? -1 : 1) : a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
}

function runTool(tool: "mvn" | "gradle", args: string[], cwd: string, options: ResolveOptions): Promise<{ stdout: string }> {
  const timeout = options.timeoutMs ?? RESOLVE_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    execFile(tool, args, { cwd, env: buildToolEnv(options.env), timeout, maxBuffer: MAX_OUTPUT_BYTES, encoding: "utf8", windowsHide: true }, (error, stdout, stderr) => {
      if (!error) return resolve({ stdout });
      const failure = error as NodeJS.ErrnoException & { killed?: boolean; signal?: string };
      if (failure.code === "ENOENT") return reject(new ResolveFailedError(`${tool} is not installed (or not on PATH). 0 runs only the ${tool} on your PATH, never a wrapper script from the project.`));
      if (failure.killed || failure.signal === "SIGTERM") return reject(new ResolveFailedError(`${tool} did not finish within ${Math.round(timeout / 1000)} seconds.`));
      if (failure.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return reject(new ResolveFailedError(`${tool} printed more than ${MAX_OUTPUT_BYTES / 1024 / 1024} MB.`));
      const detail = `${stderr}\n${stdout}`.replace(/[^\x20-\x7e\n]/g, "").split("\n").filter(line => /ERROR|FAIL|not found|Could not|wrong/i.test(line)).slice(0, 5).join("\n");
      reject(new ResolveFailedError(`${tool} failed${typeof failure.code === "number" ? ` (exit ${failure.code})` : ""}${detail ? `:\n${detail}` : "."}`));
    });
  });
}

const exists = async (path: string): Promise<boolean> => stat(path).then(info => info.isFile(), () => false);

/** Folders under `folder` (including it) that hold a Gradle build file, shallowest first. */
async function gradleProjects(folder: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (found.length >= MAX_GRADLE_PROJECTS) return;
    if (await exists(join(dir, "build.gradle")) || await exists(join(dir, "build.gradle.kts"))) found.push(dir);
    if (depth >= MAX_PROJECT_DEPTH) return;
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) if (entry.isDirectory() && !SKIP.has(entry.name) && !entry.name.startsWith(".")) await walk(join(dir, entry.name), depth + 1);
  };
  await walk(folder, 0);
  return found;
}

/**
 * Run `mvn dependency:tree` and `gradle dependencies` (runtimeClasspath, then testRuntimeClasspath for test-only packages) in a folder that has a `pom.xml` or Gradle build files, and parse the trees.
 * Refuses under ZERO_ENTERPRISE. Throws ResolveFailedError when a tool that should run produced no tree.
 */
export async function resolveJvmDependencies(folder: string, options: ResolveOptions = {}): Promise<ResolveResult> {
  assertEgressAllowed("Maven and Gradle repositories (sbom generate --resolve runs the project's build tool)", options.env);
  const lists: Component[][] = [];
  const tools: string[] = [];
  const warnings: string[] = [];
  const failures: string[] = [];
  const hasPom = await exists(join(folder, "pom.xml"));
  const projects = await gradleProjects(folder);
  if (!hasPom && !projects.length) throw new ResolveFailedError("--resolve found no pom.xml and no build.gradle or build.gradle.kts in the folder.");
  if (hasPom) {
    const scratch = await mkdtemp(join(tmpdir(), "0-sbom-mvn-"));
    try {
      const file = join(scratch, "tree.txt");
      const args = ["-B", "-ntp", ...(options.offline ? ["-o"] : []), ...(options.mavenSettings ? ["-s", options.mavenSettings] : []), "dependency:tree", "-DoutputType=text", `-DoutputFile=${file}`, "-DappendOutput=true"];
      await runTool("mvn", args, folder, options);
      const text = await readFile(file, "utf8").catch(() => "");
      const components = parseMavenTree(text);
      if (!text.trim()) throw new ResolveFailedError("mvn finished but wrote no dependency tree.");
      lists.push(components);
      tools.push("mvn");
    } catch (error) { failures.push(error instanceof Error ? error.message : String(error)); }
    finally { await rm(scratch, { recursive: true, force: true }); }
  }
  for (const project of projects) {
    const label = relative(folder, project) || ".";
    try {
      const gradleArgs = ["--no-daemon", "--console=plain", "-q", ...(options.offline ? ["--offline"] : []), ...(options.gradleInitScript ? ["-I", options.gradleInitScript] : []), "-p", project, "dependencies", "--configuration"];
      const { stdout } = await runTool("gradle", [...gradleArgs, "runtimeClasspath"], folder, options);
      const runtime = parseGradleTree(stdout);
      lists.push(runtime);
      tools.push(`gradle (${label})`);
      // Test-only dependencies come from a second report and are marked dev, like Maven test scope. A project without that configuration is not an error.
      try {
        const test = await runTool("gradle", [...gradleArgs, "testRuntimeClasspath"], folder, options);
        const inRuntime = new Set(runtime.map(component => `${component.name}@${component.version}`));
        lists.push(parseGradleTree(test.stdout).map(component => inRuntime.has(`${component.name}@${component.version}`) ? component : { ...component, dev: true }));
      } catch (error) { warnings.push(`gradle (${label}) test dependencies: ${error instanceof Error ? error.message : String(error)}`); }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // A subproject with no runtimeClasspath (a plain aggregator) is normal; a tool that cannot start or time out is not.
      (projects.length > 1 ? warnings : failures).push(`gradle (${label}): ${message}`);
    }
  }
  if (!lists.length) throw new ResolveFailedError([...failures, ...warnings].join("\n") || "No dependency tree was produced.");
  warnings.push(...failures);
  return { components: mergeComponents(lists), tools, warnings };
}
