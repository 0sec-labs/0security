/**
 * Reads the files that steer a scan: context files (a threat model) and policies (Markdown rules). Only paths the
 * user names are read, plus `.0/threat-model.md` of the scanned folder when `--repo-context` asks for it. Nothing in
 * the scanned repository is read on its own: a file there is written by whoever can change the code under review.
 */
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";
import { mergePolicies, parsePolicyFile, parseScope, type PolicyEntry, type PolicySource, type ScopeEntry, type SteeringFile } from "@0/engine/shared";
import { UsageError } from "./commands/output.js";

export const REPO_CONTEXT_PATH = join(".0", "threat-model.md");
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_POLICY_FILES = 200;
const MAX_DEPTH = 5;

export interface Steering { context: SteeringFile[]; policies: PolicyEntry[] }
export interface SteeringOptions { context?: string[]; policy?: string[]; orgPolicy?: string[]; repoContext?: boolean }

function readText(path: string, what: string): string {
  const size = statSync(path).size;
  if (size > MAX_FILE_BYTES) throw new UsageError(`${what} ${path} is ${size} bytes; the limit is ${MAX_FILE_BYTES}.`);
  return readFileSync(path, "utf8");
}

function markdownFiles(directory: string, found: string[], depth = 0): void {
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (found.length >= MAX_POLICY_FILES) return;
    const path = join(directory, entry.name);
    // Symbolic links are not followed: a policy folder is plain files.
    if (entry.isDirectory()) { if (depth < MAX_DEPTH && !entry.name.startsWith(".")) markdownFiles(path, found, depth + 1); }
    else if (entry.isFile() && /\.md$/i.test(entry.name) && !/^readme\.md$/i.test(entry.name)) found.push(path);
  }
}

/** The policies in the files and folders named, in the order named (files of a folder sorted by path). */
export function loadPolicies(paths: readonly string[], source: PolicySource): { policies: PolicyEntry[]; warnings: string[] } {
  const policies: PolicyEntry[] = [];
  const warnings: string[] = [];
  for (const raw of paths) {
    const path = resolve(raw);
    let info;
    try { info = statSync(path); } catch { throw new UsageError(`${raw} does not exist. Pass a policy file or a folder of .md files.`); }
    const files: string[] = [];
    if (info.isDirectory()) markdownFiles(path, files); else files.push(path);
    if (!files.length) throw new UsageError(`${raw} holds no .md policy files.`);
    for (const file of files) {
      const parsed = parsePolicyFile(info.isDirectory() ? relative(path, file) || file : file, readText(file, "The policy file"), source);
      policies.push(parsed.policy);
      warnings.push(...parsed.warnings);
    }
  }
  return { policies, warnings };
}

/** `.0/threat-model.md` of the scanned folder, only when it is a regular file that really lives inside the folder. */
export function readRepoContext(folder: string): SteeringFile | undefined {
  const path = join(folder, REPO_CONTEXT_PATH);
  try {
    if (!lstatSync(path).isFile()) return undefined; // a symbolic link could point anywhere on this machine
    const root = realpathSync(folder);
    if (!realpathSync(path).startsWith(root + sep)) return undefined;
    return { name: "threat-model.md", text: readText(path, "The repository context file") };
  } catch (error) { if (error instanceof UsageError) throw error; return undefined; }
}

export function loadSteering(folder: string, options: SteeringOptions, err: (text: string) => void): Steering {
  const context: SteeringFile[] = (options.context ?? []).map(raw => {
    const path = resolve(raw);
    let isFile = false;
    try { isFile = statSync(path).isFile(); } catch { /* reported below */ }
    if (!isFile) throw new UsageError(`--context ${raw} is not a file.`);
    return { name: path, text: readText(path, "The context file") };
  });
  if (options.repoContext) {
    err(`warning: --repo-context reads ${REPO_CONTEXT_PATH} from the folder being scanned. Whoever can change that folder (a pull request under review) can edit this file to steer the scan away from a flaw. In CI read it from the base branch instead: git show origin/main:${REPO_CONTEXT_PATH} > threat-model.md, then --context threat-model.md.`);
    const file = readRepoContext(folder);
    if (file) context.push(file); else err(`warning: --repo-context: ${REPO_CONTEXT_PATH} was not found in the scanned folder (or is not a regular file inside it); continuing without it`);
  }
  const org = loadPolicies(options.orgPolicy ?? [], "org");
  const rest = loadPolicies(options.policy ?? [], "policy");
  const merged = mergePolicies(org.policies, rest.policies);
  for (const warning of [...org.warnings, ...rest.warnings, ...merged.warnings]) err(`policy: ${warning}`);
  return { context, policies: merged.policies };
}

export const REPO_SCOPE_PATH = "SECURITY.md";

/** A scope the operator declared: the entries, the file name they came from (shown in reports) and the vectors named. */
export interface ScopeDeclaration { entries: ScopeEntry[]; source: string; inScopeVectors: string[]; outOfScopeVectors: string[]; unmatched: number }
export interface ScopeOptions { scope?: string; repoScope?: boolean; scopeSarif?: string }

/** `SECURITY.md` of the scanned folder, only when it is a regular file that really lives inside the folder. */
export function readRepoScopeFile(folder: string): string | undefined {
  const path = join(folder, REPO_SCOPE_PATH);
  try {
    if (!lstatSync(path).isFile()) return undefined;
    const root = realpathSync(folder);
    if (!realpathSync(path).startsWith(root + sep)) return undefined;
    return readText(path, "The repository scope file");
  } catch (error) { if (error instanceof UsageError) throw error; return undefined; }
}

const safeSource = (name: string): string => basename(name).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "scope";

/**
 * The declared scope, only from a place the operator chose: `--scope <file>` (any path, usually a copy of SECURITY.md from
 * the base branch) or `--repo-scope` (SECURITY.md of the scanned folder, with a warning). Nothing is read on its own, so a
 * change under review cannot declare its own findings out of scope.
 */
export function loadScope(folder: string, options: ScopeOptions, err: (text: string) => void): ScopeDeclaration | undefined {
  if (options.scopeSarif !== undefined && options.scopeSarif !== "suppress" && options.scopeSarif !== "label") throw new UsageError("--scope-sarif must be label or suppress.");
  if (options.scope !== undefined && options.repoScope) throw new UsageError("Use --scope <file> or --repo-scope, not both.");
  if (options.scope === undefined && !options.repoScope) {
    if (options.scopeSarif === "suppress") throw new UsageError("--scope-sarif suppress needs --scope <file> or --repo-scope.");
    return undefined;
  }
  let text: string | undefined;
  let source: string;
  if (options.scope !== undefined) {
    const path = resolve(options.scope);
    let isFile = false;
    try { isFile = statSync(path).isFile(); } catch { /* reported below */ }
    if (!isFile) throw new UsageError(`--scope ${options.scope} is not a file.`);
    text = readText(path, "The scope file");
    source = safeSource(path);
  } else {
    err(`warning: --repo-scope reads ${REPO_SCOPE_PATH} from the folder being scanned. Whoever can change that folder (a pull request under review) can edit its Scope section to label real findings out of scope and take them out of --fail-on. In CI pass the base branch's copy instead: git show origin/main:${REPO_SCOPE_PATH} > base-security.md, then --scope base-security.md.`);
    text = readRepoScopeFile(folder);
    source = REPO_SCOPE_PATH;
    if (text === undefined) { err(`warning: --repo-scope: ${REPO_SCOPE_PATH} was not found in the scanned folder (or is not a regular file inside it); nothing is labelled`); return undefined; }
  }
  const parsed = parseScope(text);
  if (!parsed.found) { err(`warning: ${source} has no '## Scope' section; nothing is labelled`); return undefined; }
  for (const warning of parsed.warnings) err(`scope: ${warning}`);
  const vectors = (kind: "in" | "out") => parsed.entries.filter(entry => entry.kind === kind).map(entry => entry.category ?? entry.vector);
  return { entries: parsed.entries, source, inScopeVectors: [...new Set(vectors("in"))], outOfScopeVectors: [...new Set(vectors("out"))], unmatched: parsed.unmatched.length };
}
