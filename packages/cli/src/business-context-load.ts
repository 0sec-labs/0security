/**
 * Finding the business context a command should use, and the repository it is about.
 *
 * Precedence, highest first: `--context <file>`, then the file named by `0 config set findingsContext`.
 * The repository is `--repository`, else the name in the git remote of the folder the command is about.
 * Nothing is ever read from a scanned repository: only the path the operator named.
 */
import { execFile } from "node:child_process";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";
import type { Finding, FindingBusinessContext } from "@0/engine/shared";
import { labelBusinessContext, loadBusinessContext, type BusinessContext } from "./business-context.js";
import { UsageError } from "./commands/output.js";
import { loadSettings } from "./state/settings.js";
import { repoIdentifier } from "./scan-tiers.js";

const run = promisify(execFile);

export interface ContextOptions { context?: string; repository?: string }

export interface LoadedContext {
  context: BusinessContext;
  /** The file it was read from. */
  source: string;
  /** Whether the file came from the findingsContext setting rather than --context. */
  fromConfig: boolean;
  /** The repository the findings are taken to belong to, when known. */
  repository?: string;
}

export const CONTEXT_FLAG_HELP = "Business context file (JSON): order findings by what matters to you, with the reason shown. Defaults to the file set with `0security config set findingsContext`";
export const REPOSITORY_FLAG_HELP = "Repository name the context rules are matched against (default: the git remote of the current folder)";

/** The git remote of a folder as owner/name, or undefined. No shell; five seconds at most. */
export async function detectRepository(folder: string): Promise<string | undefined> {
  try {
    const { stdout } = await run("git", ["-C", folder, "remote", "get-url", "origin"], { timeout: 5000 });
    return repoIdentifier(stdout.trim());
  } catch { return undefined; }
}

function expand(path: string): string {
  return path === "~" || path.startsWith("~/") ? resolve(homedir(), path.slice(2)) : resolve(path);
}

/** The path of the context file to use, and whether it came from the setting. Undefined when none is set. */
export function contextPath(options: ContextOptions, settings: { findingsContext?: string } = loadSettings()): { path: string; fromConfig: boolean } | undefined {
  if (options.context !== undefined) {
    if (!options.context.trim()) throw new UsageError("--context needs a file path.");
    return { path: options.context, fromConfig: false };
  }
  const configured = settings.findingsContext?.trim();
  return configured ? { path: expand(configured), fromConfig: true } : undefined;
}

export interface LoadDeps { settings?: { findingsContext?: string }; folder?: string; detect?: (folder: string) => Promise<string | undefined> }

/**
 * Reads the context for a command, or returns undefined when none is named. A bad file stops the command before it
 * reads any finding. Git is asked for the repository only when the file has rules for specific repositories.
 */
export async function loadContextFor(options: ContextOptions, deps: LoadDeps = {}): Promise<LoadedContext | undefined> {
  const named = contextPath(options, deps.settings);
  if (!named) {
    if (options.repository !== undefined) throw new UsageError("--repository needs a business context: pass --context <file> or run `0security config set findingsContext <file>`.");
    return undefined;
  }
  let context: BusinessContext;
  try { context = loadBusinessContext(named.path); } catch (error) {
    if (named.fromConfig && error instanceof UsageError) throw new UsageError(`${error.message} The path comes from the findingsContext setting; change it with \`0security config set findingsContext <file>\`.`);
    throw error;
  }
  let repository = options.repository?.trim() || undefined;
  if (!repository && context.repositories.length) repository = await (deps.detect ?? detectRepository)(deps.folder ?? process.cwd());
  return { context, source: named.path, fromConfig: named.fromConfig, ...(repository ? { repository } : {}) };
}

/** The name a label carries when no repository is known. */
export const UNKNOWN_REPOSITORY = "(unspecified)";

/**
 * Labels findings with what the context says about them, so every command and report orders and explains them the same
 * way. Severity is never touched. An unmatched finding still gets a label that says the rank is unchanged.
 */
export function withBusinessContext<T extends Pick<Finding, "reviewAnnotation" | "severity">>(findings: readonly T[], loaded: LoadedContext | undefined, repository?: string): T[] {
  if (!loaded) return [...findings];
  const name = repository ?? loaded.repository;
  return findings.map(finding => labelBusinessContext(finding as unknown as Finding, loaded.context, name ?? UNKNOWN_REPOSITORY, name) as unknown as T);
}

/** The label for one finding known only by its severity and file, for commands that do not hold a whole finding. */
export function labelFor(loaded: LoadedContext, finding: { severity: string; path?: string | undefined }, repository?: string): FindingBusinessContext {
  const shaped = { severity: finding.severity, ...(finding.path ? { reviewAnnotation: { path: finding.path, startLine: 1 } } : {}) } as unknown as Finding;
  return withBusinessContext([shaped], loaded, repository)[0]!.businessContext!;
}

/**
 * `findings` declares --context and --repository for its own list view, and Commander gives a flag to the parent
 * when both declare it. A subcommand reads its own value first, then the parent's.
 */
export function contextOptionsOf(options: ContextOptions, command?: { parent?: { opts(): Record<string, unknown> } | null }): ContextOptions {
  const parent = (command?.parent?.opts() ?? {}) as ContextOptions;
  const context = options.context ?? parent.context;
  const repository = options.repository ?? parent.repository;
  return { ...(context !== undefined ? { context } : {}), ...(repository !== undefined ? { repository } : {}) };
}
