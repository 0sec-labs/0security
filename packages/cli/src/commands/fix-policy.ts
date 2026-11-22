/**
 * Where `0 findings fix` takes its fix policy from.
 *
 * The policy steers the model, so whoever writes it steers the fix. The repository being fixed is
 * not trusted: a policy file in it is read only when the operator passes --repo-policy.
 * Order: --policy <file> (any path, relative to the current directory), then the operator's own
 * state directory (~/.0/fix-policy.*), then, only with --repo-policy, the repository's file.
 */
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, relative, resolve, isAbsolute } from "node:path";
import { parseDocument } from "yaml";
import { homeStateDir, type FixPolicy } from "@0/engine/shared";
import { UsageError } from "./output.js";

const POLICY_BASENAMES = ["fix-policy.json", "fix-policy.yaml", "fix-policy.yml"];
/** Directories searched inside a repository, in order. */
const REPO_POLICY_DIRS = [".zero", "."];
/** The candidate names inside a repository (six: each basename in .zero/ and in the root). */
export const DEFAULT_FIX_POLICY_FILES = REPO_POLICY_DIRS.flatMap(dir => POLICY_BASENAMES.map(name => (dir === "." ? name : `${dir}/${name}`)));
export const MAX_POLICY_FILE_BYTES = 64 * 1024;

export interface FixPolicyOptions { policy?: string; repoPolicy?: boolean }
export interface LoadedFixPolicy {
  policy: FixPolicy;
  /** The file it came from, for the operator's log. */
  source: string;
  /** True when it came from the repository under fix, which is untrusted. */
  fromRepo: boolean;
}

export function parseFixPolicy(content: string, filename?: string): FixPolicy {
  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch {
    try {
      const doc = parseDocument(content, { schema: "core", merge: false });
      if (doc.errors.length) throw doc.errors[0];
      raw = doc.toJS();
    } catch (yamlErr) {
      throw new UsageError(`Failed to parse fix policy${filename ? ` from ${filename}` : ""}: ${(yamlErr as Error).message}`);
    }
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new UsageError(`Fix policy${filename ? ` in ${filename}` : ""} must be an object with approvedLibraries, forbiddenPatterns, or rules.`);
  }
  const obj = raw as Record<string, unknown>;
  const approvedLibraries = Array.isArray(obj.approvedLibraries) ? obj.approvedLibraries : undefined;
  const forbiddenPatterns = Array.isArray(obj.forbiddenPatterns) ? obj.forbiddenPatterns : undefined;
  const rules = Array.isArray(obj.rules) ? obj.rules.map(String) : undefined;
  const notes = typeof obj.notes === "string" ? obj.notes : undefined;
  const version = typeof obj.version === "number" ? obj.version : undefined;
  return {
    ...(version !== undefined ? { version } : {}),
    ...(approvedLibraries ? { approvedLibraries: approvedLibraries as FixPolicy["approvedLibraries"] } : {}),
    ...(forbiddenPatterns ? { forbiddenPatterns: forbiddenPatterns as FixPolicy["forbiddenPatterns"] } : {}),
    ...(rules ? { rules } : {}),
    ...(notes ? { notes } : {}),
  };
}

function readPolicy(path: string, label: string): FixPolicy {
  if (statSync(path).size > MAX_POLICY_FILE_BYTES) throw new UsageError(`Fix policy ${label} is larger than ${MAX_POLICY_FILE_BYTES / 1024} KiB.`);
  return parseFixPolicy(readFileSync(path, "utf8"), label);
}

function firstExisting(dir: string, names: string[]): string | undefined {
  return names.map(name => join(dir, name)).find(path => existsSync(path));
}

/** `home` is the operator's home directory; only tests pass it. */
export function loadFixPolicyFile(repoRoot: string, options: FixPolicyOptions = {}, home?: string): LoadedFixPolicy | undefined {
  if (options.policy) {
    const path = resolve(options.policy);
    if (!existsSync(path)) throw new UsageError(`Fix policy file not found: ${options.policy}`);
    return { policy: readPolicy(path, options.policy), source: path, fromRepo: false };
  }
  const own = firstExisting(homeStateDir(home), POLICY_BASENAMES);
  if (own) return { policy: readPolicy(own, own), source: own, fromRepo: false };
  if (options.repoPolicy) {
    const path = firstExisting(repoRoot, DEFAULT_FIX_POLICY_FILES);
    if (path) {
      // A symlink in the repository must not pull in a file from outside it (for example a credential).
      const inside = relative(realpathSync(repoRoot), realpathSync(path));
      if (inside.startsWith("..") || isAbsolute(inside)) throw new UsageError(`Fix policy ${path} points outside the repository.`);
      return { policy: readPolicy(path, path), source: path, fromRepo: true };
    }
  }
  return undefined;
}
