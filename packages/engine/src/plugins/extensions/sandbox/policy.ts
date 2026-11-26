/**
 * What an extension's sandbox allows. Pure except for path resolution, which touches the file system only to resolve
 * symlinks. The manifest declares a small block (`sandbox`); this module validates it, turns its relative paths into
 * absolute, symlink-resolved paths inside the extension folder, and builds the policy a backend turns into a profile
 * (macOS Seatbelt) or an argument list (Linux bubblewrap).
 *
 * Defaults, with no declaration: no network, no child programs beyond the interpreter allowlist, read-only access to the
 * extension's own folder and the system, read-write access to one scratch folder. Nothing in the user's home, in ~/.0,
 * or in the scanned folder is visible unless declared.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";

/** Interpreters a sandboxed process may start without `process`. The script-run check in script-runs.ts trusts exactly these names. */
export const TRUSTED_INTERPRETER_NAMES = ["sh", "bash", "zsh", "python", "python3", "node", "bun"] as const;
export type TrustedInterpreter = (typeof TRUSTED_INTERPRETER_NAMES)[number];

/** The only token a path entry may use besides a relative path: the folder the operator runs the extension in. */
export const WORKSPACE_TOKEN = "$WORKSPACE";

/** What the manifest declares, normalised. Paths are relative to the extension folder, or the workspace token. */
export interface SandboxDecl {
  /** The extension may open network connections. Off unless declared and approved. */
  network: boolean;
  /** The extension may start programs from the system binary folders, not only the interpreter allowlist. */
  process: boolean;
  /** Names of programs (not paths) the extension may start, resolved from PATH at launch. Narrower than `process`. */
  programs: string[];
  readPaths: string[];
  writePaths: string[];
}

const MAX_PATHS = 16;
const unsafePath = (p: string): boolean =>
  p.includes("\0") || p.includes("\\") || p.startsWith("/") || p.startsWith("~") || /^[A-Za-z]:/.test(p) || /[\n\r"]/.test(p);
const entry = z.string().min(1).max(256).superRefine((value, ctx) => {
  if (value === WORKSPACE_TOKEN) return;
  if (unsafePath(value)) { ctx.addIssue({ code: "custom", message: `must be a path relative to the extension folder, or ${WORKSPACE_TOKEN}` }); return; }
  const n = path.posix.normalize(value);
  if (n === "." || n === ".." || n.startsWith("../") || value.split("/").includes("..")) ctx.addIssue({ code: "custom", message: "must stay inside the extension folder (no .. segments)" });
}).transform(value => value === WORKSPACE_TOKEN ? value : path.posix.normalize(value).replace(/^\.\//, "").replace(/\/$/, ""));
const entries = z.array(entry).max(MAX_PATHS).default([]).transform(list => [...new Set(list)].sort());

const programName = z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9._+-]*$/, "must be a bare program name such as curl, not a path");
const programs = z.array(programName).max(MAX_PATHS).default([]).transform(list => [...new Set(list)].sort());

/** Strict: an unknown key is an error, so a typo never silently widens or narrows a policy. */
export const sandboxShape = z.object({ network: z.boolean().default(false), process: z.boolean().default(false), programs, readPaths: entries, writePaths: entries }).strict();

/** Keys people reach for to limit the network by host. The OS layers cannot enforce them, so they are refused by name. */
const HOST_FILTER_KEYS = new Set(["hosts", "allowHosts", "allowedHosts", "networkHosts", "domains", "allowDomains", "allowedDomains"]);

export function parseSandboxDecl(raw: unknown): { ok: true; value: SandboxDecl } | { ok: false; error: string } {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const o = raw as Record<string, unknown>;
    const hostKey = Object.keys(o).find(k => HOST_FILTER_KEYS.has(k));
    if (hostKey || (o.network !== undefined && typeof o.network === "object" && o.network !== null)) return { ok: false, error: `sandbox: filtering the network by host is not supported (neither macOS Seatbelt nor Linux bubblewrap can enforce it). Set network to true or false` };
  }
  const parsed = sandboxShape.safeParse(raw);
  if (parsed.success) return { ok: true, value: parsed.data };
  return { ok: false, error: parsed.error.issues.slice(0, 3).map(i => `sandbox${i.path.length ? `.${i.path.join(".")}` : ""}: ${i.message}`).join("; ") };
}

/** One stable line per declaration: part of the approval, so a changed block asks the operator again. */
export const sandboxLine = (s: SandboxDecl): string =>
  `sandbox: network ${s.network ? "ON" : "off"}, programs ${s.process ? "system folders" : s.programs.length ? `interpreters + ${s.programs.join(",")}` : "interpreters only"}, read ${s.readPaths.join(",") || "-"}, write ${s.writePaths.join(",") || "-"}`;

export interface ResolvedSandbox {
  extensionDir: string;
  scratchDir: string;
  workspace: string | null;
  network: boolean;
  process: boolean;
  /** Names of the extra programs that may start (already resolved to execAllow). */
  programs: string[];
  /** Absolute, symlink-resolved, inside the extension folder (or the workspace). */
  readPaths: string[];
  writePaths: string[];
  /** Absolute paths of programs the process may start. */
  execAllow: string[];
  limits: { cpuSeconds?: number; memoryMb?: number };
  /** The user's home folder (symlink-resolved). macOS hides even the existence of files below it, except what is allowed. */
  home?: string;
}

const within = (parent: string, child: string): boolean => child === parent || child.startsWith(parent.endsWith(path.sep) ? parent : parent + path.sep);

/** Resolve one declared path. Refuses a missing path, a symlink that leaves the extension folder, or a missing workspace. */
export function resolveDeclaredPath(entryPath: string, extensionDir: string, workspace: string | null): { ok: true; path: string } | { ok: false; error: string } {
  let realExt: string;
  try { realExt = fs.realpathSync(extensionDir); } catch { return { ok: false, error: `the extension folder ${extensionDir} cannot be resolved` }; }
  if (entryPath === WORKSPACE_TOKEN) {
    if (!workspace) return { ok: false, error: `it declares ${WORKSPACE_TOKEN} but there is no workspace folder for this run` };
    try { return { ok: true, path: fs.realpathSync(workspace) }; } catch { return { ok: false, error: `the workspace folder ${workspace} cannot be resolved` }; }
  }
  if (unsafePath(entryPath) || entryPath.split("/").includes("..")) return { ok: false, error: `sandbox path ${JSON.stringify(entryPath)} is not a relative path inside the extension folder` };
  const joined = path.resolve(realExt, entryPath);
  if (!within(realExt, joined)) return { ok: false, error: `sandbox path ${JSON.stringify(entryPath)} leaves the extension folder` };
  let real: string;
  try { real = fs.realpathSync(joined); } catch { return { ok: false, error: `sandbox path ${JSON.stringify(entryPath)} does not exist in the extension folder` }; }
  if (!within(realExt, real)) return { ok: false, error: `sandbox path ${JSON.stringify(entryPath)} is a symlink that leaves the extension folder` };
  return { ok: true, path: real };
}

export interface ResolveInput {
  decl: SandboxDecl;
  extensionDir: string;
  scratchDir: string;
  workspace: string | null;
  execAllow: readonly string[];
  limits?: ResolvedSandbox["limits"];
  home?: string;
}

export function resolveSandbox(input: ResolveInput): { ok: true; value: ResolvedSandbox } | { ok: false; error: string } {
  let extensionDir: string; let scratchDir: string;
  try { extensionDir = fs.realpathSync(input.extensionDir); scratchDir = fs.realpathSync(input.scratchDir); } catch (e) { return { ok: false, error: `cannot resolve a sandbox folder: ${e instanceof Error ? e.message : String(e)}` }; }
  const lists: Record<"readPaths" | "writePaths", string[]> = { readPaths: [], writePaths: [] };
  for (const key of ["readPaths", "writePaths"] as const) {
    for (const p of input.decl[key]) {
      const r = resolveDeclaredPath(p, extensionDir, input.workspace);
      if (!r.ok) return r;
      lists[key].push(r.path);
    }
  }
  const execAllow = [...new Set(input.execAllow.filter(p => path.isAbsolute(p)))].sort();
  return { ok: true, value: { extensionDir, scratchDir, workspace: input.workspace, network: input.decl.network, process: input.decl.process, programs: input.decl.programs, readPaths: [...new Set(lists.readPaths)].sort(), writePaths: [...new Set(lists.writePaths)].sort(), execAllow, limits: input.limits ?? {}, ...homeOf(input.home) } };
}

const homeOf = (home: string | undefined): { home?: string } => { try { return { home: fs.realpathSync(home ?? os.homedir()) }; } catch { return {}; } };

/** The sandbox a run gets when the extension declares nothing (used by `ZERO_SANDBOX=require`): the strictest defaults. */
export const DEFAULT_DECL: SandboxDecl = { network: false, process: false, programs: [], readPaths: [], writePaths: [] };

/** A short description for the per-run status line. */
export function describeSandbox(backend: string, s: ResolvedSandbox): string {
  const extra = [s.readPaths.length ? `${s.readPaths.length} extra read path${s.readPaths.length === 1 ? "" : "s"}` : "", s.writePaths.length ? `${s.writePaths.length} extra write path${s.writePaths.length === 1 ? "" : "s"}` : ""].filter(Boolean);
  return `${backend}, network ${s.network ? "ON" : "off"}, programs ${s.process ? "system folders" : s.programs.length ? `interpreters + ${s.programs.join(", ")}` : "interpreters only"}, writes to a scratch folder${s.writePaths.length ? " and declared paths" : " only"}${extra.length ? `, ${extra.join(", ")}` : ""}`;
}
