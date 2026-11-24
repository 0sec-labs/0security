/**
 * Node's own permission model (`node --permission`) as a sandbox layer for extension programs that are started with node.
 *
 * It limits what the node process itself may do: which folders it can read and write, whether it can start child
 * programs and whether it can start workers. It does not restrict the network, so it never claims to. It works on every
 * platform node runs on, so it is the only layer on Windows and on Linux hosts where bubblewrap cannot start; where an OS
 * sandbox exists it is added on top.
 *
 * The flags come from the same resolved policy the OS backends use. Nothing is inferred from the script.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import type { ResolvedSandbox } from "./policy.js";

export interface NodePermissionSupport {
  supported: boolean;
  /** The flag that turns the model on: `--permission` (node 22.13 and later), or `--experimental-permission` (node 20 to 22.12). */
  flag?: "--permission" | "--experimental-permission";
  detail: string;
}

const PROBE = "process.exit(typeof process.permission === 'object' && process.permission !== null ? 0 : 1)";
const cache = new Map<string, NodePermissionSupport>();

export type NodeProbe = (file: string, args: string[]) => { status: number | null; stderr?: string };
const defaultProbe: NodeProbe = (file, args) => {
  const r = spawnSync(file, args, { encoding: "utf8", timeout: 4000, stdio: ["ignore", "ignore", "pipe"] });
  return { status: r.status, stderr: r.stderr?.toString() };
};

/** Starts the given node once with each flag and reports which one works. Cached per binary. */
export function detectNodePermission(nodePath: string, probe: NodeProbe = defaultProbe): NodePermissionSupport {
  const hit = probe === defaultProbe ? cache.get(nodePath) : undefined;
  if (hit) return hit;
  let result: NodePermissionSupport = { supported: false, detail: "this node has no permission model (node 20 or later is needed)" };
  for (const flag of ["--permission", "--experimental-permission"] as const) {
    const r = probe(nodePath, [flag, "-e", PROBE]);
    if (r.status === 0) { result = { supported: true, flag, detail: `node ${flag}` }; break; }
  }
  if (probe === defaultProbe) cache.set(nodePath, result);
  return result;
}
export const resetNodePermissionDetection = (): void => { cache.clear(); };

/** True for a program that is node itself (not a script that happens to start node). */
export const isNodeProgram = (program: string, realProgram: string = program): boolean => [program, realProgram].some(p => /^node(?:\.exe)?$/i.test(path.basename(p)));

/** Paths node cannot take: a `*` is a wildcard to it, and a comma or newline would be ambiguous in logs. */
const usable = (p: string): boolean => path.isAbsolute(p) && !/[*\n\r\0]/.test(p);

/**
 * The flags to put right after the node binary. Reads: the extension folder, declared read paths, the workspace when
 * declared, and scratch. Writes: scratch and declared write paths. Child programs only with `process`. Workers never.
 * Returns an error string when a path cannot be expressed safely.
 */
export function nodePermissionArgs(policy: ResolvedSandbox, support: NodePermissionSupport): { ok: true; args: string[] } | { ok: false; error: string } {
  if (!support.supported || !support.flag) return { ok: false, error: support.detail };
  const reads = [...new Set([policy.extensionDir, policy.scratchDir, ...policy.readPaths, ...policy.writePaths])];
  const writes = [...new Set([policy.scratchDir, ...policy.writePaths])];
  const bad = [...reads, ...writes].find(p => !usable(p));
  if (bad) return { ok: false, error: `the path ${JSON.stringify(bad)} cannot be passed to node's permission model` };
  const args: string[] = [support.flag];
  for (const p of reads) args.push(`--allow-fs-read=${p}`);
  for (const p of writes) args.push(`--allow-fs-write=${p}`);
  if (policy.process) args.push("--allow-child-process");
  return { ok: true, args };
}
