/**
 * Optional Foxguard backend: `foxguard graph <folder>` prints the code graph (schema version 1, see
 * docs/design/code-index.md). When a Foxguard binary with that subcommand is found, its graph replaces the
 * built-in extractor; anything else (no binary, older binary, bad output, timeout) returns undefined and the
 * caller uses the built-in index. Offline: a local process, no network, no shell.
 */
import { execFile } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import type { CodeIndex } from "./types.js";

const run = promisify(execFile);

const sink = z.object({ category: z.enum(["command", "code-eval", "sql", "file", "network", "deserialize", "template", "redirect"]), text: z.string().max(300) });
const bounded = (n: number) => z.string().max(n);

/** Schema version 1 of `foxguard graph`. Unknown top-level keys (for example `taintSummaries`) are ignored. */
export const graphV1 = z.object({
  version: z.literal(1),
  producer: z.string().max(40).optional(),
  files: z.number().int().min(0),
  symbols: z.array(z.object({
    id: bounded(600), name: bounded(300), qualified: bounded(400), kind: z.enum(["function", "method", "route-handler", "module"]),
    file: bounded(600), line: z.number().int().min(1), endLine: z.number().int().min(1), language: z.enum(["javascript", "python", "java"]),
  })).max(400_000),
  calls: z.array(z.object({
    from: bounded(600), name: bounded(300), text: bounded(400), file: bounded(600), line: z.number().int().min(1), sink: sink.optional(), auth: z.boolean().optional(), receiverType: bounded(200).optional(),
  })).max(2_000_000),
  routes: z.array(z.object({
    method: bounded(12), path: bounded(500), file: bounded(600), line: z.number().int().min(1), handler: bounded(600),
    middleware: z.array(bounded(300)).max(100), framework: bounded(40), authSignals: z.array(bounded(300)).max(100).optional(),
  })).max(100_000),
  unsupported: z.record(z.string(), z.number().int().min(0)).default({}),
  truncated: z.boolean().default(false),
});

const probed = new Map<string, boolean>();

function findBinary(env: NodeJS.ProcessEnv): string | undefined {
  const explicit = env["ZERO_FOXGUARD_PATH"];
  const candidates = explicit ? [explicit] : (env["PATH"] ?? "").split(delimiter).filter((d) => d && isAbsolute(d)).map((d) => join(d, "foxguard"));
  for (const file of candidates) {
    try { accessSync(file, constants.X_OK); if (statSync(file).isFile()) return file; } catch { /* next */ }
  }
  return undefined;
}

/** Most bytes of graph JSON read from the child; over it the child is killed and the built-in index is used. */
export const GRAPH_MAX_BYTES = 128 * 1024 * 1024;
/** Per-file time budget passed to `foxguard graph`, seconds. */
const GRAPH_FILE_TIMEOUT_SEC = "30";

const SAFE_ENV = (env: NodeJS.ProcessEnv): NodeJS.ProcessEnv => ({ PATH: env["PATH"] ?? "", HOME: env["HOME"] ?? "", DO_NOT_TRACK: "1" });

/** `foxguard graph` reads no config file from the scanned folder (it takes only the folder and these flags), so no empty-config argument applies. */
export function graphArgs(root: string): string[] { return ["graph", "--file-timeout", GRAPH_FILE_TIMEOUT_SEC, root]; }

export async function foxguardGraph(root: string, commit: string, fingerprint: string, env: NodeJS.ProcessEnv = process.env): Promise<CodeIndex | undefined> {
  const bin = findBinary(env);
  if (!bin) return undefined;
  try {
    let ok = probed.get(bin);
    if (ok === undefined) {
      // An older binary has no `graph` subcommand and would treat the word as a scan path, so ask for help first.
      const help = await run(bin, ["graph", "--help"], { timeout: 10_000, env: SAFE_ENV(env), maxBuffer: 256 * 1024 });
      ok = /schema version 1/i.test(help.stdout) && help.stdout.includes("--file-timeout");
      probed.set(bin, ok);
    }
    if (!ok) return undefined;
    const { stdout } = await run(bin, graphArgs(root), { timeout: 180_000, env: SAFE_ENV(env), maxBuffer: GRAPH_MAX_BYTES });
    const parsed = graphV1.safeParse(JSON.parse(stdout));
    if (!parsed.success) return undefined;
    const g = parsed.data;
    return { version: 1, root, commit, fingerprint, files: g.files, symbols: g.symbols, calls: g.calls, routes: g.routes, unsupported: g.unsupported, truncated: g.truncated, engine: "foxguard" };
  } catch {
    return undefined;
  }
}

export function clearFoxguardProbe(): void { probed.clear(); }
