/**
 * Picks the OS sandbox backend, honours `ZERO_SANDBOX`, and turns "run this program" into "run it inside the sandbox".
 *
 *   ZERO_SANDBOX=auto     (default) sandbox an extension that declares a `sandbox` block; say so when none is available.
 *   ZERO_SANDBOX=require  sandbox every extension process (an extension with no block gets the strictest defaults);
 *                         refuse to run when no backend works.
 *   ZERO_SANDBOX=off      run as before, no sandbox.
 *
 * Backends: macOS `sandbox-exec` (Seatbelt, deprecated by Apple but present) and Linux `bwrap`. Nothing here claims more
 * than the generated profile and arguments do; see the tests for what was observed.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bwrapArgs } from "./bwrap.js";
import { DEFAULT_DECL, describeSandbox, resolveSandbox, WORKSPACE_TOKEN, type ResolvedSandbox, type SandboxDecl } from "./policy.js";
import { detectNodePermission, isNodeProgram, nodePermissionArgs, type NodePermissionSupport } from "./node-permission.js";
import { resolveLaunch } from "./launcher.js";
import { seatbeltArgs, seatbeltProfile } from "./seatbelt.js";

export type SandboxMode = "auto" | "require" | "off";
export type SandboxBackend = "seatbelt" | "bwrap";

export function sandboxMode(env: Readonly<Record<string, string | undefined>> = process.env): { ok: true; mode: SandboxMode } | { ok: false; error: string } {
  const raw = env.ZERO_SANDBOX?.trim().toLowerCase();
  if (!raw) return { ok: true, mode: "auto" };
  if (raw === "auto" || raw === "require" || raw === "off") return { ok: true, mode: raw };
  return { ok: false, error: `ZERO_SANDBOX=${JSON.stringify(env.ZERO_SANDBOX)} is not valid: use auto, require or off` };
}

export interface ToolStatus { present: boolean; path?: string; usable?: boolean; detail: string }
export interface SandboxStatus {
  platform: NodeJS.Platform;
  seatbelt: ToolStatus; bwrap: ToolStatus; docker: ToolStatus;
  /** The backend a run would use here, or null with the reason. */
  backend: SandboxBackend | null;
  reason: string;
}

export interface DetectHost {
  platform: NodeJS.Platform;
  pathEnv: string;
  exists(file: string): boolean;
  /** Runs a tiny program under the tool and reports whether it worked. */
  probe(file: string, args: string[]): { ok: boolean; detail: string };
}

const defaultHost = (env: Readonly<Record<string, string | undefined>>): DetectHost => ({
  platform: process.platform,
  pathEnv: env.PATH ?? "",
  exists: f => { try { fs.accessSync(f, fs.constants.X_OK); return fs.statSync(f).isFile(); } catch { return false; } },
  probe(file, args) {
    const r = spawnSync(file, args, { encoding: "utf8", timeout: 4000, stdio: ["ignore", "ignore", "pipe"] });
    if (r.status === 0) return { ok: true, detail: "works" };
    return { ok: false, detail: (r.stderr || r.error?.message || `exit ${r.status}`).toString().trim().split("\n")[0]?.slice(0, 140) || "failed" };
  },
});

export function whichIn(name: string, pathEnv: string, exists: (f: string) => boolean = f => { try { fs.accessSync(f, fs.constants.X_OK); return fs.statSync(f).isFile(); } catch { return false; } }): string | null {
  for (const dir of pathEnv.split(path.delimiter)) { if (!dir || !path.isAbsolute(dir)) continue; const f = path.join(dir, name); if (exists(f)) return f; }
  return null;
}

let cached: SandboxStatus | undefined;
/** What this machine offers. Probes once per process (a probe starts a tiny program under the tool). */
export function detectSandbox(host?: DetectHost, env: Readonly<Record<string, string | undefined>> = process.env): SandboxStatus {
  if (!host && cached) return cached;
  const h = host ?? defaultHost(env);
  const missing = (detail: string): ToolStatus => ({ present: false, detail });
  let seatbelt = missing(h.platform === "darwin" ? "sandbox-exec not found" : "macOS only");
  if (h.platform === "darwin" && h.exists("/usr/bin/sandbox-exec")) {
    const r = h.probe("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)", "/usr/bin/true"]);
    seatbelt = { present: true, path: "/usr/bin/sandbox-exec", usable: r.ok, detail: r.ok ? "works (deprecated by Apple, still shipped)" : `present but not usable here: ${r.detail}` };
  }
  let bwrap = missing(h.platform === "linux" ? "bwrap not found in PATH" : "Linux only");
  const bwrapPath = h.platform === "linux" ? whichIn("bwrap", h.pathEnv, h.exists) : null;
  if (bwrapPath) {
    const truth = ["/usr/bin/true", "/bin/true"].find(f => h.exists(f));
    const r = truth ? h.probe(bwrapPath, ["--ro-bind", "/", "/", "--unshare-all", "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev", truth]) : { ok: false, detail: "no true binary to probe with" };
    bwrap = { present: true, path: bwrapPath, usable: r.ok, detail: r.ok ? "works" : `present but not usable here (bwrap needs unprivileged user namespaces and a /proc mount): ${r.detail}` };
  }
  const dockerPath = whichIn("docker", h.pathEnv, h.exists);
  const docker: ToolStatus = dockerPath ? { present: true, path: dockerPath, detail: "found (0 does not use it for extensions)" } : missing("docker not found");
  const backend: SandboxBackend | null = seatbelt.usable ? "seatbelt" : bwrap.usable ? "bwrap" : null;
  const reason = backend ? "" : h.platform === "win32" ? "Windows has no supported sandbox backend" : h.platform === "darwin" ? seatbelt.detail : h.platform === "linux" ? bwrap.detail : `no sandbox backend for ${h.platform}`;
  const status: SandboxStatus = { platform: h.platform, seatbelt, bwrap, docker, backend, reason };
  if (!host) cached = status;
  return status;
}
/** Forget the probe result (tests). */
export const resetSandboxDetection = (): void => { cached = undefined; };

const positiveInt = (raw: string | undefined, max: number): number | undefined => { const n = Number(raw); return raw && Number.isInteger(n) && n > 0 && n <= max ? n : undefined; };
/** Optional limits from the environment. CPU seconds work on macOS and Linux; the memory limit only on Linux (macOS does not enforce it). */
export function sandboxLimits(env: Readonly<Record<string, string | undefined>> = process.env, platform: NodeJS.Platform = process.platform): ResolvedSandbox["limits"] {
  const cpuSeconds = positiveInt(env.ZERO_SANDBOX_CPU_SECONDS, 86_400);
  const memoryMb = platform === "linux" ? positiveInt(env.ZERO_SANDBOX_MEMORY_MB, 1_048_576) : undefined;
  return { ...(cpuSeconds ? { cpuSeconds } : {}), ...(memoryMb ? { memoryMb } : {}) };
}

/** Wrap a program in a `ulimit` step that runs OUTSIDE the sandbox, so the sandboxed program inherits the limits. */
export function withLimits(file: string, args: readonly string[], limits: ResolvedSandbox["limits"]): { file: string; args: string[] } {
  if (!limits.cpuSeconds && !limits.memoryMb) return { file, args: [...args] };
  const script = 'if [ "$1" != 0 ]; then ulimit -t "$1" || exit 126; fi; if [ "$2" != 0 ]; then ulimit -v "$(( $2 * 1024 ))" || exit 126; fi; shift 2; exec "$@"';
  return { file: "/bin/sh", args: ["-c", script, "sh", String(limits.cpuSeconds ?? 0), String(limits.memoryMb ?? 0), file, ...args] };
}

/** The file and arguments that run `argv` inside the policy on `backend`. */
export function sandboxedCommand(backend: SandboxBackend, policy: ResolvedSandbox, argv: readonly string[], cwd: string, backendPath?: string): { file: string; args: string[] } {
  const inner = backend === "seatbelt"
    ? { file: backendPath ?? "/usr/bin/sandbox-exec", args: [...seatbeltArgs(seatbeltProfile(policy)), ...argv] }
    : { file: backendPath ?? "bwrap", args: [...bwrapArgs(policy, { cwd }), ...argv] };
  return withLimits(inner.file, inner.args, policy.limits);
}

export interface SandboxRequest {
  /** The extension's declaration, or null when its manifest has no `sandbox` block. */
  decl: SandboxDecl | null;
  extensionDir: string;
  /** The folder the operator is working in. Visible only when the declaration names it. */
  workspace: string | null;
  /** Program and arguments, no shell. The first item is made absolute using PATH from `env`. */
  argv: readonly string[];
  /** Interpreter names the policy may start (the trusted interpreter set). */
  interpreters: readonly string[];
  env: Readonly<Record<string, string>>;
  cwd: string;
  /** For messages: "script scripts/run.sh of extension x". */
  label: string;
}

export type SandboxPlan =
  | { kind: "sandboxed"; file: string; args: string[]; cwd: string; env: Record<string, string>; status: string; cleanup(): void }
  | { kind: "unsandboxed"; status: string }
  | { kind: "refused"; error: string };

export interface PlanOptions { env?: Readonly<Record<string, string | undefined>>; status?: SandboxStatus; scratchRoot?: string; nodeSupport?: NodePermissionSupport }

/** ZERO_SANDBOX_NODE_PERMISSION=off leaves node's permission flags out (an extension that needs a native addon, for example). */
const nodePermissionWanted = (env: Readonly<Record<string, string | undefined>>): boolean => env.ZERO_SANDBOX_NODE_PERMISSION?.trim().toLowerCase() !== "off";

/** Flags that would widen or replace node's own permissions. Quotes in NODE_OPTIONS are ignored. `--require` and `--import` are allowed: node applies its permissions before it loads them. */
const NODE_WIDENING_FLAG = /^["']?--(?:allow[-_]|no[-_](?:experimental[-_])?permission|env[-_]file|(?:no[-_])?experimental[-_]config[-_]file|(?:no[-_])?experimental[-_]default[-_]config[-_]file|config[-_]file)/i;
/** Variables that make the system loader put code into a process before node starts. */
const LOADER_ENV = /^(?:LD_|DYLD_)/i;

const resolveProgram = (name: string, pathEnv: string): string => (name.includes("/") ? name : whichIn(name, pathEnv) ?? name);
const real = (p: string): string => { try { return fs.realpathSync(p); } catch { return p; } };

export function planSandbox(req: SandboxRequest, options: PlanOptions = {}): SandboxPlan {
  const env = options.env ?? process.env;
  const m = sandboxMode(env);
  if (!m.ok) return { kind: "refused", error: m.error };
  if (m.mode === "off") return { kind: "unsandboxed", status: "sandbox: not applied (ZERO_SANDBOX=off)" };
  if (!req.decl && m.mode === "auto") return { kind: "unsandboxed", status: `sandbox: not applied (${req.label} declares no sandbox block; set ZERO_SANDBOX=require to sandbox it with the strict defaults)` };
  const detected = options.status ?? detectSandbox(undefined, env);
  const pathEnv = req.env.PATH ?? process.env.PATH ?? "";
  const rawProgram = resolveProgram(req.argv[0] ?? "", pathEnv);
  // Look through `env`, and refuse launchers that could hide node, so the node layer is applied or the run is refused (see launcher.ts).
  const launch = nodePermissionWanted(env) && req.argv[0]
    ? resolveLaunch(req.argv, req.env, { resolve: resolveProgram, real, isNode: p => path.isAbsolute(p) && isNodeProgram(p, real(p)) }, req.label)
    : undefined;
  if (launch && !launch.ok) return { kind: "refused", error: launch.error };
  const usesEnvNode = Boolean(launch?.ok && launch.unwrapped);
  const program = usesEnvNode && launch?.ok ? launch.program : rawProgram;
  const programArgs = usesEnvNode && launch?.ok ? launch.args : req.argv.slice(1);
  const childEnv: Record<string, string> = usesEnvNode && launch?.ok ? launch.env : { ...req.env };
  // Node's permission model: a layer for programs started with node, and the only one where no OS sandbox works.
  const nodeSupport = nodePermissionWanted(env) && program && path.isAbsolute(program) && isNodeProgram(program, real(program)) ? (options.nodeSupport ?? detectNodePermission(program)) : undefined;
  if (!detected.backend) {
    const nodeOnly = nodeSupport?.supported === true;
    // require means every declared limit is enforced. Node's model cannot enforce "no network", so it only stands in when the network is declared on.
    if (m.mode === "require" && !(nodeOnly && (req.decl ?? DEFAULT_DECL).network)) return { kind: "refused", error: `ZERO_SANDBOX=require but no sandbox is available (${detected.reason}). Run \`0security doctor\` to see what is missing, or set ZERO_SANDBOX=auto to run without one.` };
    if (!nodeOnly) return { kind: "unsandboxed", status: `sandbox: not available (${detected.reason}); ran without it` };
  }
  const decl = req.decl ?? DEFAULT_DECL;
  const usesWorkspace = [...decl.readPaths, ...decl.writePaths].includes(WORKSPACE_TOKEN);
  const workspace = usesWorkspace ? req.workspace : null;
  if (!req.argv[0] || !path.isAbsolute(program)) return { kind: "refused", error: `cannot start ${req.label} in a sandbox: ${req.argv[0] ?? "(nothing)"} was not found in PATH` };
  const decl0 = req.decl ?? DEFAULT_DECL;
  // Per-binary allowlist: each declared name must resolve to a program on PATH, or the run is refused (fail closed).
  const namedPaths: string[] = [];
  for (const name of decl0.programs) {
    const p = whichIn(name, pathEnv);
    if (!p) return { kind: "refused", error: `cannot start ${req.label} in a sandbox: it declares the program ${JSON.stringify(name)}, which was not found in PATH` };
    namedPaths.push(p, real(p));
  }
  if (!detected.backend && decl0.programs.length && nodeSupport?.supported) return { kind: "refused", error: `cannot start ${req.label} in a sandbox: it declares programs it may start, and node's permission layer cannot limit which programs start. That needs an OS sandbox (macOS Seatbelt or Linux bubblewrap)` };
  const interpreterPaths = req.interpreters.flatMap(n => { const p = whichIn(n, pathEnv); return p ? [p, real(p)] : []; });
  const execAllow = [program, real(program), ...interpreterPaths, ...namedPaths, "/usr/bin/env", real("/usr/bin/env"), "/bin/sh", real("/bin/sh"), "/bin/bash", real("/bin/bash")].filter(p => fs.existsSync(p));

  let scratch: string;
  try { scratch = fs.mkdtempSync(path.join(real(options.scratchRoot ?? os.tmpdir()), "0-sandbox-")); } catch (e) { return { kind: "refused", error: `cannot create a scratch folder for ${req.label}: ${e instanceof Error ? e.message : String(e)}` }; }
  const cleanup = (): void => { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } };
  const resolved = resolveSandbox({ decl, extensionDir: req.extensionDir, scratchDir: scratch, workspace, execAllow, limits: sandboxLimits(env) });
  if (!resolved.ok) { cleanup(); return { kind: "refused", error: `cannot sandbox ${req.label}: ${resolved.error}` }; }
  const policy = resolved.value;
  const cwd = usesWorkspace && policy.workspace ? policy.workspace : policy.extensionDir;
  const backendPath = detected.backend === "seatbelt" ? detected.seatbelt.path : detected.bwrap.path;
  let argv = [program, ...programArgs];
  let nodeNote = "";
  if (nodeSupport?.supported) {
    const flags = nodePermissionArgs(policy, nodeSupport);
    if (flags.ok) {
      // Flags that widen node's own permissions would win over ours, from the arguments, an env file or NODE_OPTIONS: refuse them.
      const widens = programArgs.find(arg => NODE_WIDENING_FLAG.test(arg)) ?? Object.entries(childEnv).filter(([k]) => /^NODE_OPTIONS$/i.test(k)).flatMap(([, v]) => v.split(/\s+/)).find(arg => NODE_WIDENING_FLAG.test(arg));
      if (widens) { cleanup(); return { kind: "refused", error: `cannot start ${req.label} in a sandbox: ${widens.slice(0, 60)} would change node's permissions` }; }
      const loader = Object.keys(childEnv).find(k => LOADER_ENV.test(k));
      if (loader) { cleanup(); return { kind: "refused", error: `cannot start ${req.label} in a sandbox: ${loader} would load code into node before its permissions apply` }; }
      argv = [program, ...flags.args, ...programArgs]; nodeNote = `${nodeSupport.flag}: folders, child programs, workers`; }
    else if (!detected.backend) { cleanup(); return { kind: "unsandboxed", status: `sandbox: not available (${detected.reason}; ${flags.error}); ran without it` }; }
  }
  const limitNote = policy.limits.cpuSeconds || policy.limits.memoryMb ? `, limits ${[policy.limits.cpuSeconds ? `${policy.limits.cpuSeconds}s cpu` : "", policy.limits.memoryMb ? `${policy.limits.memoryMb} MB memory` : ""].filter(Boolean).join(" ")}` : "";
  if (!detected.backend) {
    const alone = withLimits(argv[0]!, argv.slice(1), policy.limits);
    return { kind: "sandboxed", ...alone, cwd, env: { ...childEnv, TMPDIR: scratch, ZERO_SANDBOX_ACTIVE: "1" }, status: `sandbox: applied (${nodeNote}; writes only to a scratch folder${policy.writePaths.length ? " and declared paths" : ""}; the network is NOT restricted by this layer${limitNote})`, cleanup };
  }
  const cmd = sandboxedCommand(detected.backend, policy, argv, cwd, backendPath);
  return { kind: "sandboxed", ...cmd, cwd, env: { ...childEnv, TMPDIR: scratch, ZERO_SANDBOX_ACTIVE: "1" }, status: `sandbox: applied (${describeSandbox(detected.backend, policy)}${nodeNote ? `; ${nodeNote}` : ""}${limitNote})`, cleanup };
}
