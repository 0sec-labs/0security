/**
 * `0security scan --scanner nuclei --target-url <url>`: run Nuclei, the operator's own tool, against one named target and read what it
 * wrote. 0 sends no request itself. The target must pass `assertScopedTarget` first; Nuclei is found on PATH (or ZERO_NUCLEI_PATH)
 * and is never downloaded; it is started without a shell, in an empty folder, with a timeout.
 */
import { execFile } from "node:child_process";
import { accessSync, constants, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { isIP } from "node:net";
import { delimiter, join } from "node:path";
import { assertScopedTarget, describeScopedTarget, parseScopeFile, type ResolveTargetHost, type ScopedTarget } from "@0/engine";
import { parseNucleiJsonl, type ImportedFinding } from "@0/engine/shared";

/** Run a binary without a shell. Its standard input is closed at once: Nuclei reads targets from a pipe on standard input and would wait for it. */
function exec(file: string, args: string[], options: { env: NodeJS.ProcessEnv; cwd: string; timeout: number; maxBuffer?: number }): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { ...options, windowsHide: true }, (error, stdout, stderr) => error ? reject(Object.assign(error, { stdout, stderr })) : resolve({ stdout, stderr }));
    child.stdin?.end();
  });
}

/** Templates carrying these tags are never run: they change data, exhaust the target, or send unusual input. */
export const NUCLEI_EXCLUDED_TAGS = ["intrusive", "dos", "fuzz"] as const;
export const NUCLEI_PATH_ENV = "ZERO_NUCLEI_PATH";
export const DEFAULT_RATE_LIMIT = 10;
export const DEFAULT_CONCURRENCY = 5;
export const MAX_RATE_LIMIT = 150;
export const MAX_CONCURRENCY = 25;
const MAX_SCOPE_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 20 * 1024 * 1024;

export interface NucleiTargetOptions {
  targetUrl: string;
  scopeFile?: string;
  acknowledgeHost?: string;
  rateLimit?: number;
  concurrency?: number;
  /** A template file or folder to run instead of the templates Nuclei has installed. */
  templates?: string;
  timeoutSeconds?: number;
}

export interface NucleiTargetIo {
  env?: NodeJS.ProcessEnv;
  resolve?: ResolveTargetHost;
  note?: (text: string) => void;
}

export interface NucleiTargetRun {
  target: ScopedTarget;
  scope: string;
  findings: ImportedFinding[];
  /** Nuclei's JSON Lines output, as written. */
  jsonl: string;
  version?: string;
  rateLimit: number;
  concurrency: number;
}

/** The Nuclei binary: ZERO_NUCLEI_PATH, else the first `nuclei` on PATH. Undefined when there is none. */
export function findNuclei(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const usable = (path: string) => { try { accessSync(path, constants.X_OK); return statSync(path).isFile(); } catch { return false; } };
  const named = env[NUCLEI_PATH_ENV]?.trim();
  if (named) return usable(named) ? named : undefined;
  for (const directory of (env.PATH ?? "").split(delimiter)) {
    if (!directory) continue;
    const candidate = join(directory, process.platform === "win32" ? "nuclei.exe" : "nuclei");
    if (usable(candidate)) return candidate;
  }
  return undefined;
}

export const NUCLEI_INSTALL_HINT = "Install Nuclei yourself (brew install nuclei, or https://github.com/projectdiscovery/nuclei), or set ZERO_NUCLEI_PATH to the binary. 0 never downloads it.";

/**
 * The URL Nuclei is given. A name is replaced by the address 0 checked, so Nuclei cannot resolve it again to something else;
 * the Host header and TLS server name keep the name. An address given directly is used as it is.
 */
export function pinnedUrl(target: ScopedTarget): { url: string; pin?: { host: string; hostname: string } } {
  if (isIP(target.hostname)) return { url: target.url };
  const address = target.addresses.find(candidate => isIP(candidate) === 4) ?? target.addresses[0]!;
  const url = new URL(target.url);
  url.hostname = address.includes(":") ? `[${address}]` : address;
  return { url: url.href, pin: { host: target.host, hostname: target.hostname } };
}

/** The arguments for one run. Interactsh (out-of-band callbacks to a public server) and update checks are always off. */
export function nucleiArguments(options: { url: string; out: string; rateLimit: number; concurrency: number; templates?: string; pin?: { host: string; hostname: string } }): string[] {
  return [
    "-u", options.url, "-jle", options.out,
    "-rl", String(options.rateLimit), "-c", String(options.concurrency),
    "-etags", NUCLEI_EXCLUDED_TAGS.join(","),
    "-ni", "-duc", "-silent", "-nc", "-retries", "0", "-timeout", "10",
    // Only http templates run: no dns, file, code, javascript, headless, tcp or whois templates, which can reach hosts other than the target.
    "-pt", "http",
    ...(options.templates ? ["-t", options.templates] : []),
    ...(options.pin ? ["-H", `Host: ${options.pin.host}`, "-sni", options.pin.hostname] : []),
  ];
}

function boundedInteger(value: number | undefined, fallback: number, max: number, flag: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1 || value > max) throw new Error(`${flag} must be a whole number from 1 to ${max}.`);
  return value;
}

export async function runNucleiTarget(options: NucleiTargetOptions, io: NucleiTargetIo = {}): Promise<NucleiTargetRun> {
  const env = io.env ?? process.env;
  const rateLimit = boundedInteger(options.rateLimit, DEFAULT_RATE_LIMIT, MAX_RATE_LIMIT, "--rate-limit");
  const concurrency = boundedInteger(options.concurrency, DEFAULT_CONCURRENCY, MAX_CONCURRENCY, "--concurrency");
  let scopeHosts: string[] | undefined;
  if (options.scopeFile) {
    const stat = statSync(options.scopeFile);
    if (!stat.isFile() || stat.size > MAX_SCOPE_BYTES) throw new Error("The scope file must be a regular file of at most 64 KB.");
    scopeHosts = parseScopeFile(readFileSync(options.scopeFile, "utf8"));
  }
  const target = await assertScopedTarget(options.targetUrl, {
    ...(scopeHosts ? { scopeHosts } : {}), ...(options.acknowledgeHost !== undefined ? { acknowledge: options.acknowledgeHost } : {}),
    ...(io.resolve ? { resolve: io.resolve } : {}), env,
  });
  const binary = findNuclei(env);
  if (!binary) throw new Error(`Nuclei is not installed. ${NUCLEI_INSTALL_HINT}`);
  const scope = describeScopedTarget(target);
  io.note?.(`scope: ${scope}`);

  const scratch = mkdtempSync(join(tmpdir(), "0-nuclei-"));
  const out = join(scratch, "results.jsonl");
  try {
    let version: string | undefined;
    try { version = /v?(\d+\.\d+\.\d+)/.exec((await exec(binary, ["-version"], { env, cwd: scratch, timeout: 15000 })).stderr)?.[1]; } catch { /* the version is optional */ }
    try {
      await exec(binary, nucleiArguments({ ...pinnedUrl(target), out, rateLimit, concurrency, ...(options.templates ? { templates: options.templates } : {}) }), { env, cwd: scratch, timeout: (options.timeoutSeconds ?? 600) * 1000, maxBuffer: 16 * 1024 * 1024 });
    } catch (error) {
      const failure = error as { killed?: boolean; signal?: string; stderr?: string; message?: string };
      if (failure.killed || failure.signal === "SIGTERM") throw new Error(`Nuclei did not finish within ${options.timeoutSeconds ?? 600} seconds.`);
      const text = String(failure.stderr || failure.message || "").replace(/[^\x20-\x7e\n]/g, "").trim();
      if (/no templates provided/i.test(text)) throw new Error("Nuclei has no templates. Run `nuclei -update-templates` yourself, or pass --templates <file-or-folder>. 0 does not download them.");
      throw new Error(`Nuclei failed: ${text.split("\n").slice(-3).join(" | ").slice(0, 400)}`);
    }
    let jsonl = "";
    try {
      if (statSync(out).size > MAX_OUTPUT_BYTES) throw new Error("Nuclei wrote more than 20 MB of results.");
      jsonl = readFileSync(out, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const findings = jsonl.trim() ? parseNucleiJsonl(jsonl).findings : [];
    return { target, scope, findings, jsonl, ...(version ? { version } : {}), rateLimit, concurrency };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
