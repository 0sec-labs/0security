import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { assertEgressAllowed, fetchScoped } from "@0/engine";
import { acceptPolicyBundle } from "./state.js";
import { MAX_BUNDLE_BYTES, PolicyBundleError, parseTrustedKey, verifyPolicyBundle, type TrustedKey } from "./verify.js";

export interface PolicyBundleOptions { policyBundle?: string; policyBundleKey?: string[]; policyBundleKeyFile?: string[]; scanRoots?: string[] }
export interface LoadedBundle { policyText: string; version: number; keyId: string; source: string }

const MAX_KEY_BYTES = 16 * 1024;

/** The git working tree (or, without one, the folder) the run is started in. A key file inside it could be planted by the repository being scanned. */
function workingTreeRoot(cwd: string): string {
  let dir = resolve(cwd);
  for (;;) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return resolve(cwd);
    dir = parent;
  }
}
const inside = (child: string, root: string): boolean => { const r = relative(root, child); return r === "" || (!r.startsWith("..") && !isAbsolute(r)); };

function readKeyFile(file: string, scanRoots: readonly string[]): string {
  if (!isAbsolute(file)) throw new PolicyBundleError(`Policy bundle key file must be an absolute path: ${file}`);
  let info;
  try { info = lstatSync(file); } catch { throw new PolicyBundleError(`Policy bundle key file not found: ${file}`); }
  if (info.isSymbolicLink()) throw new PolicyBundleError(`Policy bundle key file must not be a symlink: ${file}`);
  if (!info.isFile() || info.size > MAX_KEY_BYTES) throw new PolicyBundleError(`Policy bundle key file is not a small regular file: ${file}`);
  const real = realpathSync(file);
  const roots = new Set<string>();
  for (const r of scanRoots) { roots.add(resolve(r)); roots.add(workingTreeRoot(r)); if (existsSync(r)) { const rr = realpathSync(r); roots.add(rr); roots.add(workingTreeRoot(rr)); } }
  for (const root of roots) {
    if (inside(real, root) || inside(resolve(file), root)) throw new PolicyBundleError(`Policy bundle key file must be outside the working tree and every repository the command reads (${root}): ${file}`);
  }
  return readFileSync(file, "utf8");
}

/**
 * Trusted keys come from two separate sources that never fall back to each other.
 * Inline key text (--policy-bundle-key, ZERO_POLICY_BUNDLE_KEY, comma separated) is only ever parsed as a key, never opened as a path.
 * Key files (--policy-bundle-key-file, ZERO_POLICY_BUNDLE_KEY_FILE) must be absolute, not symlinks, and outside every repository the command reads (the current folder, --repo and the repository it resolves to).
 */
export function configuredKeys(inline: readonly string[] | undefined, files: readonly string[] | undefined, env: NodeJS.ProcessEnv = process.env, scan: string | readonly string[] = process.cwd()): TrustedKey[] {
  const scanRoots = typeof scan === "string" ? [scan] : scan;
  const clean = (list: readonly string[]) => list.map(v => v.trim()).filter(Boolean);
  const texts = clean([...(inline ?? []), ...(env.ZERO_POLICY_BUNDLE_KEY?.split(",") ?? [])]);
  const paths = clean([...(files ?? []), ...(env.ZERO_POLICY_BUNDLE_KEY_FILE?.split(",") ?? [])]);
  return [...texts.map(parseTrustedKey), ...paths.map(p => parseTrustedKey(readKeyFile(p, scanRoots)))];
}

/** A fixed public base: the destination the user gave must never become the trusted local origin, so loopback and private addresses stay blocked. */
const PUBLIC_BASE = "https://policy-bundle.example.com";

async function readSource(source: string, env: NodeJS.ProcessEnv): Promise<string> {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source)) {
    let url: URL;
    try { url = new URL(source); } catch { throw new PolicyBundleError("Policy bundle URL is not valid."); }
    if (url.protocol !== "https:") throw new PolicyBundleError("Policy bundle URLs must use https.");
    assertEgressAllowed(url.host, env);
    try {
      const res = await fetchScoped(url.href, { method: "GET", headers: { accept: "application/json" } }, { baseUrl: PUBLIC_BASE, allowPublicNetwork: true, maxResponseBytes: MAX_BUNDLE_BYTES, timeoutMs: 15_000, maxRedirects: 0, validateUrl: u => { if (!u.startsWith("https://")) throw new Error("https only"); } });
      if (!res.ok) throw new PolicyBundleError(`Policy bundle fetch failed with HTTP ${res.status}.`);
      return await res.text();
    } catch (error) {
      if (error instanceof PolicyBundleError) throw error;
      throw new PolicyBundleError(`Policy bundle fetch failed: ${error instanceof Error ? error.message.split("\n")[0] : "error"}`);
    }
  }
  const path = resolve(source);
  if (!existsSync(path)) throw new PolicyBundleError(`Policy bundle file not found: ${source}`);
  if (statSync(path).size > MAX_BUNDLE_BYTES) throw new PolicyBundleError("Policy bundle is too large.");
  return readFileSync(path, "utf8");
}

/** Fetch, verify against the configured keys, check the version floor, and return the policy text. Nothing is recorded or used on failure. */
export async function loadPolicyBundle(options: PolicyBundleOptions, home?: string, env: NodeJS.ProcessEnv = process.env): Promise<LoadedBundle | undefined> {
  if (!options.policyBundle) return undefined;
  const keys = configuredKeys(options.policyBundleKey, options.policyBundleKeyFile, env, [process.cwd(), ...(options.scanRoots ?? [])]);
  const verified = verifyPolicyBundle(await readSource(options.policyBundle, env), keys);
  acceptPolicyBundle(verified, home);
  return { policyText: verified.policyText, version: verified.version, keyId: verified.keyId, source: options.policyBundle };
}
