import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { assertEgressAllowed, fetchScoped } from "@0/engine";
import { acceptPolicyBundle } from "./state.js";
import { MAX_BUNDLE_BYTES, PolicyBundleError, parseTrustedKey, verifyPolicyBundle, type TrustedKey } from "./verify.js";

export interface PolicyBundleOptions { policyBundle?: string; policyBundleKey?: string[] }
export interface LoadedBundle { policyText: string; version: number; keyId: string; source: string }

/** Each configured key is a file holding a key, or the key text itself. ZERO_POLICY_BUNDLE_KEY holds the same, separated by commas. */
export function configuredKeys(values: readonly string[] | undefined, env: NodeJS.ProcessEnv = process.env): TrustedKey[] {
  const all = [...(values ?? []), ...(env.ZERO_POLICY_BUNDLE_KEY?.split(",") ?? [])].map(v => v.trim()).filter(Boolean);
  return all.map(v => parseTrustedKey(existsSync(resolve(v)) && statSync(resolve(v)).isFile() ? readFileSync(resolve(v), "utf8") : v));
}

async function readSource(source: string, env: NodeJS.ProcessEnv): Promise<string> {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source)) {
    let url: URL;
    try { url = new URL(source); } catch { throw new PolicyBundleError("Policy bundle URL is not valid."); }
    if (url.protocol !== "https:") throw new PolicyBundleError("Policy bundle URLs must use https.");
    assertEgressAllowed(url.host, env);
    try {
      const res = await fetchScoped(url.href, { method: "GET", headers: { accept: "application/json" } }, { baseUrl: url.origin, allowPublicNetwork: true, maxResponseBytes: MAX_BUNDLE_BYTES, timeoutMs: 15_000, maxRedirects: 0, validateUrl: u => { if (!u.startsWith("https://")) throw new Error("https only"); } });
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
  const keys = configuredKeys(options.policyBundleKey, env);
  const verified = verifyPolicyBundle(await readSource(options.policyBundle, env), keys);
  acceptPolicyBundle(verified, home);
  return { policyText: verified.policyText, version: verified.version, keyId: verified.keyId, source: options.policyBundle };
}
