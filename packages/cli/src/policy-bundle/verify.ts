/**
 * Offline check of a signed policy bundle. The bundle is a JSON envelope around the policy file text:
 *   { "format": "0-policy-bundle/1", "version": 3, "policy": "<base64 of the policy file>", "signature": "<base64 Ed25519>" }
 * The signature covers `0-policy-bundle/1\n<version>\n` followed by the exact policy bytes, so neither the
 * version nor one byte of the policy can change without the signature failing.
 */
import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";

export const BUNDLE_FORMAT = "0-policy-bundle/1";
export const MAX_BUNDLE_BYTES = 192 * 1024;

export class PolicyBundleError extends Error {}

export interface TrustedKey { id: string; key: KeyObject }
export interface VerifiedBundle { version: number; policyText: string; keyId: string; digest: string }

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** A key the user configured: a PEM public key, or the 32 raw bytes as base64 or hex. */
export function parseTrustedKey(text: string): TrustedKey {
  const value = text.trim();
  try {
    let key: KeyObject;
    if (value.includes("BEGIN")) key = createPublicKey(value);
    else {
      const raw = /^[0-9a-f]{64}$/i.test(value) ? Buffer.from(value, "hex") : Buffer.from(value, "base64");
      if (raw.length !== 32) throw new Error("not 32 bytes");
      key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
    }
    if (key.asymmetricKeyType !== "ed25519") throw new Error("not an Ed25519 key");
    const der = key.export({ format: "der", type: "spki" });
    return { id: createHash("sha256").update(der).digest("hex").slice(0, 16), key };
  } catch (error) {
    throw new PolicyBundleError(`Policy bundle key is not a valid Ed25519 public key (${error instanceof Error ? error.message : "unreadable"}).`);
  }
}

export function signedBytes(version: number, policy: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`${BUNDLE_FORMAT}\n${version}\n`, "utf8"), policy]);
}

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function verifyPolicyBundle(content: string, keys: readonly TrustedKey[]): VerifiedBundle {
  if (!keys.length) throw new PolicyBundleError("No policy bundle key is configured; pass --policy-bundle-key or --policy-bundle-key-file, or set ZERO_POLICY_BUNDLE_KEY or ZERO_POLICY_BUNDLE_KEY_FILE.");
  if (Buffer.byteLength(content) > MAX_BUNDLE_BYTES) throw new PolicyBundleError("Policy bundle is too large.");
  let raw: unknown;
  try { raw = JSON.parse(content); } catch { throw new PolicyBundleError("Policy bundle is not valid JSON."); }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new PolicyBundleError("Policy bundle must be a JSON object.");
  const b = raw as Record<string, unknown>;
  if (b.format !== BUNDLE_FORMAT) throw new PolicyBundleError(`Policy bundle format must be ${BUNDLE_FORMAT}.`);
  if (typeof b.version !== "number" || !Number.isSafeInteger(b.version) || b.version < 1) throw new PolicyBundleError("Policy bundle version must be a positive integer.");
  if (typeof b.policy !== "string" || !b.policy || !B64.test(b.policy)) throw new PolicyBundleError("Policy bundle policy must be base64 text.");
  if (typeof b.signature !== "string" || !B64.test(b.signature)) throw new PolicyBundleError("Policy bundle signature must be base64.");
  const policy = Buffer.from(b.policy, "base64");
  const signature = Buffer.from(b.signature, "base64");
  const message = signedBytes(b.version, policy);
  const match = signature.length === 64 ? keys.find(k => verify(null, message, k.key, signature)) : undefined;
  if (!match) throw new PolicyBundleError("Policy bundle signature does not match any configured key; it was not used.");
  let policyText: string;
  try { policyText = new TextDecoder("utf-8", { fatal: true }).decode(policy); } catch { throw new PolicyBundleError("Policy bundle policy is not valid UTF-8."); }
  return { version: b.version, policyText, keyId: match.id, digest: createHash("sha256").update(policy).digest("hex") };
}
