// The only file in packages/cli that imports the key-gated enterprise package (see scripts/check-enterprise-boundary.mjs).
import { EvidenceKeyError, SamlError, SamlServiceProvider, formatLicenseStatus, hasFeature as licenseHasFeature, licenseStatus, parseIdpMetadata, requireFeature, signEvidenceStatement, type DsseEnvelope, type EnterpriseFeature, type LicenseStatus, type SamlIdentity } from "@0/enterprise";

export { SamlError, SamlServiceProvider, parseIdpMetadata };
export type { SamlIdentity };
// Licenses are checked against the public keys compiled into @0/enterprise and no others. Nothing in the
// environment, a file or a repository can add a signing key. Tests inject throwaway keys by mocking
// "@0/enterprise" (see src/web/__fixtures__/test-license.ts), never through this file.
const MEMO_MS = 2_000;
const memo = new Map<string, { at: number; value: boolean }>();

/**
 * True when the license in the process environment allows paid writes for the feature. Request handlers
 * call this often, so the answer is kept for two seconds per feature and license.
 */
export function hasFeature(name: EnterpriseFeature): boolean {
  const now = Date.now();
  const key = JSON.stringify([name, process.env.ZERO_LICENSE, process.env.ZERO_LICENSE_FILE]);
  const known = memo.get(key);
  if (known && now - known.at < MEMO_MS) return known.value;
  const value = licenseHasFeature(name, process.env, new Date(now));
  if (memo.size > 64) memo.clear();
  memo.set(key, { at: now, value });
  return value;
}

export { requireFeature };

/** License status read from the process environment. Contains no secret. */
export function readLicenseStatus(): LicenseStatus {
  return licenseStatus();
}

export function licenseStatusLines(status: LicenseStatus = readLicenseStatus()): string[] {
  return formatLicenseStatus(status);
}

/** Signed evidence bundles (paid). Null when allowed, else the message to show. */
export function evidenceSigningRefusal(): string | null {
  if (!hasFeature("evidence-signing")) return requireFeature("evidence-signing") ?? "Signed evidence bundles need an enterprise license.";
  return null;
}

/** Signs an evidence statement with the customer's Ed25519 private key (PEM). Call only after evidenceSigningRefusal() returned null. */
export function signEvidence(statementJson: string, privateKeyPem: string): DsseEnvelope {
  return signEvidenceStatement(statementJson, privateKeyPem);
}

export { EvidenceKeyError };
export type { DsseEnvelope };

/** True when the license in the process environment unlocks SAML sign-in. */
export function samlLicensed(): boolean {
  return hasFeature("saml");
}

/** Why SAML sign-in is unavailable, in words for the operator, or null when it is licensed. */
export function samlLicenseDenial(): string | null {
  return requireFeature("saml");
}
