// The only file in packages/cli that imports the key-gated enterprise package (see scripts/check-enterprise-boundary.mjs).
import { EvidenceKeyError, SamlError, SamlServiceProvider, formatLicenseStatus, hasFeature, licenseStatus, parseIdpMetadata, requireFeature, signEvidenceStatement, type DsseEnvelope, type LicenseStatus, type SamlIdentity } from "@0/enterprise";

export { SamlError, SamlServiceProvider, parseIdpMetadata };
export type { SamlIdentity };

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
