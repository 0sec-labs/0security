// The only file in packages/cli that imports the key-gated enterprise package (see scripts/check-enterprise-boundary.mjs).
import { EvidenceKeyError, formatLicenseStatus, hasFeature, licenseStatus, requireFeature, signEvidenceStatement, type DsseEnvelope, type LicenseStatus } from "@0/enterprise";

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
