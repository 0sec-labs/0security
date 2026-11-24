// The only file in packages/cli that imports the key-gated enterprise package (see scripts/check-enterprise-boundary.mjs).
import { formatLicenseStatus, licenseStatus, type LicenseStatus } from "@0/enterprise";

/** License status read from the process environment. Contains no secret. */
export function readLicenseStatus(): LicenseStatus {
  return licenseStatus();
}

export function licenseStatusLines(status: LicenseStatus = readLicenseStatus()): string[] {
  return formatLicenseStatus(status);
}
