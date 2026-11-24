// Bridge to the key-gated enterprise package for the shared findings server (see scripts/check-enterprise-boundary.mjs).
// Call sites outside this file are plain `if (!hasFindingsServer())` checks.
import { featureMode, hasFeature, requireFeature } from "@0/enterprise";

export {
  INGEST_LIMITS,
  IngestError,
  WRITE_FINDINGS_SCOPE,
  ingestDigest,
  ingestFingerprint,
  parseIngestBody,
  parseIngestLabels,
  summarizeOrg,
  suppressionReasonError,
  triageHistoryAction,
} from "@0/enterprise";
export type { IngestLabels, OrgRow, OrgSummary, ParsedIngestBody } from "@0/enterprise";

/** True when the license allows paid writes: ingest, new write keys, required suppression reasons and history. */
export function hasFindingsServer(): boolean {
  return hasFeature("findings-server");
}

/** True when stored shared-server data may be read: licensed, including after expiry. */
export function canReadFindingsServer(): boolean {
  return featureMode("findings-server") !== "none";
}

/** The sentence to show when the feature is not available (needs a license, or has expired). */
export function findingsServerMessage(): string {
  return requireFeature("findings-server") ?? "The shared findings server is available.";
}
