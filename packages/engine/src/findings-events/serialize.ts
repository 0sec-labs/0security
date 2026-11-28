import { effectiveTriageStatus } from "../shared/triage-expiry.js";
import type { Finding } from "../shared/types.js";
import { FINDINGS_EVENT_SCHEMA_ID, FINDINGS_EVENT_VERSION, findingEventSchema, type FindingEvent, type FindingEventStatus } from "./schema.js";

export interface FindingEventOptions {
  /** ISO time the event is produced; passed in so output is reproducible. */
  emittedAt: string;
  /** What was scanned (folder, repository or URL); used as the location when a finding cites no file. */
  target?: string;
  now?: Date | number;
}

/** A fixed finding is fixed; a false positive or a dismissed or still-accepted risk is suppressed; everything else is open. */
export function findingEventStatus(finding: Pick<Finding, "status" | "triageStatus" | "triageExpiresAt">, now?: Date | number): FindingEventStatus {
  if (finding.status === "fixed") return "fixed";
  if (finding.status === "false-positive") return "suppressed";
  const triage = effectiveTriageStatus(finding, now);
  return triage === "new" ? "open" : "suppressed";
}

/** One finding as a versioned event. The fingerprint is the finding's own; a finding without one falls back to its id. */
export function serializeFindingEvent(finding: Finding, options: FindingEventOptions): FindingEvent {
  const status = findingEventStatus(finding, options.now);
  const fingerprint = finding.fingerprint || finding.id;
  const cited = finding.reviewAnnotation;
  const [ruleTool, ruleId] = finding.templateId.includes("/") ? [finding.templateId.slice(0, finding.templateId.indexOf("/")), finding.templateId.slice(finding.templateId.indexOf("/") + 1)] : [undefined, finding.templateId];
  const event: FindingEvent = {
    schema: FINDINGS_EVENT_SCHEMA_ID,
    version: FINDINGS_EVENT_VERSION,
    id: `${fingerprint}:${status}`,
    type: `finding.${status}`,
    emittedAt: options.emittedAt,
    finding: {
      fingerprint,
      id: finding.id,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      category: finding.category,
      status,
      location: {
        ...(cited ? { path: cited.path, startLine: cited.startLine, ...(cited.endLine ? { endLine: cited.endLine } : {}) } : {}),
        ...(options.target ? { target: options.target } : {}),
      },
      ...(ruleId ? { ruleId } : {}),
      ...((finding.tool ?? ruleTool) ? { tool: finding.tool ?? ruleTool } : {}),
      ...(finding.cvssScore !== undefined ? { cvssScore: finding.cvssScore } : {}),
      ...(finding.cvssVector ? { cvssVector: finding.cvssVector } : {}),
    },
  };
  return findingEventSchema.parse(event);
}

export function serializeFindingEvents(findings: readonly Finding[], options: FindingEventOptions): FindingEvent[] {
  return findings.map(finding => serializeFindingEvent(finding, options));
}
