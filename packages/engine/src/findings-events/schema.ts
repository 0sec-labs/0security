import { z } from "zod";

/** Bumped only for a breaking change; additive fields keep the number. See docs findings-events. */
export const FINDINGS_EVENT_VERSION = 1;
export const FINDINGS_EVENT_SCHEMA_ID = "0.findings-event";

export const findingEventStatusSchema = z.enum(["open", "fixed", "suppressed"]);
export const findingEventSeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

export const findingEventLocationSchema = z.object({
  path: z.string().optional(),
  startLine: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  target: z.string().optional(),
});

export const findingEventSchema = z.object({
  schema: z.literal(FINDINGS_EVENT_SCHEMA_ID),
  version: z.literal(FINDINGS_EVENT_VERSION),
  /** Stable per fingerprint and status, so a consumer can drop a redelivery of the same event. */
  id: z.string().min(1),
  type: z.enum(["finding.open", "finding.fixed", "finding.suppressed"]),
  emittedAt: z.string(),
  finding: z.object({
    fingerprint: z.string().min(1),
    id: z.string().min(1),
    title: z.string(),
    description: z.string(),
    severity: findingEventSeveritySchema,
    category: z.string(),
    status: findingEventStatusSchema,
    location: findingEventLocationSchema,
    ruleId: z.string().optional(),
    tool: z.string().optional(),
    cvssScore: z.number().optional(),
    cvssVector: z.string().optional(),
  }),
});

export type FindingEvent = z.infer<typeof findingEventSchema>;
export type FindingEventStatus = z.infer<typeof findingEventStatusSchema>;
export type FindingEventLocation = z.infer<typeof findingEventLocationSchema>;

/** The JSON Schema (draft 2020-12) of a findings event, generated from the same definition the serializer checks. */
export function findingEventJsonSchema(): Record<string, unknown> {
  return { $id: "urn:0:findings-event:v1", ...z.toJSONSchema(findingEventSchema) };
}
