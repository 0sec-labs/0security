/**
 * Canonical runtime validation for externally supplied findings, PoC steps,
 * and persisted report summaries. Shared by CLI ingestion and bundle replay.
 * Unknown finding metadata is preserved; execution-relevant fields are checked.
 */

import { z } from "zod";
import { ATTACK_CATEGORIES, classifyFinding } from "./finding-category.js";
import type { AttackCategory, Finding, PocStep, ReportSummary } from "./types.js";

// ── Enum mirrors ────────────────────────────────────────────────────────────
//
// These mirror the string-literal unions in `./index.js`. We list them
// explicitly (rather than e.g. deriving from a const tuple) so a drift between
// the schema and the TypeScript type surfaces as a compile error here.

const severityEnum = z.enum(["critical", "high", "medium", "low", "info"]);

const attackCategoryEnum = z.enum(ATTACK_CATEGORIES);

const findingStatusEnum = z.enum([
  "discovered",
  "verified",
  "confirmed",
  "scored",
  "reported",
  "fixed",
  "false-positive",
]);

const pocStepKindEnum = z.enum([
  "setup",
  "auth",
  "prerequisite",
  "exploit",
  "verify",
]);

// ── PocStep schema ──────────────────────────────────────────────────────────

export const pocStepActionSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("shell"),
    cmd: z.string(),
    cwd: z.string().optional(),
  }),
  z.object({
    type: z.literal("http"),
    method: z.string(),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
    body: z.string().optional(),
  }),
  z.object({
    type: z.literal("docker"),
    image: z.string(),
    args: z.array(z.string()),
  }),
  z.object({
    type: z.literal("note"),
    text: z.string(),
  }),
])

export const pocStepExpectSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("exit-zero") }),
  z.object({
    type: z.literal("http-status"),
    status: z.union([z.number(), z.array(z.number())]),
  }),
  z.object({ type: z.literal("body-contains"), text: z.string() }),
  z.object({ type: z.literal("body-matches"), pattern: z.string() }),
  z.object({ type: z.literal("file-exists"), path: z.string() }),
])

export const pocStepSchema = z.object({
  id: z.string(),
  kind: pocStepKindEnum,
  summary: z.string(),
  action: pocStepActionSchema,
  expect: pocStepExpectSchema.optional(),
});

export const pocStepArraySchema = z.array(pocStepSchema);

// ── Finding schema ──────────────────────────────────────────────────────────
//
// Mirrors `Finding` in `./index.js`. We `.passthrough()` so undocumented
// extras (e.g. cloud-side annotations, in-progress fields not yet landed in
// the shared type) round-trip without rejection. We only enforce the fields
// the rest of the codebase actually reads.
//
// Optional/forward-compatible fields like `layerVerdicts`, `remediation`,
// and `verificationSpec` are validated loosely as objects — the CLI doesn't
// need them for verify/disclose, and tightening would be churn-prone.

const evidenceSchema = z.object({
  request: z.string(),
  response: z.string(),
  analysis: z.string().optional(),
});

/**
 * A category the model chose, as one of ours. A label we have an alias for ("idor") becomes its category; one we do
 * not have becomes the closest category by its words, or `other`. The model's label comes back in `unknownLabel`, so
 * the finding is stored rather than rejected when it is read back. The full rules are in finding-category.ts.
 */
export function normalizeAttackCategory(value: unknown): { category: z.infer<typeof attackCategoryEnum>; unknownLabel?: string } {
  const { category, unknownLabel } = classifyFinding({ category: value });
  return unknownLabel ? { category, unknownLabel } : { category };
}

const clippedText = z.string().trim().min(1).max(500);

/** The structured root cause of a finding; every part is required so a half-filled record never seeds a hunt. */
export const rootCauseSchema = z.object({
  bugClass: clippedText,
  unsafePattern: z.object({ sink: clippedText, source: clippedText }),
  missingGuard: clippedText,
  designOrigin: clippedText,
});

export const findingSchema = z
  .object({
    id: z.string().min(1),
    templateId: z.string(),
    title: z.string(),
    description: z.string(),
    severity: severityEnum,
    category: attackCategoryEnum,
    status: findingStatusEnum,
    evidence: evidenceSchema,
    fingerprint: z.string().optional(),
    triageStatus: z.enum(["new", "accepted", "suppressed"]).optional(),
    triageNote: z.string().optional(),
    triageExpiresAt: z.string().optional(),
    triageApprover: z.string().optional(),
    scope: z.enum(["in-scope", "out-of-scope"]).optional(),
    scopeReason: z.string().optional(),
    scopeSource: z.string().optional(),
    layerVerdicts: z.array(z.unknown()).optional(),
    workflowStatus: z.string().optional(),
    workflowAssignee: z.string().nullable().optional(),
    confidence: z.number().optional(),
    cvssVector: z.string().optional(),
    cvssScore: z.number().optional(),
    remediation: z.unknown().optional(),
    pocSteps: pocStepArraySchema.optional(),
    verificationSpec: z.unknown().optional(),
    // A malformed record from an older or foreign source is dropped, never a reason to reject the finding.
    rootCause: rootCauseSchema.optional().catch(undefined),
    variantOf: z.string().min(1).optional().catch(undefined),
    timestamp: z.number(),
  })
  .passthrough();

// ── ReportSummary schema (used by `0 scan --replay`) ───────────────────
//
// Mirrors `ReportSummary` in `./index.js` — a flat object of seven
// non-negative integer counters. The CLI reads this back from the
// `scans.summary` DB column on `--replay`; an older schema version or a
// corrupt row would otherwise crash the replay renderer (which does
// `data.summary.totalAttacks` without a nullish guard).
//
// We're strict here on purpose: every field is required and must be a
// number. `.passthrough()` lets forward-compatible counters (e.g. a future
// "exploitable" tally) survive round-tripping. Counters must be
// non-negative integers — a negative value almost certainly indicates a
// migration bug rather than legitimate data we should accept.

const nonNegativeIntCounter = z.number().int().nonnegative();

export const reportSummarySchema = z
  .object({
    totalAttacks: nonNegativeIntCounter,
    totalFindings: nonNegativeIntCounter,
    critical: nonNegativeIntCounter,
    high: nonNegativeIntCounter,
    medium: nonNegativeIntCounter,
    low: nonNegativeIntCounter,
    info: nonNegativeIntCounter,
  })
  .passthrough();

// ── Type-level sync check ───────────────────────────────────────────────────
//
// These no-op assignments fail at compile time if the schema's inferred type
// diverges from the canonical TypeScript type for a field the CLI relies on.
// They're not exhaustive (the shared `Finding` has more optional metadata
// than we mirror), but they pin the load-bearing core.

type _FindingSchemaShape = z.infer<typeof findingSchema>;
type _PocStepSchemaShape = z.infer<typeof pocStepSchema>;
type _ReportSummarySchemaShape = z.infer<typeof reportSummarySchema>;
const _reportSummaryAssign: (x: _ReportSummarySchemaShape) => ReportSummary = (x) => x;
void _reportSummaryAssign;
type _AttackCategorySchema = z.infer<typeof attackCategoryEnum>;
const _attackCategoryAssign: (x: AttackCategory) => _AttackCategorySchema = (x) => x;
void _attackCategoryAssign;

// Width check: schema output must be assignable to the shared type for the
// fields we copy out. We intentionally don't require the schema to recreate
// every optional field of `Finding`/`PocStep` — only that what the schema
// produces is compatible.
const _findingAssign: (x: _FindingSchemaShape) => Pick<
  Finding,
  "id" | "templateId" | "title" | "description" | "severity" | "category" | "status" | "evidence" | "timestamp"
> = (x) => x;
const _pocStepAssign: (x: _PocStepSchemaShape) => PocStep = (x) => x;
void _findingAssign;
void _pocStepAssign;

// ── Friendly error formatter ────────────────────────────────────────────────

/**
 * Turn a `ZodError` into a one-line, user-readable summary that names the
 * first failing field and its issue. Used by both verify and disclose so
 * the operator sees something like:
 *
 *   finding JSON failed validation: severity: Invalid enum value. Expected 'critical' | 'high' | …, received 'super-critical'
 *
 * rather than zod's default multi-line dump.
 */
export function formatZodError(err: z.ZodError, label: string): string {
  const issue = err.issues[0];
  if (!issue) return `${label} failed validation`;
  const path = issue.path.length > 0 ? issue.path.join(".") : "<root>";
  return `${label} failed validation at ${path}: ${issue.message}`;
}
