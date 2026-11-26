import { z } from "zod";
import { compareFindingsBySeverity } from "./finding-priority.js";

/** Operator declarations used only for work ordering; never observed exposure or verification. */
export const findingBusinessContextSchema = z.object({
  provenance: z.literal("operator"),
  repository: z.string().min(1).max(2048),
  tags: z.array(z.enum(["internet-facing", "payments", "personal-data", "operationally-critical", "internal-only", "non-production"])).max(6),
  notes: z.array(z.string().max(200)).max(32),
  shift: z.number().int().min(-2).max(2),
  score: z.number().int().min(-10).max(6),
  rationale: z.string().max(8192),
});
export type FindingBusinessContext = z.infer<typeof findingBusinessContextSchema>;
export function parseFindingBusinessContext(value: unknown): FindingBusinessContext | undefined {
  if (typeof value === "string") { try { value = JSON.parse(value); } catch { return undefined; } }
  const parsed = findingBusinessContextSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}
const weights: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
/** Compare work priority without changing technical severity or its tie breakers. */
export function compareFindingsByBusinessContext(a: Parameters<typeof compareFindingsBySeverity>[0] & { businessContext?: unknown }, b: Parameters<typeof compareFindingsBySeverity>[0] & { businessContext?: unknown }): number {
  const left = parseFindingBusinessContext(a.businessContext), right = parseFindingBusinessContext(b.businessContext);
  const score = (severity: string | undefined, context: FindingBusinessContext | undefined) => (weights[severity?.toLowerCase() ?? ""] ?? -10) + (context?.shift ?? 0);
  return (left || right ? score(b.severity, right) - score(a.severity, left) : 0) || compareFindingsBySeverity(a, b);
}
export function businessContextLabel(value: unknown): string | undefined {
  const context = parseFindingBusinessContext(value);
  return context ? `Operator business context (unverified declaration; technical severity unchanged): ${context.rationale}` : undefined;
}
