/**
 * The structured root cause of a finding, read from what a thread wrote. A record is kept only when every part is
 * there: a half-filled one would seed a variant hunt with a guess.
 */
import { rootCauseSchema } from "./finding-schemas.js";
import type { RootCause } from "./types.js";

const text = (value: unknown): string | undefined => typeof value === "string" ? value.replace(/\s+/g, " ").trim().slice(0, 500) || undefined : undefined;
const pick = (object: Record<string, unknown>, ...keys: string[]): unknown => { for (const key of keys) if (object[key] !== undefined) return object[key]; return undefined; };

/** A root cause from a model's object (camelCase or snake_case keys), or undefined when any part is missing. */
export function parseRootCause(value: unknown): RootCause | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const pattern = pick(raw, "unsafe_pattern", "unsafePattern");
  const patternObject = pattern && typeof pattern === "object" && !Array.isArray(pattern) ? pattern as Record<string, unknown> : undefined;
  const parsed = rootCauseSchema.safeParse({
    bugClass: text(pick(raw, "bug_class", "bugClass")),
    unsafePattern: { sink: text(patternObject?.sink), source: text(patternObject?.source) },
    missingGuard: text(pick(raw, "missing_guard", "missingGuard")),
    designOrigin: text(pick(raw, "design_origin", "designOrigin")),
  });
  return parsed.success ? parsed.data : undefined;
}

/** The record stored in a `rootCause` column, or undefined for anything that is not a complete one. */
export function parseStoredRootCause(value: unknown): RootCause | undefined {
  if (typeof value === "string") { try { return parseRootCause(JSON.parse(value)); } catch { return undefined; } }
  return parseRootCause(value);
}

/** One line for a list or a prompt: "SQL injection: query() fed by req.query; missing parameter binding". */
export function rootCauseSummary(rootCause: RootCause): string {
  return `${rootCause.bugClass}: ${rootCause.unsafePattern.sink} fed by ${rootCause.unsafePattern.source}; missing ${rootCause.missingGuard}`;
}
