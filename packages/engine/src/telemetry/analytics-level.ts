/**
 * Analytics consent level.
 *
 * Two environment variables force "off": `DO_NOT_TRACK` (the cross-tool
 * standard) and `ZERO_ENTERPRISE` (the no-egress mode). They win unconditionally.
 * The only other off-switch is the saved `analyticsLevel: off` setting, which
 * the CLI settings store bridges into `ZERO_ANALYTICS_LEVEL`. `ZERO_OFFLINE`
 * and `ZERO_NO_TELEMETRY` do not affect analytics.
 *
 * DEFAULT: usage analytics are ON for a fresh install (anonymous counters and
 * lifecycle events only; see analytics-pipeline.ts for where they may go).
 */

/** Consent levels, in increasing order of what may be transmitted. */
export type AnalyticsLevel = "off" | "usage";

const LEVEL_ORDER: Record<AnalyticsLevel, number> = {
  off: 0,
  usage: 1,
};

/** The env vars that hard-disable analytics, regardless of `ZERO_ANALYTICS_LEVEL`. */
export const ANALYTICS_OPT_OUT_ENV = ["DO_NOT_TRACK", "ZERO_ENTERPRISE"] as const;

/** The env var that selects the tier when nothing opts out. */
export const ANALYTICS_LEVEL_ENV = "ZERO_ANALYTICS_LEVEL";

/** True when `current` is at least `required` (off < usage). */
export function levelAtLeast(current: AnalyticsLevel, required: AnalyticsLevel): boolean {
  return LEVEL_ORDER[current] >= LEVEL_ORDER[required];
}

/**
 * True when `value` reads as "on". Mirrors the CLI's opt-out semantics:
 * anything set and not explicitly falsy ("", "0", "false", "no") counts as an
 * opt-out. Failure directions are asymmetric here — a missed opt-out would let
 * client data cross a boundary someone explicitly tried to close — so this is
 * deliberately permissive.
 */
export function isOptOutSet(value: string | undefined): boolean {
  if (value === undefined) return false;
  const normalized = value.trim().toLowerCase();
  if (normalized === "") return false;
  return normalized !== "0" && normalized !== "false" && normalized !== "no";
}

function isAnalyticsLevel(value: string): value is AnalyticsLevel {
  return value === "off" || value === "usage";
}

/** Shared hard opt-out gate for analytics and separately permissioned contributions. */
export function analyticsOptedOut(env: NodeJS.ProcessEnv = process.env): boolean {
  return ANALYTICS_OPT_OUT_ENV.some(name => isOptOutSet(env[name]));
}

/**
 * Resolve the effective analytics level. `DO_NOT_TRACK` or `ZERO_ENTERPRISE` forces "off"; when
 * `ZERO_ANALYTICS_LEVEL` is unset the default is usage metrics only (automatic,
 * anonymous counters; an explicit saved `off` is applied by the CLI settings
 * store before this env is bridged). An unknown/invalid
 * value still fails closed to "off".
 */
export function resolveAnalyticsLevel(env: NodeJS.ProcessEnv = process.env): AnalyticsLevel {
  if (analyticsOptedOut(env)) return "off";
  const raw = env[ANALYTICS_LEVEL_ENV];
  if (typeof raw !== "string") return "usage";
  const normalized = raw.trim().toLowerCase();
  return isAnalyticsLevel(normalized) ? normalized : "off";
}
