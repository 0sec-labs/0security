/**
 * Analytics payload TYPES only: no logic, no I/O.
 *
 * The finite `platform` / `arch` / `runtime` value sets mirror the CLI's
 * diagnostic allowlists (packages/cli/src/state/feedback.ts): custom or unknown
 * values collapse to "unknown" so no free-form host string is ever transmitted.
 */

/** Finite OS platform labels; anything else collapses to "unknown". */
export type FinitePlatform =
  | "darwin"
  | "linux"
  | "win32"
  | "aix"
  | "freebsd"
  | "openbsd"
  | "sunos"
  | "unknown";

/** Finite CPU arch labels; anything else collapses to "unknown". */
export type FiniteArch =
  | "x64"
  | "arm64"
  | "arm"
  | "ia32"
  | "s390"
  | "mips"
  | "ppc64"
  | "unknown";

/** Finite JS runtime labels; anything else collapses to "unknown". */
export type FiniteRuntime = "node" | "bun" | "deno" | "unknown";

/** Usage level: aggregate counters only, no free text. */
export interface UsageRecord {
  kind: "usage";
  /** Feature name → invocation count. */
  featureCounts: Record<string, number>;
  /** Finding category → count. */
  findingCounts: Record<string, number>;
  /** Finite error category → count. */
  errorCategories: Record<string, number>;
  /** Number of agent turns in the run. */
  turnCount: number;
  /** Total run duration (ms). */
  durationMs: number;
  /** Optional model spend for the run (USD). */
  costUsd?: number;
}
