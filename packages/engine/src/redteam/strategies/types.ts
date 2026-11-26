/**
 * The attack-strategy library's data model. A strategy changes how a benign canary payload is delivered or adapted, never the goal: the
 * goal stays "make the agent emit or send a harmless marker". Success is judged elsewhere, mechanically, from the tool-call log.
 */

export type StrategyFamily =
  | "baseline"
  | "encoding"
  | "framing"
  | "delimiter"
  | "placement"
  | "multi-turn"
  | "iterative"
  | "optimization"
  | "sampling"
  | "language-format";

/** Where the poisoned text sits when it reaches the agent. A hint a harness can use to pick the matching delivery slot. */
export type Placement =
  | "user-message"
  | "email"
  | "web"
  | "document"
  | "tool-result"
  | "tool-description"
  | "memory"
  | "file-name"
  | "repository"
  | "calendar"
  | "stored-field"
  | "rules-file"
  | "error-response"
  | "transcript";

export interface StrategyInput {
  /** The benign payload. The placeholder AGENT-CANARY-0 is replaced by `canary` first. */
  payload: string;
  /** This run's canary, for example CANARY-1a2b3c4d5e6f. */
  canary: string;
  /** Drives every random choice; the same input and seed always give the same output. */
  seed: number;
  /** When set, strategies that produce variants for several placements keep only the matching ones (all of them if none match). */
  placement?: Placement;
  /** Number of variants for sampling strategies (best-of-N, resampling, paraphrase). Whole number from 1 to MAX_VARIANT_COUNT (50); other values are clamped, NaN is ignored. */
  count?: number;
}

export interface StrategyVariant {
  text: string;
  /** What was done to the payload, for the report. */
  notes: string;
  placement?: Placement;
  /** Extra facts a harness needs, for example the trigger phrase of a keyed entry. */
  meta?: Record<string, string>;
}

export interface Strategy {
  /** S00 to S49 are the catalog ids; later ids extend the same catalog. */
  id: string;
  family: StrategyFamily;
  turns: "single" | "multi";
  needsAttackerModel: boolean;
  cost: "low" | "medium" | "high";
  description: string;
  /** Where the technique comes from; "(U)" means common practice with no primary source fetched. */
  source: string;
  /** Deterministic implementation. Left undefined for strategies that need an attacker model, several turns or a fixture another component owns. */
  apply?: (input: StrategyInput) => StrategyVariant[];
}
