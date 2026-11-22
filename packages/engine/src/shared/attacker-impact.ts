import { isHeuristicImpactAssessment } from "./finding-priority.js";
import type { ImpactAssessment } from "./types.js";

/** What a person reads about a finding's impact: who can do it, what they can do, what they get. */
export interface AttackerImpact {
  /** What an attacker can do, in the model's words (the blast radius). */
  can: string;
  /** Who can do it: from the reachability tier. Empty when that was not established. */
  who: string;
  /** What they get: from how weaponizable the bug is. */
  gets: string;
  /** Set when the finding is not an attack at all (a policy violation): the heading to use instead of "What an attacker can do". */
  label?: string;
}

export const ATTACKER_LABEL = "What an attacker can do";
/** A policy violation has no attacker: what it records is what the breach of the rule exposes. */
export const POLICY_IMPACT_LABEL = "What the violation exposes";

const WHO: Record<ImpactAssessment["reachability_tier"], string> = {
  "remote-unauth": "anyone who can reach it over the network, without logging in",
  "remote-auth": "any logged-in user",
  "proximity-rf": "someone within radio range",
  "local-unpriv": "an unprivileged local user",
  "local-priv": "a privileged local user",
  "needs-hardware": "someone with physical access",
  "needs-host-migration": "someone who first controls another part of the system",
  unknown: "",
};
const GETS: Record<ImpactAssessment["weaponizability"], string> = {
  rce: "run their own code",
  "lpe-to-root": "take full control of the host",
  "integrity-tampering": "change data they should not be able to change",
  "info-leak": "read data they should not be able to read",
  "dos-crash": "crash or stall the service",
  unknown: "an outcome that is not established",
};

/**
 * The attacker's view of a finding, only when someone actually assessed it. A severity-and-category guess is not an
 * assessment, so it is never shown as one.
 */
export function describeAttackerImpact(finding: { impactAssessment?: unknown; category?: string }): AttackerImpact | undefined {
  const value = finding.impactAssessment as ImpactAssessment | null | undefined;
  if (!value || typeof value !== "object" || typeof value.blast_radius !== "string" || !value.blast_radius.trim()) return undefined;
  if (isHeuristicImpactAssessment(value)) return undefined;
  // A broken policy is not an attack: no "who can do it" and no "what they get", only what the violation exposes.
  if (finding.category === "policy-violation") return { can: value.blast_radius.trim(), who: "", gets: "", label: POLICY_IMPACT_LABEL };
  return { can: value.blast_radius.trim(), who: WHO[value.reachability_tier] ?? WHO.unknown, gets: GETS[value.weaponizability] ?? GETS.unknown };
}

/** One line for a report or a code scanning alert. */
export function attackerImpactSentence(finding: { impactAssessment?: unknown; category?: string }): string | undefined {
  const impact = describeAttackerImpact(finding);
  if (impact?.label) return impact.can;
  return impact ? `${impact.can}${impact.who ? ` Who: ${impact.who}.` : ""} They can: ${impact.gets}.` : undefined;
}
