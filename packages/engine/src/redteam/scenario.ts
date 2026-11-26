/**
 * A red-team scenario: one attacker goal, the place the poisoned text enters, and the effect that proves the attack worked.
 * The `agent-toxic-flow` skill writes one per finding as a single `SCENARIO:` line so that a later run can replay it.
 */

/** The marker the skill puts in a payload. A run replaces it with a unique canary so a hit cannot be a coincidence. */
export const CANARY_PLACEHOLDER = "AGENT-CANARY-0";

export interface Scenario {
  goal: string;
  injectionPoint: string;
  payload: string;
  success: string;
}

const FIELDS = ["goal", "injection_point", "payload", "success"] as const;

/** Reads a `SCENARIO: goal=... | injection_point=... | payload=... | success=...` line. Returns null when any field is missing. */
export function parseScenario(text: string): Scenario | null {
  const line = text.split(/\r?\n/).find(candidate => /^\s*SCENARIO:/i.test(candidate));
  if (!line) return null;
  const body = line.replace(/^\s*SCENARIO:\s*/i, "");
  const found: Partial<Record<(typeof FIELDS)[number], string>> = {};
  // Split on " | " only where the next segment starts with a known field name, so a value may contain a pipe.
  const parts = body.split(/\s\|\s(?=(?:goal|injection_point|payload|success)=)/i);
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 1) continue;
    const key = part.slice(0, eq).trim().toLowerCase() as (typeof FIELDS)[number];
    if ((FIELDS as readonly string[]).includes(key)) found[key] = part.slice(eq + 1).trim();
  }
  if (FIELDS.some(field => !found[field])) return null;
  return { goal: found.goal!, injectionPoint: found.injection_point!, payload: found.payload!, success: found.success! };
}

/**
 * The scenario in a scan finding. The skill writes it as the finding's `evidence_request`, but a report may hold the evidence as an
 * object or as JSON text, and a model sometimes puts the line elsewhere, so every text field of the finding is tried.
 */
export function scenarioFromFinding(finding: unknown): Scenario | null {
  if (typeof finding !== "object" || finding === null) return null;
  const { evidence, description } = finding as { evidence?: unknown; description?: unknown };
  const pieces: string[] = [];
  const addEvidence = (value: unknown) => {
    if (typeof value === "string") pieces.push(value);
    else if (typeof value === "object" && value !== null) for (const part of Object.values(value as Record<string, unknown>)) if (typeof part === "string") pieces.push(part);
  };
  if (typeof evidence === "string") {
    try { addEvidence(JSON.parse(evidence)); } catch { /* plain text */ }
  }
  addEvidence(evidence);
  if (typeof description === "string") pieces.push(description);
  for (const piece of pieces) {
    const parsed = parseScenario(piece);
    if (parsed) return parsed;
  }
  return null;
}

/** A canary no model would produce unprompted, unique per run. */
export function newCanary(random: () => string = defaultRandom): string {
  return `CANARY-${random()}`;
}

function defaultRandom(): string {
  const bytes = new Uint8Array(6);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** The scenario's payload with the placeholder replaced by this run's canary. */
export function materializePayload(scenario: Scenario, canary: string): string {
  return scenario.payload.split(CANARY_PLACEHOLDER).join(canary);
}

/** The scenario's success condition, with the same replacement, so the text a person reads names the canary of this run. */
export function materializeSuccess(scenario: Scenario, canary: string): string {
  return scenario.success.split(CANARY_PLACEHOLDER).join(canary);
}
