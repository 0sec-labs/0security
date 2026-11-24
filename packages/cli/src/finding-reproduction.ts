import { parseFindingReproduction, proposeProof, reproductionFor, reproductionLabel, reproductionLine, proofLine, type FindingReproduction, type PocStep } from "@0/engine/shared";

/** What a finding row shows for proof: the stored record, or a proposed recipe derived from its steps. Never a guess at a result. */
export function rowReproduction(row: { reproduction?: unknown; pocSteps?: unknown }): FindingReproduction | undefined {
  let steps: unknown = row.pocSteps;
  if (typeof steps === "string") { try { steps = JSON.parse(steps); } catch { steps = undefined; } }
  const pocSteps = Array.isArray(steps) ? (steps as PocStep[]) : undefined;
  return reproductionFor({ ...(pocSteps ? { pocSteps } : {}) }, parseFindingReproduction(row.reproduction));
}

/** Short phrase for `findings list`. */
export function reproductionPhrase(row: { reproduction?: unknown; pocSteps?: unknown }): string | undefined {
  return reproductionLabel(rowReproduction(row));
}

/** The full line for `findings show`: the harness result when there is one, else the proposed recipe. */
export function reproductionDetail(row: { reproduction?: unknown; pocSteps?: unknown }): { label: string; line: string } | undefined {
  const rep = rowReproduction(row);
  if (!rep) return undefined;
  if (rep.result) return { label: "Proof", line: reproductionLine(rep.result) };
  return rep.proof ? { label: "Proof", line: proofLine(rep.proof)! } : undefined;
}

export { proposeProof };
