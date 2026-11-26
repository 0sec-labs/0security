/**
 * The open catalog as brain scenarios, so the client fallback can offer more than the nine-entry starter pack. The payload keeps the
 * literal placeholder AGENT-CANARY-0, which is what the brain contract requires; the runner swaps in the run's canary when it
 * materializes the scenario. The canary passed here only seeds which generators are sampled, so one run is reproducible and
 * different runs see different samples.
 */
import type { BrainManifest, BrainScenario } from "../brain/schema.js";
import { TEMPLATES_BY_ID } from "./entries/index.js";
import { selectGenerators } from "./select.js";

export function catalogScenarios(manifest: BrainManifest, canary: string, count: number): BrainScenario[] {
  return selectGenerators(manifest, { count, tiers: ["open", "both"], seed: canary }).flatMap(spec => {
    const template = TEMPLATES_BY_ID.get(spec.id);
    if (!template) return [];
    return [{ id: spec.id, goal: template.goal, injection_point_kind: template.injectionPointKind, payload: template.payload, success: template.success, tags: spec.tags.map(tag => ({ ...tag })), difficulty: spec.difficulty }];
  });
}
