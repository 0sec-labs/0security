/** Small builders shared by the entry files. They keep each entry to the facts that make it different. */
import type { ArgCondition, OracleSpec } from "../../oracle-types.js";
import type { Difficulty, GeneratorSpec, ScenarioTemplate, SourceKind, Tier } from "../types.js";

/** The marker placeholder used in oracles and templates. */
export const M = "AGENT-CANARY-0";
const OWASP = "OWASP LLM Top 10 (2025)";

export interface CatalogEntry { spec: GeneratorSpec; template?: ScenarioTemplate }

type Base = Omit<GeneratorSpec, "tags" | "difficulty" | "tier"> & { difficulty: Difficulty; tier: Tier; /** OWASP LLM Top 10 2025 ids such as LLM01. */ tags?: string[] };

/** A template body: where the payload sits, what the goal is, the benign payload and how success reads. */
export type Body = [kind: SourceKind, goal: string, payload: string, success: string];

export function entry(base: Base, body?: Body): CatalogEntry {
  const { tags = [], ...rest } = base;
  const spec: GeneratorSpec = { ...rest, tags: tags.map(id => ({ framework: OWASP, id })) };
  if (!body) return { spec };
  const [injectionPointKind, goal, payload, success] = body;
  return { spec, template: { generatorId: spec.id, goal, injectionPointKind, payload, success } };
}

export const sink = (privileges?: GeneratorSpec["requires"]["privileges"], tools?: string[]): OracleSpec => ({ kind: "marker-in-sink", ...(privileges ? { privileges } : {}), ...(tools ? { tools } : {}) });
export const called = (tool: string, where?: ArgCondition): OracleSpec => ({ kind: "tool-called", tool, ...(where ? { where } : {}) });
export const notCalled = (tool: string): OracleSpec => ({ kind: "tool-not-called", tool });
export const seq = (...steps: OracleSpec[]): OracleSpec => ({ kind: "sequence", steps });
export const anyOf = (...of: OracleSpec[]): OracleSpec => ({ kind: "any", of });
export const allOf = (...of: OracleSpec[]): OracleSpec => ({ kind: "all", of });
export const has = (arg: string): ArgCondition => ({ arg, contains: M });
/** The same step n times in order: used to detect a repeated or runaway call. */
export const times = (n: number, step: OracleSpec): OracleSpec => seq(...Array.from({ length: n }, () => step));
