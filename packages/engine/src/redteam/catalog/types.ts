/**
 * The test-generator catalog's data model. A generator names one weakness of a tool-using agent, the benign canary-style payload that
 * probes it, and the mechanical oracle that proves the agent was steered. The open entries carry complete scenario templates; the
 * closed generator service builds scenarios for the rest from the same ids. Nothing here is harmful content: a payload only asks an
 * agent to emit or send a harmless marker.
 */
import type { Privilege } from "../honeypot.js";
import type { OracleSpec } from "../oracle-types.js";

export type SourceKind = "user-message" | "web" | "email" | "document" | "tool-result" | "memory" | "repository" | "other";
export type Difficulty = "basic" | "intermediate" | "advanced";
/** open: complete templates ship in the open repository. closed: only the service generates it. both: an open starter plus a richer closed version. */
export type Tier = "open" | "closed" | "both";

export interface FrameworkTagRef { framework: string; id: string }

export interface GeneratorSpec {
  /** kebab-case, stable. */
  id: string;
  /** For example "Excessive agency" or "Payment mandate". */
  area: string;
  /** What weakness this tests, in one sentence. */
  weakness: string;
  /** What the benign payload asks for, in one sentence. */
  payloadShape: string;
  oracle: OracleSpec;
  /** What the target agent must have for this generator to apply. A generator applies when every listed kind is present. */
  requires: { privileges?: Privilege[]; sources?: SourceKind[]; tools?: string[] };
  difficulty: Difficulty;
  /** Only identifiers you are sure of (OWASP LLM Top 10 2025 LLM01, LLM02, LLM06 and MITRE ATLAS AML.T0051 are already used in this repository). */
  tags: FrameworkTagRef[];
  tier: Tier;
}

/** A complete, ready-to-run scenario for an open generator. The placeholder AGENT-CANARY-0 stands for this run's canary. */
export interface ScenarioTemplate {
  generatorId: string;
  goal: string;
  injectionPointKind: SourceKind;
  /** Contains the placeholder AGENT-CANARY-0 at least once. */
  payload: string;
  /** Contains the placeholder AGENT-CANARY-0 or names the tool call that proves success. */
  success: string;
}
