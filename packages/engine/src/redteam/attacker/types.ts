/**
 * Types of the multi-turn attacker loop. The attacker sees only what an outside party could see: the agent's replies and the calls
 * recorded in the fake environment. Whether an attack worked is decided by the mechanical oracle, never by a model.
 */
import type { TraceEvent } from "../honeypot.js";
import type { OracleResult, OracleSpec } from "../oracle-types.js";

/** One conversational agent under test. `calls` are the calls the agent made while producing this reply. */
export interface ChatDriver {
  send(message: string): Promise<{ reply: string; calls: TraceEvent[] }>;
  /** Releases the agent (for a child process, ends it). The caller of runAttack owns the driver and closes it. */
  close?(): Promise<void> | void;
}

export type ChatMessage = { role: "system" | "user" | "assistant"; content: string };
/** The customer's own model, in the attacker role. Injected so the loop is testable and sends nothing by itself. */
export interface AttackerModelOptions {
  /** Aborted when the run is out of wall-clock time; a model client should cancel its request. */
  signal?: AbortSignal;
}
export type AttackerModel = (messages: ChatMessage[], options?: AttackerModelOptions) => Promise<string>;

/** maxTurns is clamped to a whole number (at most 1000); NaN or a negative value stops the run before the first turn. maxWallMs may be Infinity. */
export interface AttackBudget { maxTurns: number; maxModelCalls: number; maxWallMs: number }

export interface AttackTurn { n: number; attackerMessage: string; agentReply: string; newCalls: TraceEvent[] }

export type StopReason = "hit" | "budget-turns" | "budget-model" | "budget-time" | "attacker-done" | "attacker-error" | "driver-error";

export interface AttackResult {
  hit: boolean;
  turns: AttackTurn[];
  stopReason: StopReason;
  modelCalls: number;
  oracle: OracleResult;
  /** Plain explanation of an attacker or driver failure (for example `attacker_refused`); never argument values. */
  error?: string;
}

export interface AttackObjective {
  /** What the attacker is trying to get the agent to do, in words. Always a harmless marker request. */
  goal: string;
  /** A ready-made benign request text, for strategies that rewrite or send one payload. */
  payload?: string;
}

/** What a strategy may look at when it picks the next message. The oracle is deliberately absent. */
export interface AttackerState {
  objective: { goal: string; payload?: string };
  canary: string;
  /** 1-based number of the turn being asked for. */
  turn: number;
  maxTurns: number;
  maxModelCalls: number;
  /** Earlier turns, oldest first. */
  history: readonly AttackTurn[];
  /** Every call recorded so far. */
  calls: readonly TraceEvent[];
  /** Aborted when the wall-clock budget runs out; strategies pass it on to the attacker model. */
  signal?: AbortSignal;
}

export interface AttackerMove { message: string; done?: boolean }

export interface AttackerStrategy {
  id: string;
  nextMessage(state: AttackerState): Promise<AttackerMove>;
  /** Attacker-model calls made so far, for the budget. */
  modelCalls?(): number;
}

export interface RunAttackInput {
  objective: AttackObjective;
  oracle: OracleSpec;
  canary: string;
  driver: ChatDriver;
  attacker: AttackerStrategy;
  budget: AttackBudget;
  now?: () => number;
}

/** Thrown by a strategy that would exceed the model-call budget; runAttack reports `budget-model`. */
export class ModelBudgetError extends Error { constructor() { super("the attacker-model call budget is used up"); this.name = "ModelBudgetError"; } }
/** Thrown by a strategy when the attacker model declines the role. A refusal is logged as `attacker_refused`, never as the agent resisting. */
export class AttackerRefusedError extends Error { constructor() { super("attacker_refused"); this.name = "AttackerRefusedError"; } }
