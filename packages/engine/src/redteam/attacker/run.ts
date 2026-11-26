/**
 * The attacker loop. Each turn asks the strategy for a message, guards it, sends it to the agent, and checks the mechanical oracle
 * over every call recorded so far. It never throws on a driver or attacker failure: it stops and reports why.
 */
import { evaluateOracle } from "../oracle.js";
import type { TraceEvent } from "../honeypot.js";
import { CANARY_PLACEHOLDER } from "../scenario.js";
import { guardMessage } from "./guard.js";
import { AttackerRefusedError, ModelBudgetError, type AttackResult, type AttackTurn, type RunAttackInput, type StopReason } from "./types.js";

const fill = (text: string, canary: string): string => text.split(CANARY_PLACEHOLDER).join(canary);
const describe = (error: unknown): string => (error instanceof Error ? error.message : String(error)).slice(0, 300);

const MAX_TURNS_CAP = 1000;
const invalid = (n: unknown): boolean => typeof n !== "number" || Number.isNaN(n) || n < 0;
const whole = (n: number, cap: number): number => Math.min(cap, Math.floor(n));

type Raced<T> = { done: true; value: T } | { done: false };
/** Awaits `work` for at most `ms`; on timeout aborts `controller` and reports it. A late result or rejection is ignored. */
function within<T>(work: Promise<T>, ms: number, controller: AbortController): Promise<Raced<T>> {
  if (!Number.isFinite(ms)) return work.then(value => ({ done: true as const, value }));
  return new Promise<Raced<T>>((resolve, reject) => {
    const timer = setTimeout(() => { controller.abort(); resolve({ done: false }); }, Math.max(0, ms));
    work.then(value => { clearTimeout(timer); resolve({ done: true, value }); }, error => { clearTimeout(timer); reject(error); });
  });
}

export async function runAttack(input: RunAttackInput): Promise<AttackResult> {
  const { canary, driver, attacker, oracle } = input;
  const raw = input.budget;
  const now = input.now ?? Date.now;
  const started = now();
  const objective = { goal: fill(input.objective.goal, canary), ...(input.objective.payload !== undefined ? { payload: fill(input.objective.payload, canary) } : {}) };
  const turns: AttackTurn[] = [];
  const calls: TraceEvent[] = [];
  const modelCalls = () => attacker.modelCalls?.() ?? 0;
  const finish = (stopReason: StopReason, error?: string): AttackResult => {
    const result = evaluateOracle(calls, oracle, { canary });
    return { hit: result.hit, turns, stopReason, modelCalls: modelCalls(), oracle: result, ...(error !== undefined ? { error } : {}) };
  };

  if (invalid(raw.maxTurns)) return finish("budget-turns", "invalid budget: maxTurns must be a number of zero or more");
  if (invalid(raw.maxWallMs)) return finish("budget-time", "invalid budget: maxWallMs must be a number of zero or more");
  if (invalid(raw.maxModelCalls)) return finish("budget-model", "invalid budget: maxModelCalls must be a number of zero or more");
  const budget = { maxTurns: whole(raw.maxTurns, MAX_TURNS_CAP), maxWallMs: raw.maxWallMs, maxModelCalls: Math.floor(raw.maxModelCalls) };
  const remaining = () => budget.maxWallMs - (now() - started);

  for (let n = 1; ; n++) {
    if (n > budget.maxTurns) return finish("budget-turns");
    if (remaining() <= 0) return finish("budget-time");
    if (modelCalls() >= budget.maxModelCalls && attacker.modelCalls) return finish("budget-model");

    let move;
    const controller = new AbortController();
    try {
      const raced = await within(Promise.resolve().then(() => attacker.nextMessage({ objective, canary, turn: n, maxTurns: budget.maxTurns, maxModelCalls: budget.maxModelCalls, history: turns, calls, signal: controller.signal })), remaining(), controller);
      if (!raced.done) return finish("budget-time");
      move = raced.value;
    } catch (error) {
      if (error instanceof ModelBudgetError) return finish("budget-model");
      return finish("attacker-error", error instanceof AttackerRefusedError ? "attacker_refused" : describe(error));
    }
    const message = typeof move?.message === "string" ? fill(move.message, canary) : "";
    if (move?.done && message.trim() === "") return finish("attacker-done");
    const guard = guardMessage(message, { canary });
    if (!guard.ok) return finish("attacker-error", `guard rejected the message: ${guard.reason}`);

    let sent;
    try {
      const raced = await within(Promise.resolve().then(() => driver.send(message)), remaining(), new AbortController());
      if (!raced.done) return finish("budget-time");
      sent = raced.value;
    } catch (error) { return finish("driver-error", describe(error)); }
    const newCalls = Array.isArray(sent?.calls) ? sent.calls : [];
    calls.push(...newCalls);
    turns.push({ n, attackerMessage: message, agentReply: typeof sent?.reply === "string" ? sent.reply : "", newCalls });
    if (evaluateOracle(calls, oracle, { canary }).hit) return finish("hit");
    if (move.done) return finish("attacker-done");
  }
}
