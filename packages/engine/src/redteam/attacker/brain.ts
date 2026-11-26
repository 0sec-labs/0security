/**
 * The brain attacker: asks a server for each next move (tactics stay server-side) and falls back to a local strategy, saying so, when
 * the server may not or cannot be used. Opt-in only: the clipped transcript of the fake environment leaves the machine.
 */
import { requestNextMove, buildNextMoveRequest, type NextMoveOptions } from "../brain/next-move.js";
import type { BrainDeps } from "../brain/client.js";
import { CANARY_PLACEHOLDER } from "../scenario.js";
import { guardMessage } from "./guard.js";
import { crescendo } from "./scripted.js";
import type { AttackerState, AttackerStrategy } from "./types.js";

export interface BrainAttackerOptions extends NextMoveOptions {
  deps: BrainDeps;
  /** Used when the brain is off, offline or failing. Default: crescendo. */
  fallback?: AttackerStrategy;
  generatorId?: string;
  strategyId?: string;
  /** Called with each note, for example the reason for a fallback, so the report can state it. */
  onNote?: (note: string) => void;
}

export function brainAttacker(options: BrainAttackerOptions): AttackerStrategy & { notes: string[] } {
  const fallback = options.fallback ?? crescendo();
  const notes: string[] = [];
  const note = (text: string) => { if (notes[notes.length - 1] !== text) { notes.push(text); options.onNote?.(text); } };
  return {
    id: "brain",
    notes,
    ...(fallback.modelCalls ? { modelCalls: () => fallback.modelCalls!() } : {}),
    async nextMessage(state: AttackerState) {
      const history = state.history.flatMap(t => [{ role: "attacker" as const, text: t.attackerMessage }, { role: "agent" as const, text: t.agentReply }]);
      const request = buildNextMoveRequest({
        objective: { goal: state.objective.goal, ...(options.generatorId ? { generatorId: options.generatorId } : {}), ...(options.strategyId ? { strategyId: options.strategyId } : {}) },
        turn: state.turn, maxTurns: state.maxTurns, history, calls: state.calls.map(c => ({ tool: c.tool, privilege: c.privilege, args: c.args })),
      });
      const result = await requestNextMove(request, options, options.deps);
      note(result.note);
      if (result.source === "remote") {
        const { message, done } = result.response;
        const guard = guardMessage(message.split(CANARY_PLACEHOLDER).join(state.canary), { canary: state.canary });
        if (guard.ok) return { message, ...(done ? { done: true } : {}) };
        note(`The brain's move failed the local guard (${guard.reason}); the local strategy was used instead.`);
      }
      return fallback.nextMessage(state);
    },
  };
}
