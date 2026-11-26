/**
 * The contract of the `next-move` task: one turn of a multi-turn attacker, produced by a server so that the attack tactics stay
 * server-side. Types only; the open attacker loop (attacker/) and the closed service both implement against them.
 *
 * What may be sent: the objective, and the conversation and recorded tool calls from the FAKE environment, each clipped. The agent's
 * replies can contain text the agent under test chose to say, so this task is opt-in and never the default attacker; the default
 * attacker runs on the customer's own model and sends nothing anywhere.
 */
export interface NextMoveRequest {
  v: 1;
  task: "next-move";
  objective: { goal: string; generatorId?: string; strategyId?: string };
  /** 1-based number of the turn being asked for. */
  turn: number;
  maxTurns: number;
  /** Earlier turns, oldest first. Each text at most 2000 characters; at most 40 entries. */
  history: { role: "attacker" | "agent"; text: string }[];
  /** Calls the agent made so far in the fake environment; argument values clipped to 200 characters. */
  calls: { tool: string; privilege: string; args: Record<string, string> }[];
}

export interface NextMoveResponse {
  v: 1;
  task: "next-move";
  /** The next message the attacker sends to the agent. At most 4000 characters, no control characters except newline and tab. */
  message: string;
  /** Why this move, for the report. At most 500 characters. */
  rationale?: string;
  /** True when the server thinks further turns will not help. */
  done?: boolean;
}
