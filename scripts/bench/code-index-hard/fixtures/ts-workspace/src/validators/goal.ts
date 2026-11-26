import { num, str } from "../lib/validate";

export interface GoalInput {
  name: string;
  target: number;
}

export function parseGoalInput(body: unknown): GoalInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    target: num(input.target),
  };
}
