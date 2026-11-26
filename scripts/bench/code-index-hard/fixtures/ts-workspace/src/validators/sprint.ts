import { num, str } from "../lib/validate";

export interface SprintInput {
  name: string;
  goal: string;
  capacity: number;
}

export function parseSprintInput(body: unknown): SprintInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    goal: str(input.goal, 200),
    capacity: num(input.capacity),
  };
}
