import { str } from "../lib/validate";

export interface MilestoneInput {
  title: string;
  dueOn: string;
}

export function parseMilestoneInput(body: unknown): MilestoneInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    title: str(input.title, 200),
    dueOn: str(input.dueOn, 200),
  };
}
