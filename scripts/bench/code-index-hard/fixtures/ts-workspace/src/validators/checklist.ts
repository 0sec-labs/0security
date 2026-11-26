import { str } from "../lib/validate";

export interface ChecklistInput {
  title: string;
  items: string;
}

export function parseChecklistInput(body: unknown): ChecklistInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    title: str(input.title, 200),
    items: str(input.items, 200),
  };
}
