import { str } from "../lib/validate";

export interface ComponentInput {
  name: string;
  lead: string;
}

export function parseComponentInput(body: unknown): ComponentInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    lead: str(input.lead, 200),
  };
}
