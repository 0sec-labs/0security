import { str } from "../lib/validate";

export interface EpicInput {
  name: string;
  summary: string;
}

export function parseEpicInput(body: unknown): EpicInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    summary: str(input.summary, 200),
  };
}
