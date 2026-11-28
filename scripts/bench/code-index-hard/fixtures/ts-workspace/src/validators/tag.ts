import { str } from "../lib/validate";

export interface TagInput {
  name: string;
}

export function parseTagInput(body: unknown): TagInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
  };
}
