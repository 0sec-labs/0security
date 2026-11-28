import { str } from "../lib/validate";

export interface LabelInput {
  name: string;
  color: string;
}

export function parseLabelInput(body: unknown): LabelInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    color: str(input.color, 200),
  };
}
