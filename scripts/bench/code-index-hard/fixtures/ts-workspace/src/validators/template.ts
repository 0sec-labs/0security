import { str } from "../lib/validate";

export interface TemplateInput {
  name: string;
  body: string;
}

export function parseTemplateInput(body: unknown): TemplateInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    body: str(input.body, 200),
  };
}
