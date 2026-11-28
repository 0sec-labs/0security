import { str } from "../lib/validate";

export interface CustomFieldInput {
  name: string;
  kind: string;
}

export function parseCustomFieldInput(body: unknown): CustomFieldInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    kind: str(input.kind, 200),
  };
}
