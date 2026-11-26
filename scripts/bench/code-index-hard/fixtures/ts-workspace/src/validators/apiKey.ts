import { str } from "../lib/validate";

export interface ApiKeyInput {
  label: string;
  scope: string;
}

export function parseApiKeyInput(body: unknown): ApiKeyInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    label: str(input.label, 200),
    scope: str(input.scope, 200),
  };
}
