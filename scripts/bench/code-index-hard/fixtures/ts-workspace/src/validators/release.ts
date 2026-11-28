import { str } from "../lib/validate";

export interface ReleaseInput {
  version: string;
  notes: string;
}

export function parseReleaseInput(body: unknown): ReleaseInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    version: str(input.version, 200),
    notes: str(input.notes, 200),
  };
}
