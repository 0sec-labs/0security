import { str } from "../lib/validate";

export interface NoteInput {
  title: string;
  body: string;
}

export function parseNoteInput(body: unknown): NoteInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    title: str(input.title, 200),
    body: str(input.body, 200),
  };
}
