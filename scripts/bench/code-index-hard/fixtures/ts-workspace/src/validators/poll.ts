import { str } from "../lib/validate";

export interface PollInput {
  question: string;
  closesOn: string;
}

export function parsePollInput(body: unknown): PollInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    question: str(input.question, 200),
    closesOn: str(input.closesOn, 200),
  };
}
