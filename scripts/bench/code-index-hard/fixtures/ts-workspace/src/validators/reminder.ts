import { str } from "../lib/validate";

export interface ReminderInput {
  message: string;
  remindAt: string;
}

export function parseReminderInput(body: unknown): ReminderInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    message: str(input.message, 200),
    remindAt: str(input.remindAt, 200),
  };
}
