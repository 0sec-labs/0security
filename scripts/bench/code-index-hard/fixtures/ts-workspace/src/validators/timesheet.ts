import { num, str } from "../lib/validate";

export interface TimesheetInput {
  weekOf: string;
  hours: number;
}

export function parseTimesheetInput(body: unknown): TimesheetInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    weekOf: str(input.weekOf, 200),
    hours: num(input.hours),
  };
}
