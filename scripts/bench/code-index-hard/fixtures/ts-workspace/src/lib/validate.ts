import { badRequest } from "./http";

export function str(value: unknown, max: number): string {
  if (typeof value !== "string" || !value.trim()) throw badRequest("text value required");
  return value.trim().slice(0, max);
}

export function num(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw badRequest("number required");
  return parsed;
}

export function bool(value: unknown): boolean {
  return value === true || value === "true";
}
