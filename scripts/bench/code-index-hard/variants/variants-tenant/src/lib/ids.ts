import { randomBytes } from "node:crypto";

export function newId(prefix: string): string {
  return prefix + "_" + randomBytes(5).toString("hex");
}

export function isoNow(): string {
  return new Date().toISOString();
}
