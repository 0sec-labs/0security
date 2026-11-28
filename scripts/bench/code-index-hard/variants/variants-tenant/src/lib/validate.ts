import { badRequest } from "./errors";

/** Copy only the listed keys from a request body. */
export function pick<K extends string>(body: unknown, keys: readonly K[]): Partial<Record<K, any>> {
  const source = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const out: Partial<Record<K, any>> = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
  }
  return out;
}

export function requireFields(data: Record<string, unknown>, keys: readonly string[]): void {
  for (const key of keys) {
    const value = data[key];
    if (value === undefined || value === null || value === "") throw badRequest("missing field " + key);
  }
}
