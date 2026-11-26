const MARKUP_CHARS = /[<>&"']/g;

const ENTITIES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Display-safe short text: markup characters are dropped and the length is capped. */
export function cleanName(value: string): string {
  return value.replace(MARKUP_CHARS, "").trim().slice(0, 120);
}

export function escapeHtml(value: string): string {
  return value.replace(MARKUP_CHARS, (ch) => ENTITIES[ch]);
}

/** A single path segment: separators and leading dots cannot survive. */
export function safeSegment(value: string): string {
  const flat = value.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "_");
  return flat.slice(0, 120) || "_";
}
