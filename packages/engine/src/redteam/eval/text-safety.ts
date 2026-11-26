/** Shared text hygiene for anything that came from an agent or a run: control, invisible and bidirectional characters are removed before text is stored or shown. */
// eslint-disable-next-line no-control-regex
const CONTROL_G = /[\u0000-\u001F\u007F-\u009F]/g;
const INVISIBLE_G = /[\u00AD\u061C\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
/** Zero-width and bidirectional formatting characters (non-global, for testing). */
export const INVISIBLE = /[\u00AD\u061C\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;

/** Control characters (newlines and tabs included) become a space; invisible and bidirectional characters are dropped. */
export const cleanText = (value: string): string => value.replace(CONTROL_G, " ").replace(INVISIBLE_G, "");
/** Stringifies, cleans and clips. */
export const clipText = (value: unknown, max: number): string => cleanText(typeof value === "string" ? value : JSON.stringify(value) ?? "").slice(0, max);
