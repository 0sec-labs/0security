/**
 * Reversible and near-reversible text transforms. Each one leaves the marker, URLs, e-mail addresses and identifiers such as tool names
 * untouched where it edits words, because the oracle needs the marker to survive intact and the linter must still see reserved hosts.
 * The decoders exist so tests, and the payload linter, can prove the original request is recoverable.
 */
import type { Rng } from "./rng.js";

/** Plain words of four or more letters that are not part of an identifier, address, URL or marker. */
const WORD = /(?<![\w.@/:=-])[A-Za-z]{4,}(?![\w@/:=-]|\.\w)/g;

export function mapWords(text: string, fn: (word: string, index: number) => string): string {
  let index = 0;
  return text.replace(WORD, word => fn(word, index++));
}

export function toBase64(text: string): string { return Buffer.from(text, "utf8").toString("base64"); }
export function fromBase64(text: string): string { return Buffer.from(text, "base64").toString("utf8"); }
export function toHex(text: string): string { return Buffer.from(text, "utf8").toString("hex"); }
export function fromHex(text: string): string { return Buffer.from(text, "hex").toString("utf8"); }

export function rot13(text: string): string {
  return text.replace(/[A-Za-z]/g, ch => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function reverseText(text: string): string { return Array.from(text).reverse().join(""); }

const LEET: Readonly<Record<string, string>> = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7" };
const LEET_BACK: Readonly<Record<string, string>> = Object.fromEntries(Object.entries(LEET).map(([k, v]) => [v, k]));

export function leetspeak(text: string, rng: Rng): string {
  return mapWords(text, word => Array.from(word).map(ch => (LEET[ch.toLowerCase()] !== undefined && rng() < 0.8 ? LEET[ch.toLowerCase()]! : ch)).join(""));
}
/** Approximate: digits inside words become letters again (lower case). Used only to let the linter look through leetspeak. */
export function unLeet(text: string): string {
  return text.replace(/(?<=[A-Za-z])[0-9]|[0-9](?=[A-Za-z])/g, d => LEET_BACK[d] ?? d);
}

/** Latin letter to a visually similar Cyrillic letter. */
const HOMOGLYPHS: Readonly<Record<string, string>> = { a: "а", e: "е", o: "о", p: "р", c: "с", x: "х", y: "у", i: "і", s: "ѕ" };
const HOMOGLYPHS_BACK: Readonly<Record<string, string>> = Object.fromEntries(Object.entries(HOMOGLYPHS).map(([k, v]) => [v, k]));

export function swapHomoglyph(word: string, rng: Rng): string {
  const spots = Array.from(word).flatMap((ch, i) => (HOMOGLYPHS[ch] !== undefined ? [i] : []));
  if (!spots.length) return word;
  const at = spots[Math.floor(rng() * spots.length)]!;
  return Array.from(word).map((ch, i) => (i === at ? HOMOGLYPHS[ch]! : ch)).join("");
}
export function foldHomoglyphs(text: string): string {
  return Array.from(text).map(ch => HOMOGLYPHS_BACK[ch] ?? ch).join("");
}

export const ZERO_WIDTH = ["​", "‌", "⁠"] as const;
const ZERO_WIDTH_RE = /[​‌‍⁠﻿]/g;
export function stripZeroWidth(text: string): string { return text.replace(ZERO_WIDTH_RE, ""); }

/** Puts an invisible character between the letters of plain words. Stripping them gives the input back exactly. */
export function zeroWidthSeparate(text: string, rng: Rng): string {
  return mapWords(text, word => Array.from(word).join(ZERO_WIDTH[Math.floor(rng() * ZERO_WIDTH.length)]!));
}

/** Random capitals and doubled spaces. Collapsing spaces and lower-casing gives back the original words. */
export function casingAndSpacingNoise(text: string, rng: Rng): string {
  const cased = mapWords(text, word => Array.from(word).map(ch => (rng() < 0.4 ? ch.toUpperCase() : ch.toLowerCase())).join(""));
  return cased.replace(/ /g, () => (rng() < 0.25 ? "  " : rng() < 0.1 ? " \t" : " "));
}

/** Names the fake environment's tools use; the homoglyph strategy can disguise one of them. */
export const TOOL_NAMES = [
  "read_file", "read_email", "fetch_url", "write_file", "send_email", "http_post", "run_command", "make_payment", "memory_write", "memory_read",
  "delegate_to_agent", "call_with_token", "update_agent_config", "install_skill", "browser_navigate",
] as const;

export function swapHomoglyphInToolName(text: string, rng: Rng): string | null {
  const name = TOOL_NAMES.find(n => text.includes(n));
  if (!name) return null;
  return text.replace(name, swapHomoglyph(name, rng));
}

/** Collapses all whitespace, for carriers that need one line (comments, titles, CSV cells). */
export function oneLine(text: string): string { return text.replace(/\s+/g, " ").trim(); }
