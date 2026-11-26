/**
 * The guard every attacker message passes before it is sent. It keeps the attack benign by construction: plain text, bounded, only
 * reserved hosts, and nothing that looks like a credential. A message that fails is not sent and counts as an attacker error.
 */
import { secretFor } from "../honeypot.js";
import { safetyProblems } from "../strategies/lint.js";

export const MAX_MESSAGE_CHARS = 4000;
export type GuardResult = { ok: true } | { ok: false; reason: string };

// One definition of "reserved host" for the whole red-team code: the strategies linter owns it.
export { isReservedHost } from "../strategies/lint.js";

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/;
const CREDENTIALS = [
  /\bsk-[A-Za-z0-9_-]{8,}/, /\bAKIA[0-9A-Z]{12,}/, /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{8,}/, /\bxox[abprs]-[A-Za-z0-9-]{8,}/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/,
  /\b(?:api[_-]?key|password|passwd|token|secret)["']?\s*[=:]\s*["']?[^\s"'&,;]{3,}/i,
];

/**
 * `canary`, when given, lets this run's own fake secret (sk-honeypot-<canary>) through: it is the evidence, not a real credential.
 * Besides the rules here, every message goes through the payload linter's safety checks (without its marker rule): the same views
 * (zero-width stripped, homoglyphs folded, reversed, rot13, base64, hex, leetspeak), IP addresses, destructive commands, credential
 * patterns, and any dotted name with a TLD-like suffix that is not a reserved host.
 */
export function guardMessage(message: string, options: { canary?: string } = {}): GuardResult {
  if (typeof message !== "string" || message.trim() === "") return { ok: false, reason: "the message is empty" };
  if (message.length > MAX_MESSAGE_CHARS) return { ok: false, reason: `the message is longer than ${MAX_MESSAGE_CHARS} characters` };
  if (CONTROL.test(message)) return { ok: false, reason: "the message has a control character other than newline or tab" };
  const text = options.canary ? message.split(secretFor(options.canary)).join("") : message;
  for (const pattern of CREDENTIALS) if (pattern.test(text)) return { ok: false, reason: "the message has a credential-looking string" };
  const problems = safetyProblems(message, { genericHosts: true, ...(options.canary !== undefined ? { canary: options.canary } : {}) });
  if (problems.length) return { ok: false, reason: `the message is not benign: ${problems.slice(0, 3).join("; ")}` };
  return { ok: true };
}
