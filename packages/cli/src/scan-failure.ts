/**
 * Why a scan thread failed, in plain words, and whether trying again can help.
 *
 * The console reports a failed turn as one error string. This reads it into a cause. Only causes that come from the
 * network or an overloaded provider are transient. Budget, authentication, invalid requests and cancellations are never
 * retried: another attempt would fail the same way or spend more for nothing.
 */

export type FailureCause =
  | "provider_connection"
  | "provider_timeout"
  | "provider_rate_limit"
  | "provider_server"
  | "provider_auth"
  | "provider_quota"
  | "provider_invalid_request"
  | "provider_refusal"
  | "no_model"
  | "budget"
  | "timeout"
  | "batch_timeout"
  | "cancelled"
  | "console_lost"
  | "console_crashed"
  | "target_changed"
  | "unknown";

export interface ScanFailure {
  cause: FailureCause;
  /** A retry can help: the failure came from the connection or the provider being busy. */
  transient: boolean;
  /** A short sentence with secrets removed. */
  message: string;
}

import { PROVIDER_REFUSAL_ADVICE, classifyProviderRefusal } from "@0/engine/shared";

const MAX_MESSAGE = 240;

/** Remove what must not reach a terminal, a report or a pull request comment: keys, tokens, URL credentials. */
export function scrubFailureText(text: string): string {
  return text
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [redacted]")
    .replace(/\b(sk|pk|rk|ghp|gho|ghs|github_pat|xox[abprs]|AIza|AKIA|ASIA|glpat|hf|r8|gsk|nvapi|fw)[-_][A-Za-z0-9_-]{12,}/g, "[redacted]")
    .replace(/\b(AIza|AKIA|ASIA)[A-Za-z0-9_-]{12,}/g, "[redacted]")
    .replace(/([?&;](?:api[_-]?key|key|token|access_token|secret|password|signature|sig)=)[^&\s"']+/gi, "$1[redacted]")
    .replace(/\b((?:api[_-]?key|token|secret|password|authorization)["']?\s*[:=]\s*["']?)[^\s"',;]{6,}/gi, "$1[redacted]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+(?::[^\s/@]*)?@/gi, "$1")
    // The text can end up in a pull request comment: no HTML, no @mentions, no #references.
    .replace(/[<>]/g, " ")
    .replace(/@/g, " at ")
    .replace(/#(?=\w)/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/** The same text, shortened at a word boundary with a trailing dot kept off. */
function shorten(text: string, limit = MAX_MESSAGE): string {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit);
  return `${cut.slice(0, Math.max(cut.lastIndexOf(" "), limit - 40))}...`;
}

/** What an operator reads before the error text: no engine wording, no repeated provider names. */
function plain(text: string): string {
  return text
    .replace(/^[A-Za-z0-9 ()._-]+ API error:\s*/i, "")
    .replace(/\.?\s*Request outcome may be unknown\.?\s*Automatic replay is disabled(?: by the configured retry policy)?\.?/i, "")
    .replace(/\s+Automatic replay is disabled(?: by the configured retry policy)?\.?/i, "")
    .trim();
}

const LABEL: Record<FailureCause, string> = {
  provider_connection: "The model provider dropped the connection",
  provider_timeout: "The model provider did not answer in time",
  provider_rate_limit: "The model provider rate limit was hit",
  provider_server: "The model provider returned a server error",
  provider_auth: "The model provider refused the credentials",
  provider_quota: "The model provider account has no quota left",
  provider_invalid_request: "The model provider rejected the request",
  provider_refusal: "The model provider refused the request (a policy or safety block, not an outage)",
  no_model: "No model is configured",
  budget: "The scan reached its budget",
  timeout: "The scan reached its time limit",
  batch_timeout: "A batch reached its time limit",
  cancelled: "The thread was cancelled",
  console_lost: "The scan lost contact with its console",
  console_crashed: "The console stopped",
  target_changed: "The scan changed files in the target",
  unknown: "The scan thread failed",
};

const TRANSIENT: ReadonlySet<FailureCause> = new Set(["provider_connection", "provider_timeout", "provider_rate_limit", "provider_server"]);

/** Which cause an error string stands for. Order matters: the specific causes come before the general ones. */
export function causeOf(raw: string | undefined): FailureCause {
  const text = raw ?? "";
  if (/cost ceiling|budget/i.test(text) && !/api error|provider/i.test(text)) return "budget";
  if (/\bcancell?ed\b|aborted by (the )?(operator|user)|operation was aborted/i.test(text)) return "cancelled";
  if (/lost contact with the console|backend response exceeds/i.test(text)) return "console_lost";
  if (/console (this scan starts for itself )?stopped|console exited|could not start a console/i.test(text)) return "console_crashed";
  if (/changed \d+ files? in the target/i.test(text)) return "target_changed";
  // A refusal comes first: its text can mention policy, access or safety, and it must never read as quota, auth or a bad request.
  if (classifyProviderRefusal(text)) return "provider_refusal";
  if (/quota|insufficient_quota|billing|usage_limit|credit balance|out of credits/i.test(text)) return "provider_quota";
  if (/(?:error|http|status)\s*(?:code\s*)?(?:401|403)\b|\b(?:401|403)\b.*(?:unauthori[sz]ed|forbidden)|unauthori[sz]ed|invalid[_ ]api[_ ]key|incorrect api key|authentication|invalid[_ ]credentials|forbidden|\blog ?in\b|reconnect the local model source|credentials/i.test(text)) return "provider_auth";
  if (/no model|model[^.]*(?:not configured|is not set)|no provider|choose a model|pick a model|no api key|no credentials? (?:found|configured)/i.test(text)) return "no_model";
  if (/(?:error|http|status)\s*(?:code\s*)?429\b|rate[ _-]?limit|too many requests/i.test(text)) return "provider_rate_limit";
  if (/(?:error|http|status)\s*(?:code\s*)?(?:400|404|405|409|413|415|422)\b|invalid[_ ]request|context[_ ]length|maximum context|unsupported (?:parameter|model)|model[^.]*not found|does not exist/i.test(text)) return "provider_invalid_request";
  if (/(?:error|http|status)\s*(?:code\s*)?5\d\d\b|gateway HTTP 5|\b50[0-4]\b|overloaded|bad gateway|service unavailable|internal server error|server_error/i.test(text)) return "provider_server";
  if (/timed out|timeout|ETIMEDOUT|UND_ERR_(?:HEADERS|BODY|CONNECT)_TIMEOUT|did not answer|stalled/i.test(text)) return "provider_timeout";
  if (/UND_ERR|ECONNRESET|ECONNREFUSED|ECONNABORTED|EPIPE|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|socket|connection (?:was )?(?:closed|reset|failed|lost|refused)|transport failure|fetch failed|stream failed|stream ended|ended before|incomplete response|network|terminated/i.test(text)) return "provider_connection";
  return "unknown";
}

/** Read a thread's error text into a cause, a plain message and whether a retry can help. */
export function classifyFailure(raw: string | undefined, override?: FailureCause): ScanFailure {
  const cause = override ?? causeOf(raw);
  const detail = shorten(scrubFailureText(plain(raw ?? "")));
  // A refusal reviewed nothing: the advice is part of the message so no report, stderr line or JSON field can lose it.
  if (cause === "provider_refusal") return { cause, transient: false, message: `${LABEL[cause]}: ${shorten(detail.replace(/^Provider refusal:\s*/i, ""), 200)}. ${PROVIDER_REFUSAL_ADVICE}` };
  const message = detail && cause !== "budget" && cause !== "cancelled" ? `${LABEL[cause]}: ${detail}` : LABEL[cause];
  return { cause, transient: TRANSIENT.has(cause), message: shorten(message, MAX_MESSAGE + 60) };
}

/** For `findings verify` and `findings fix`: the full refusal message when this thread error is a provider refusal, else the error as it is. */
export function threadErrorText(error: string | undefined): string | undefined {
  const failure = error ? classifyFailure(error) : undefined;
  return failure?.cause === "provider_refusal" ? failure.message : error;
}
