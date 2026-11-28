/**
 * Recognise a provider refusal: the model provider (or a gateway in front of it) declined to do security work because of
 * a policy or safety block. This is a different class from transport, quota, rate-limit and auth errors:
 *
 * - it is terminal for that model: the same content sent again is refused again, so it is never retried;
 * - it must never be answered by quietly using another (possibly weaker) model;
 * - a scan that hit it reviewed nothing, so "no findings" must not be read as "the code is clean".
 *
 * One table drives every consumer (the runtime's retry code, the scan failure classifier in the CLI). Each row names the
 * exact signal a provider sends and matches the error text a runtime produced. Add a row; do not special-case a
 * provider elsewhere.
 */

export type RefusalSignalId =
  | "openai_cyber_policy"
  | "openai_policy_code"
  | "openai_flagged_cybersecurity"
  | "openai_limited_access_safety"
  | "anthropic_refusal_stop"
  | "anthropic_usage_policy"
  | "bedrock_guardrail"
  | "azure_content_filter";

export interface RefusalSignal {
  id: RefusalSignalId;
  /** Who sends it, for the message the operator reads. */
  source: string;
  /** What the provider says, as a short reminder for maintainers and the operator. */
  signal: string;
  pattern: RegExp;
}

export const PROVIDER_REFUSAL_SIGNALS: readonly RefusalSignal[] = [
  { id: "openai_cyber_policy", source: "OpenAI (Responses, Codex route)", signal: "error code cyber_policy on a failed response", pattern: /\bcyber_policy\b/i },
  { id: "openai_policy_code", source: "OpenAI (Responses)", signal: "a *_policy error code on a failed response", pattern: /["']?code["']?\s*[:=]\s*["'][a-z0-9]+(?:_[a-z0-9]+)*_policy["']/i },
  { id: "openai_flagged_cybersecurity", source: "OpenAI API", signal: "request flagged for possible cybersecurity risk", pattern: /flagged (?:for|as)(?: a)?(?: possible| potential| suspected)? cyber ?security (?:risk|activity|misuse)/i },
  { id: "openai_limited_access_safety", source: "OpenAI API", signal: "limited access to this content for safety reasons", pattern: /limited access to this content for safety reasons/i },
  { id: "anthropic_refusal_stop", source: "Anthropic Messages", signal: "stop_reason refusal", pattern: /\bstop_reason["']?\s*[:=]\s*["']?refusal\b/i },
  { id: "anthropic_usage_policy", source: "Anthropic", signal: "request appears to violate the Usage Policy", pattern: /appears to violate our usage policy/i },
  { id: "bedrock_guardrail", source: "Amazon Bedrock", signal: "guardrail intervened and blocked the content", pattern: /guardrail_intervened|blocked by (?:the |a )?guardrail|generated text has been blocked by our content filters/i },
  { id: "azure_content_filter", source: "Azure OpenAI", signal: "content filter or responsible AI policy violation", pattern: /ResponsibleAIPolicyViolation|["']?code["']?\s*[:=]\s*["']content_filter["']|prompt triggering azure openai's content management policy/i },
];

export interface ProviderRefusal {
  id: RefusalSignalId;
  source: string;
  signal: string;
}

/** The refusal signal in an error text, or undefined when the text is anything else (transport, quota, rate limit, auth). */
export function classifyProviderRefusal(text: string | undefined): ProviderRefusal | undefined {
  if (!text) return undefined;
  const hit = PROVIDER_REFUSAL_SIGNALS.find(row => row.pattern.test(text));
  return hit ? { id: hit.id, source: hit.source, signal: hit.signal } : undefined;
}

/** What every refusal means for the result and what to do about it. */
export const PROVIDER_REFUSAL_ADVICE = "Nothing was reviewed by this model, so no findings does not mean the code is clean. Use another model or provider whose policy permits security review; 0security does not switch models on its own.";

/** The error text a refused call carries: who refused, which model, which signal, then the provider's own words. */
export function providerRefusalMessage(who: { provider: string; model?: string }, refusal: ProviderRefusal, providerText: string): string {
  const model = who.model ? `, model ${who.model}` : "";
  return `Provider refusal: ${who.provider}${model} declined the request (${refusal.signal}). ${providerText}`.trim();
}
