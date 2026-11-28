import { describe, expect, it } from "vitest";
import { PROVIDER_REFUSAL_SIGNALS, classifyProviderRefusal, providerRefusalMessage } from "./provider-refusal.js";

describe("classifyProviderRefusal", () => {
  const refusals: Array<[string, string, string]> = [
    ["openai_cyber_policy", "Codex route failed response",
      `OpenAI API error: Responses terminal failure {"event":"response.failed","status":"failed","code":"cyber_policy","errorType":"refusal"}`],
    ["openai_cyber_policy", "Codex CLI process", "cyber_policy: request refused"],
    ["openai_policy_code", "another *_policy code",
      `OpenAI API error: Responses terminal failure {"event":"response.failed","code":"self_harm_policy"}`],
    ["openai_flagged_cybersecurity", "OpenAI API 400",
      `OpenAI API error: 400 {"error":{"message":"This request has been flagged for possible cybersecurity risk.","type":"invalid_request_error","code":"invalid_prompt"}}`],
    ["openai_limited_access_safety", "OpenAI invalid_prompt",
      `400 {"error":{"message":"Invalid prompt: we've limited access to this content for safety reasons.","code":"invalid_prompt"}}`],
    ["anthropic_refusal_stop", "Anthropic stop reason", `{"type":"message","stop_reason":"refusal","content":[]}`],
    ["anthropic_usage_policy", "Anthropic usage policy", "This request appears to violate our Usage Policy."],
    ["bedrock_guardrail", "Bedrock guardrail", `Bedrock API error: {"stopReason":"guardrail_intervened"}`],
    ["bedrock_guardrail", "Bedrock filters", "The generated text has been blocked by our content filters."],
    ["azure_content_filter", "Azure policy violation", `Azure OpenAI API error: 400 {"error":{"code":"content_filter","innererror":{"code":"ResponsibleAIPolicyViolation"}}}`],
  ];

  it.each(refusals)("%s: %s", (id, _label, text) => {
    expect(classifyProviderRefusal(text)?.id).toBe(id);
  });

  it("covers every row of the table", () => {
    const seen = new Set(refusals.map(([id]) => id));
    for (const row of PROVIDER_REFUSAL_SIGNALS) expect(seen.has(row.id)).toBe(true);
  });

  it.each([
    ["quota", "OpenAI API error: 429 You exceeded your current quota, please check your plan and billing details. insufficient_quota"],
    ["plan quota", "ChatGPT plan quota exhausted: usage_limit_reached, resets in 4h"],
    ["rate limit", "OpenAI API error: 429 Rate limit reached for gpt-6.1 in organization on tokens per min"],
    ["auth", "Anthropic API error: 401 invalid x-api-key"],
    ["forbidden", "OpenAI API error: 403 You are not allowed to use this model"],
    ["server", "OpenAI API error: 503 The server is overloaded or not ready yet"],
    ["server code", `Responses terminal failure {"event":"response.failed","code":"server_error"}`],
    ["timeout", "OpenAI API request timed out; request outcome may be unknown. Automatic replay is disabled"],
    ["transport", "openai transport failure [ECONNRESET]: The connection closed before a complete response was received"],
    ["empty stream", "OpenAI API error: stream completed without final response (HTTP 200; events=response.output_text.delta)"],
    ["context length", "OpenAI API error: 400 maximum context length is 128000 tokens"],
    ["unrelated policy words", "Add a Content-Security-Policy header and a password policy to the login form"],
  ])("does not treat %s as a refusal", (_label, text) => {
    expect(classifyProviderRefusal(text)).toBeUndefined();
  });

  it("returns undefined for empty input", () => {
    expect(classifyProviderRefusal(undefined)).toBeUndefined();
    expect(classifyProviderRefusal("")).toBeUndefined();
  });

  it("builds a message naming provider, model and signal, then the provider's words", () => {
    const refusal = classifyProviderRefusal("cyber_policy: request refused")!;
    expect(providerRefusalMessage({ provider: "chatgpt-codex", model: "gpt-6.1-sol" }, refusal, "cyber_policy: request refused"))
      .toBe("Provider refusal: chatgpt-codex, model gpt-6.1-sol declined the request (error code cyber_policy on a failed response). cyber_policy: request refused");
  });
});
