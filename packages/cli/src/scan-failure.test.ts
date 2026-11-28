import { describe, expect, it } from "vitest";
import { causeOf, classifyFailure, scrubFailureText } from "./scan-failure.js";

describe("causeOf", () => {
  it.each([
    ["OpenAI API error: OpenAI transport failure [UND_ERR_SOCKET]: The connection closed before a complete response was received. Request outcome may be unknown. Automatic replay is disabled", "provider_connection", true],
    ["OpenRouter API error: OpenRouter transport failure [ECONNRESET]: read ECONNRESET", "provider_connection", true],
    ["OpenAI API request timed out; request outcome may be unknown. Automatic replay is disabled", "provider_timeout", true],
    ["OpenRouter request timed out", "provider_timeout", true],
    ["OpenAI Responses stream ended before a terminal response event", "provider_connection", true],
    ["OpenAI API error 429: Rate limit reached for requests per minute", "provider_rate_limit", true],
    ["OpenAI API error 500: The server had an error", "provider_server", true],
    ["OpenAI API error 503: overloaded", "provider_server", true],
    ["OpenAI API error 401: Incorrect API key provided", "provider_auth", false],
    ["OpenAI API error 403: forbidden", "provider_auth", false],
    ["OpenAI API error 429: You exceeded your current quota (insufficient_quota)", "provider_quota", false],
    ["OpenAI API error 400: Invalid request: unsupported parameter", "provider_invalid_request", false],
    ["This model's maximum context length is 128000 tokens", "provider_invalid_request", false],
    ["Provider refusal: chatgpt-codex, model gpt-6.1-sol declined the request (error code cyber_policy on a failed response). cyber_policy: request refused", "provider_refusal", false],
    ["OpenAI API error: 400 This request has been flagged for possible cybersecurity risk.", "provider_refusal", false],
    ["Stopped at the $0.5 cost ceiling.", "budget", false],
    ["Thread cancelled by the operator", "cancelled", false],
    ["Lost contact with the console while scanning: Backend response exceeds the transport limit.", "console_lost", false],
    ["The console this scan starts for itself stopped: it exited with code 1", "console_crashed", false],
    ["No model is configured. Pick one with --model", "no_model", false],
    ["something nobody has seen before", "unknown", false],
    [undefined, "unknown", false],
  ] as const)("%s", (text, cause, transient) => {
    expect(causeOf(text)).toBe(cause);
    expect(classifyFailure(text).transient).toBe(transient);
  });
});

describe("classifyFailure", () => {
  it("says what happened in plain words, without the engine's retry policy text", () => {
    const failure = classifyFailure("OpenAI API error: OpenAI transport failure [UND_ERR_SOCKET]: The connection closed. Request outcome may be unknown. Automatic replay is disabled");
    expect(failure.message).toBe("The model provider dropped the connection: OpenAI transport failure [UND_ERR_SOCKET]: The connection closed");
  });

  it("uses the label alone for a budget stop or a cancellation", () => {
    expect(classifyFailure("Stopped at the $5 cost ceiling.").message).toBe("The scan reached its budget");
    expect(classifyFailure(undefined, "batch_timeout").message).toBe("A batch reached its time limit");
  });

  it("keeps messages short", () => {
    expect(classifyFailure(`API error 500: ${"x ".repeat(500)}`).message.length).toBeLessThan(320);
  });
});

describe("scrubFailureText", () => {
  // Built at run time: a provider-shaped key must not sit in the repository.
  const key = ["s", "k"].join("") + "-" + "A1b2C3d4E5f6G7h8I9j0";
  it("removes keys, bearer tokens, URL credentials and query secrets", () => {
    const text = scrubFailureText(`Incorrect API key ${key}; Authorization: Bearer abcdefgh12345678; https://user:pass@host.example/v1?api_key=${key}&x=1`);
    expect(text).not.toContain(key);
    expect(text).not.toContain("abcdefgh12345678");
    expect(text).not.toContain("user:pass");
    expect(text).not.toContain("pass@");
    expect(text).toContain("host.example");
  });

  it("leaves nothing a pull request comment would act on", () => {
    expect(scrubFailureText("ping @someone, see #123 <img src=x>")).not.toMatch(/@\w|#\d|[<>]/);
  });
});

describe("a provider refusal", () => {
  const text = "Provider refusal: openai, model gpt-6.1-sol declined the request (request flagged for possible cybersecurity risk). OpenAI API error: 400 flagged for possible cybersecurity risk";
  it("says which model refused and that nothing was reviewed, so no findings is not a clean result", () => {
    const failure = classifyFailure(text);
    expect(failure.cause).toBe("provider_refusal");
    expect(failure.transient).toBe(false);
    expect(failure.message).toContain("gpt-6.1-sol");
    expect(failure.message).toContain("no findings does not mean the code is clean");
    expect(failure.message).toContain("another model or provider");
  });
});
