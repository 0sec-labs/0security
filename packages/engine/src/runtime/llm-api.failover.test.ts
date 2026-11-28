import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LlmApiRuntime, __resetFallbackChainForTests, isPolicyRefusalResult } from "./llm-api.js";
import type { NativeMessage, NativeRuntimeResult, RuntimeConfig } from "./types.js";

// The exact error string consumeResponsesStream produces for a provider-side
// policy rejection: HTTP 200 SSE that streams, then ends with response.failed
// carrying a *_policy error code (observed live as `cyber_policy`).
function refusalError(code = "cyber_policy"): string {
  return `OpenAI API error: Responses terminal failure ${JSON.stringify({
    event: "response.failed",
    status: "failed",
    code,
    errorType: "refusal",
    reason: "policy block",
  })}`;
}

describe("isPolicyRefusalResult (pure classifier)", () => {
  const refused = (over: Partial<NativeRuntimeResult> = {}): NativeRuntimeResult => ({
    content: [{ type: "text", text: "" }],
    stopReason: "error",
    durationMs: 1,
    error: refusalError(),
    ...over,
  });

  it("recognises a Responses terminal refusal with a *_policy code", () => {
    expect(isPolicyRefusalResult(refused())).toBe(true);
    expect(isPolicyRefusalResult(refused({ error: refusalError("self_harm_policy") }))).toBe(true);
  });

  it("rejects non-policy terminal codes", () => {
    expect(isPolicyRefusalResult(refused({ error: refusalError("server_error") }))).toBe(false);
    expect(isPolicyRefusalResult(refused({ error: refusalError("rate_limit_exceeded") }))).toBe(false);
  });

  it("rejects outcomes that are not terminal failures at all", () => {
    expect(isPolicyRefusalResult(refused({ error: "OpenAI API error: stream completed without final response (HTTP 200; events=response.output_text.delta; malformed=0; trailing=0)" }))).toBe(false);
    expect(isPolicyRefusalResult(refused({ error: "OpenAI API error: response stream failed" }))).toBe(false);
    expect(isPolicyRefusalResult(refused({ error: undefined }))).toBe(false);
  });

  it("never misfires on successful output or cancellations, even with matching text", () => {
    expect(isPolicyRefusalResult(refused({ stopReason: "tool_use", content: [{ type: "tool_use", id: "call_x", name: "inspect", input: {} }] }))).toBe(false);
    expect(isPolicyRefusalResult(refused({ stopReason: "end_turn" }))).toBe(false);
    expect(isPolicyRefusalResult(refused({ cancelled: true }))).toBe(false);
  });

  it("rejects a malformed envelope after the marker", () => {
    expect(isPolicyRefusalResult(refused({ error: "OpenAI API error: Responses terminal failure not-json" }))).toBe(false);
  });
});

// ── executeNative failover integration (all traffic stays on mock fetch) ──

const messages: NativeMessage[] = [{ role: "user", content: [{ type: "text", text: "Inspect README.md" }] }];
const sse = (frames: unknown[]): string => frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join("");

// Primary (openai Responses wire): streams a fragment, then the safety
// classifier rejects with HTTP 200 + response.failed code=cyber_policy.
const primaryRefusal = sse([
  { type: "response.output_text.delta", delta: "scanning the target" },
  {
    type: "response.failed",
    response: {
      status: "failed",
      usage: { input_tokens: 21, output_tokens: 4 },
      error: { code: "cyber_policy", type: "refusal", message: "policy block" },
    },
  },
]);

// Fallback (deepseek, also Responses wire): completes with a tool call.
const fallbackCompletion = sse([
  {
    type: "response.completed",
    response: {
      status: "completed",
      output: [{ type: "function_call", call_id: "call_fixture", name: "inspect", arguments: '{"path":"README.md"}' }],
      usage: { input_tokens: 5, output_tokens: 2 },
    },
  },
]);

const failoverConfig: Partial<RuntimeConfig> = {
  provider: "openai",
  model: "gpt-fixture",
  env: {
    OPENAI_API_KEY: "fixture-primary",
    OPENAI_WIRE_API: "responses",
    DEEPSEEK_API_KEY: "fixture-fallback",
    ZERO_LLM_FALLBACK: "deepseek:deepseek-v4-flash",
    ZERO_LLM_STREAM_MAX_ATTEMPTS: "1",
    ZERO_SUPPRESS_PROVIDER_STARTUP_LOG: "1",
  },
};

function expectToolUse(result: NativeRuntimeResult) {
  expect(result.error).toBeUndefined();
  expect(result.stopReason).toBe("tool_use");
  expect(result.content).toEqual([{ type: "tool_use", id: "call_fixture", name: "inspect", input: { path: "README.md" } }]);
}

describe("executeNative provider refusal (terminal, no failover)", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
  beforeEach(() => {
    vi.stubEnv("ZERO_LLM_STREAM_MAX_ATTEMPTS", "1");
    vi.stubEnv("ZERO_SUPPRESS_PROVIDER_STARTUP_LOG", "1");
    __resetFallbackChainForTests();
    fetchMock = vi.fn<typeof fetch>(async () => { throw new Error("Unexpected mock transport request"); });
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    __resetFallbackChainForTests();
  });

  function urlsCalled(): string[] {
    return fetchMock.mock.calls.map(([input]) => String(input instanceof Request ? input.url : input));
  }

  it("does not fail over to the configured fallback: a refusal is terminal and names the model", async () => {
    fetchMock.mockResolvedValueOnce(new Response(primaryRefusal, { headers: { "content-type": "text/event-stream" } }));
    const runtime = new LlmApiRuntime({ type: "api", timeout: 1000, ...failoverConfig });
    const result = await runtime.executeNative("Inspect the synthetic workspace.", structuredClone(messages), []);

    // Only the primary is called: the deepseek fallback would be a different model running the scan unannounced.
    expect(urlsCalled()).toEqual([expect.stringContaining("api.openai.com")]);
    expect(result.stopReason).toBe("error");
    expect(result.error).toMatch(/^Provider refusal: .*gpt-fixture/);
    expect(result.error).toContain("cyber_policy");
    expect(result.refusal).toMatchObject({ model: "gpt-fixture", signal: "openai_cyber_policy" });
    expect(result.usage).toEqual({ inputTokens: 21, outputTokens: 4 });
  });

  it("does not retry a refusal even when empty-stream retries are allowed", async () => {
    vi.stubEnv("ZERO_LLM_STREAM_MAX_ATTEMPTS", "3");
    fetchMock.mockResolvedValue(new Response(primaryRefusal, { headers: { "content-type": "text/event-stream" } }));
    const runtime = new LlmApiRuntime({ type: "api", timeout: 1000, ...failoverConfig, env: { ...failoverConfig.env, ZERO_LLM_STREAM_MAX_ATTEMPTS: "3" } });
    const result = await runtime.executeNative("Inspect the synthetic workspace.", structuredClone(messages), []);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(result.refusal).toBeDefined();
  });

  it("recognises the OpenAI API 400 'flagged for possible cybersecurity risk' as a refusal", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: { message: "This request has been flagged for possible cybersecurity risk. If you are doing legitimate security work, apply for trusted access.", type: "invalid_request_error", code: "invalid_prompt" } }), { status: 400, headers: { "content-type": "application/json" } }));
    const runtime = new LlmApiRuntime({ type: "api", timeout: 1000, ...failoverConfig, env: { ...failoverConfig.env, OPENAI_WIRE_API: "chat_completions" } });
    const result = await runtime.executeNative("Inspect the synthetic workspace.", structuredClone(messages), []);
    expect(urlsCalled()).toHaveLength(1);
    expect(result.stopReason).toBe("error");
    expect(result.refusal?.signal).toBe("openai_flagged_cybersecurity");
    expect(result.error).toContain("Provider refusal");
  });

  it("does not fail over on a non-policy terminal failure", async () => {
    fetchMock.mockResolvedValueOnce(new Response(sse([
      {
        type: "response.failed",
        response: {
          status: "failed",
          usage: { input_tokens: 21, output_tokens: 4 },
          error: { code: "server_error", type: "server_error", message: "boom" },
        },
      },
    ]), { headers: { "content-type": "text/event-stream" } }));

    const runtime = new LlmApiRuntime({ type: "api", timeout: 1000, ...failoverConfig });
    const result = await runtime.executeNative("Inspect the synthetic workspace.", structuredClone(messages), []);

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("server_error");
    expect(result.usage).toEqual({ inputTokens: 21, outputTokens: 4 });
  });

});
