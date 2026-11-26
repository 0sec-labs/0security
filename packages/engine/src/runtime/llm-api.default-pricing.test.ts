import { describe, expect, it } from "vitest";
import { DEFAULT_PROVIDER_MODELS } from "./llm-api/provider-detect.js";
import { estimateCost, hasKnownPricing } from "../shared/pricing.js";

// A default model with no price makes the per-run cost ceiling unenforceable, so every default we
// ship for a metered provider must resolve to a price.
describe("default models are priced", () => {
  const usage = { inputTokens: 1_000_000, outputTokens: 1_000_000, cachedInputTokens: 0 };
  for (const provider of ["openai", "anthropic", "openrouter", "xai", "chatgpt-codex"] as const) {
    it(`${provider} default has a price`, () => {
      const model = DEFAULT_PROVIDER_MODELS[provider];
      expect(model, `${provider} must have a default`).toBeTruthy();
      const priced = model!;
      expect(hasKnownPricing(priced), `${priced} is unpriced`).toBe(true);
      expect(estimateCost(usage, priced)).toBeGreaterThan(0);
    });
  }
});

describe("Amazon Bedrock ids are priced as the wrapped model", () => {
  it("maps geography, vendor, date and version wrappers", async () => {
    const { bedrockPriceKey, getRates } = await import("../shared/pricing.js");
    expect(bedrockPriceKey("global.anthropic.claude-sonnet-4-5-20250929-v1:0")).toBe("claude-sonnet-4-5");
    expect(bedrockPriceKey("anthropic.claude-haiku-4-5-20251001-v1:0")).toBe("claude-haiku-4-5");
    expect(bedrockPriceKey("eu.amazon.nova-pro-v1:0")).toBe("nova-pro");
    expect(bedrockPriceKey("claude-sonnet-4-5")).toBe("claude-sonnet-4-5");
    expect(hasKnownPricing("bedrock/global.anthropic.claude-sonnet-4-5-20250929-v1:0")).toBe(true);
    expect(getRates("bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0")).toMatchObject({ input: 3, output: 15 });
    expect(hasKnownPricing("bedrock/vendor.unlisted-v1:0")).toBe(false);
  });
});
