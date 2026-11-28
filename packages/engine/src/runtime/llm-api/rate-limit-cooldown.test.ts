import { afterEach, describe, expect, it } from "vitest";
import { COOLDOWN_RELEASE_JITTER_MS, RETRY_AFTER_CAP_MS, noteRateLimitCooldown, rateLimitCooldownRemainingMs, resetRateLimitCooldowns, waitForRateLimitCooldown } from "./retry.js";

afterEach(() => resetRateLimitCooldowns());

describe("shared rate-limit cooldown", () => {
  it("is per provider, ends by itself and is never shortened by a later, shorter 429", () => {
    noteRateLimitCooldown("openai", 5_000, 1_000);
    noteRateLimitCooldown("openai", 1_000, 1_500);
    expect(rateLimitCooldownRemainingMs("openai", 2_000)).toBe(4_000);
    expect(rateLimitCooldownRemainingMs("anthropic", 2_000)).toBe(0);
    expect(rateLimitCooldownRemainingMs("openai", 6_001)).toBe(0);
  });

  it("is extended by a later 429 that asks for longer and capped at the Retry-After cap", () => {
    noteRateLimitCooldown("p", 1_000, 0);
    noteRateLimitCooldown("p", 10 * RETRY_AFTER_CAP_MS, 500);
    expect(rateLimitCooldownRemainingMs("p", 500)).toBe(RETRY_AFTER_CAP_MS);
  });

  it("ignores a missing or zero delay", () => {
    noteRateLimitCooldown("p", 0);
    noteRateLimitCooldown("p", Number.NaN);
    expect(rateLimitCooldownRemainingMs("p")).toBe(0);
  });

  it("waits for the cooldown, then a release jitter, and stops at an abort", async () => {
    noteRateLimitCooldown("p", 150);
    const started = Date.now();
    await waitForRateLimitCooldown("p", new AbortController().signal, () => 0);
    expect(Date.now() - started).toBeGreaterThanOrEqual(140);
    expect(COOLDOWN_RELEASE_JITTER_MS).toBeGreaterThan(0);

    noteRateLimitCooldown("p", 60_000);
    const controller = new AbortController();
    const waiting = waitForRateLimitCooldown("p", controller.signal);
    setTimeout(() => controller.abort(), 20);
    await expect(waiting).rejects.toThrow(/Aborted/);
  });

  it("does not wait when no cooldown is active", async () => {
    const started = Date.now();
    await waitForRateLimitCooldown("idle", new AbortController().signal);
    expect(Date.now() - started).toBeLessThan(100);
  });
});
