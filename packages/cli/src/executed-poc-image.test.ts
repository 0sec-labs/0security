import { describe, expect, it } from "vitest";
import { applyPocImage, resolvePocImage } from "./executed-poc-image.js";
import { UsageError } from "./commands/output.js";

const PINNED = `alpine@sha256:${"a".repeat(64)}`;
const OTHER = `busybox@sha256:${"b".repeat(64)}`;

describe("executed PoC opt-in", () => {
  it("stays off with nothing set", () => {
    expect(resolvePocImage(undefined, "", {})).toBeUndefined();
    expect(applyPocImage(undefined, undefined, {})).toBeUndefined();
  });
  it("the flag wins over the environment and the setting, and sets ZERO_POC_IMAGE", () => {
    const env: NodeJS.ProcessEnv = { ZERO_POC_IMAGE: OTHER };
    expect(applyPocImage(PINNED, OTHER, env)).toBe(PINNED);
    expect(env.ZERO_POC_IMAGE).toBe(PINNED);
  });
  it("an existing ZERO_POC_IMAGE wins over the setting and is left alone", () => {
    const env: NodeJS.ProcessEnv = { ZERO_POC_IMAGE: OTHER };
    expect(applyPocImage(undefined, PINNED, env)).toBeUndefined();
    expect(env.ZERO_POC_IMAGE).toBe(OTHER);
  });
  it("the setting turns it on when nothing else is set", () => {
    const env: NodeJS.ProcessEnv = {};
    expect(applyPocImage(undefined, PINNED, env)).toBe(PINNED);
    expect(env.ZERO_POC_IMAGE).toBe(PINNED);
  });
  it("refuses a tag, a bare name or a short digest, from the flag or the setting, and sets nothing", () => {
    for (const bad of ["alpine:3.20", "alpine", "alpine@sha256:abc", `alpine@sha256:${"g".repeat(64)}`]) {
      const env: NodeJS.ProcessEnv = {};
      expect(() => applyPocImage(bad, undefined, env)).toThrow(UsageError);
      expect(() => applyPocImage(undefined, bad, env)).toThrow(/pinned by digest/);
      expect(env.ZERO_POC_IMAGE).toBeUndefined();
    }
  });
});
