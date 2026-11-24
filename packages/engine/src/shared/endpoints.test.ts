import { describe, expect, it } from "vitest";
import { BRAND } from "./endpoints.js";

describe("BRAND", () => {
  it("is internally consistent", () => {
    for (const slug of [BRAND.repo, BRAND.foxguardRepo]) expect(slug.startsWith(`${BRAND.githubOrg}/`)).toBe(true);
  });
});
