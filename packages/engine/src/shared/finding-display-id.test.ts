import { describe, expect, it } from "vitest";
import { findingFingerprintCode, shortFindingFingerprint } from "./finding-display-id.js";

const scan = `sarif-${"8".repeat(64)}`;
describe("finding display identities", () => {
  it("shows the finding digest instead of the shared report prefix", () => {
    expect(findingFingerprintCode(`${scan}:sarif:0123456789abcdef`)).toBe("F-0123456789");
    expect(findingFingerprintCode(`${scan}:sarif:abcdef0123456789`)).toBe("F-ABCDEF0123");
    expect(findingFingerprintCode(`ci-${"a".repeat(64)}:0123456789abcdef`)).toBe("F-0123456789");
    expect(shortFindingFingerprint(`${scan}:sarif:0123456789abcdef`)).toBe("0123456789");
    expect(findingFingerprintCode("loc:abcdef0123456789")).toBe("F-ABCDEF0123");
  });
  it("preserves ordinary legacy family codes", () => {
    expect(findingFingerprintCode("a1b2c3d4e5f6")).toBe("F-A1B2C3");
    expect(findingFingerprintCode("ordinary-finding")).toBe("F-ORDINA");
    expect(findingFingerprintCode("")).toBe("F-000000");
    expect(shortFindingFingerprint("loc:abcdef0123456789")).toBe("loc:abcdef");
  });
});
