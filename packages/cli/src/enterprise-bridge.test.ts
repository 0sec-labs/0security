import { afterEach, describe, expect, it, vi } from "vitest";
import { hasFeature, requireFeature } from "./enterprise-bridge.js";
import { applyTestLicense, makeTestLicense } from "./web/__fixtures__/test-license.js";

let restore: (() => void) | undefined;
afterEach(() => { restore?.(); restore = undefined; });

describe("enterprise bridge", () => {
  it("grants a feature only for a license signed by a trusted key and naming it", () => {
    expect(hasFeature("rbac")).toBe(false);
    restore = applyTestLicense(["rbac"]);
    expect(hasFeature("rbac")).toBe(true);
    expect(hasFeature("scim")).toBe(false);
    expect(requireFeature("rbac")).toBeNull();
    expect(requireFeature("scim")).toContain("does not include");
  });
});

describe("trust anchors", () => {
  // These use the real enterprise module, not the test mock: this is what the product does.
  it("trusts only the compiled-in keys: a license from another key is invalid", async () => {
    const real = await vi.importActual<typeof import("@0/enterprise")>("@0/enterprise");
    const { env } = makeTestLicense(["rbac", "scim"]);
    const loaded = real.loadLicense(env);
    expect(loaded.state).toBe("invalid"); expect(loaded.reason).toBe("unknown-key");
    expect(real.hasFeature("rbac", env)).toBe(false);
  });

  it("cannot be given another trusted key through the environment", async () => {
    const real = await vi.importActual<typeof import("@0/enterprise")>("@0/enterprise");
    const { env, publicKeys } = makeTestLicense(["rbac"]);
    const spki = JSON.stringify(publicKeys); const kid = Object.keys(publicKeys)[0]!;
    const tryNames = ["ZERO_LICENSE_TEST_PUBLIC_KEYS", "ZERO_LICENSE_PUBLIC_KEYS", "ZERO_LICENSE_PUBLIC_KEY", "ZERO_LICENSE_KEYS", "ZERO_TRUSTED_KEYS", "ZERO_PUBLIC_KEYS"];
    const withNames = { ...env, ...Object.fromEntries(tryNames.map(name => [name, spki])), [`ZERO_LICENSE_KEY_${kid}`]: Object.values(publicKeys)[0]! };
    expect(real.hasFeature("rbac", withNames)).toBe(false);
    // The same holds for the process environment, which the bridge reads.
    const before = Object.fromEntries(tryNames.map(name => [name, process.env[name]]));
    for (const name of tryNames) process.env[name] = spki;
    process.env.ZERO_LICENSE = env.ZERO_LICENSE;
    try { expect(real.hasFeature("rbac")).toBe(false); }
    finally { for (const [name, value] of Object.entries(before)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } delete process.env.ZERO_LICENSE; }
  });
});
