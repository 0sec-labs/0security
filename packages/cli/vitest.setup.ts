// Test setup: let license checks also trust the throwaway keys that tests make (see src/web/__fixtures__/test-license.ts).
// This is a mock of the enterprise module for tests. The product has no way to add a trusted signing key.
import { vi } from "vitest";

vi.mock("@0/enterprise", async (importOriginal) => {
  const real = await importOriginal<typeof import("@0/enterprise")>();
  const { testPublicKeys } = await import("./src/web/__fixtures__/test-license.js");
  const merged = () => ({ ...real.PRODUCTION_PUBLIC_KEYS, ...testPublicKeys });
  return {
    ...real,
    hasFeature: (name: Parameters<typeof real.hasFeature>[0], env?: Parameters<typeof real.hasFeature>[1], now?: Date, keys?: Parameters<typeof real.hasFeature>[3]) => real.hasFeature(name, env, now, keys ?? merged()),
    featureMode: (name: Parameters<typeof real.featureMode>[0], env?: Parameters<typeof real.featureMode>[1], now?: Date, keys?: Parameters<typeof real.featureMode>[3]) => real.featureMode(name, env, now, keys ?? merged()),
    requireFeature: (name: Parameters<typeof real.requireFeature>[0], env?: Parameters<typeof real.requireFeature>[1], now?: Date, keys?: Parameters<typeof real.requireFeature>[3]) => real.requireFeature(name, env, now, keys ?? merged()),
    licenseStatus: (env?: Parameters<typeof real.licenseStatus>[0], now?: Date, keys?: Parameters<typeof real.licenseStatus>[2]) => real.licenseStatus(env, now, keys ?? merged()),
    loadLicense: (env?: Parameters<typeof real.loadLicense>[0], now?: Date, keys?: Parameters<typeof real.loadLicense>[2]) => real.loadLicense(env, now, keys ?? merged()),
  };
});
