import { generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Throwaway enterprise licenses for tests. The key pair is made on the spot and never leaves the test. The
 * production key is not involved, and no environment variable or file can add a trusted key to the product.
 *
 * In-process tests: vitest.setup.ts mocks "@0/enterprise" so license checks also trust `testPublicKeys`.
 * Spawned servers: `writeLicenseShim` writes a Node loader hook that swaps "@0/enterprise" for a wrapper
 * trusting the throwaway key. The hook lives in the test's own temp folder and is passed with --import.
 */
export const testPublicKeys: Record<string, string> = {};

export function makeTestLicense(features: string[], options: { expires?: string; issuedAt?: string; seats?: number } = {}): { env: Record<string, string>; token: string; publicKeys: Record<string, string> } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const kid = `t${Object.keys(testPublicKeys).length + 1}-${Math.random().toString(36).slice(2, 8)}`;
  const payload = Buffer.from(JSON.stringify({
    v: 1, id: "lic_test", customer: "test", seats: options.seats ?? 10, features,
    issuedAt: options.issuedAt ?? new Date(Date.now() - 86_400_000).toISOString().replace(/\.\d+Z$/, "Z"),
    expires: options.expires ?? new Date(Date.now() + 30 * 86_400_000).toISOString().replace(/\.\d+Z$/, "Z"), kid,
  }));
  const token = `${payload.toString("base64url")}.${sign(null, payload, privateKey).toString("base64url")}`;
  const publicKeys = { [kid]: publicKey.export({ format: "der", type: "spki" }).toString("base64") };
  return { token, publicKeys, env: { ZERO_LICENSE: token } };
}

/** Use a throwaway license in this process. Returns a function that puts everything back. */
export function applyTestLicense(features: string[], options?: Parameters<typeof makeTestLicense>[1]): () => void {
  const { env, publicKeys } = makeTestLicense(features, options);
  const before = { ZERO_LICENSE: process.env.ZERO_LICENSE, ZERO_LICENSE_FILE: process.env.ZERO_LICENSE_FILE };
  delete process.env.ZERO_LICENSE_FILE;
  Object.assign(process.env, env);
  Object.assign(testPublicKeys, publicKeys);
  return () => {
    for (const kid of Object.keys(publicKeys)) delete testPublicKeys[kid];
    for (const [key, value] of Object.entries(before)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  };
}

/**
 * For a spawned server: write a loader hook and a wrapper into `dir` that make the child process trust
 * `publicKeys` in addition to the production keys. Returns the arguments to put before the entry file.
 */
export function writeLicenseShim(dir: string, publicKeys: Record<string, string>, enterpriseEntry: string): string[] {
  mkdirSync(dir, { recursive: true });
  const shim = join(dir, "enterprise-shim.mjs");
  const hooks = join(dir, "enterprise-hooks.mjs");
  const register = join(dir, "enterprise-register.mjs");
  writeFileSync(shim, `import * as real from ${JSON.stringify(pathToFileURL(enterpriseEntry).href)};
const extra = ${JSON.stringify(publicKeys)};
const merged = () => ({ ...real.PRODUCTION_PUBLIC_KEYS, ...extra });
export * from ${JSON.stringify(pathToFileURL(enterpriseEntry).href)};
export const hasFeature = (name, env, now, keys) => real.hasFeature(name, env, now, keys ?? merged());
export const featureMode = (name, env, now, keys) => real.featureMode(name, env, now, keys ?? merged());
export const requireFeature = (name, env, now, keys) => real.requireFeature(name, env, now, keys ?? merged());
export const licenseStatus = (env, now, keys) => real.licenseStatus(env, now, keys ?? merged());
export const loadLicense = (env, now, keys) => real.loadLicense(env, now, keys ?? merged());
`);
  writeFileSync(hooks, `export async function resolve(specifier, context, next) {
  if (specifier === "@0/enterprise") return { url: ${JSON.stringify(pathToFileURL(shim).href)}, shortCircuit: true };
  return next(specifier, context);
}
`);
  writeFileSync(register, `import { register } from "node:module";\nregister(${JSON.stringify(pathToFileURL(hooks).href)});\n`);
  return ["--import", register];
}
