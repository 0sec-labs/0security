import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadPolicyBundle, parseTrustedKey, policyBundleStatePath, verifyPolicyBundle, BUNDLE_FORMAT, signedBytes } from "./index.js";

const pair = () => generateKeyPairSync("ed25519");
const pem = (k: KeyObject) => k.export({ format: "pem", type: "spki" }).toString();
const POLICY = JSON.stringify({ rules: ["no new dependencies"] });
function bundle(priv: KeyObject, version: number, policy = POLICY): string {
  const bytes = Buffer.from(policy);
  return JSON.stringify({ format: BUNDLE_FORMAT, version, policy: bytes.toString("base64"), signature: sign(null, signedBytes(version, bytes), priv).toString("base64") });
}

describe("verifyPolicyBundle", () => {
  const a = pair(); const b = pair();
  it("accepts a bundle signed by a configured key (PEM or raw base64)", () => {
    expect(verifyPolicyBundle(bundle(a.privateKey, 2), [parseTrustedKey(pem(a.publicKey))]).policyText).toBe(POLICY);
    const raw = (a.publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32).toString("base64");
    expect(verifyPolicyBundle(bundle(a.privateKey, 2), [parseTrustedKey(raw)]).version).toBe(2);
  });
  it("refuses a tampered policy or version", () => {
    const keys = [parseTrustedKey(pem(a.publicKey))];
    const good = JSON.parse(bundle(a.privateKey, 2));
    const evil = { ...good, policy: Buffer.from(JSON.stringify({ rules: [] })).toString("base64") };
    expect(() => verifyPolicyBundle(JSON.stringify(evil), keys)).toThrow(/does not match/);
    expect(() => verifyPolicyBundle(JSON.stringify({ ...good, version: 3 }), keys)).toThrow(/does not match/);
  });
  it("refuses a wrong key and no key", () => {
    expect(() => verifyPolicyBundle(bundle(a.privateKey, 1), [parseTrustedKey(pem(b.publicKey))])).toThrow(/does not match/);
    expect(() => verifyPolicyBundle(bundle(a.privateKey, 1), [])).toThrow(/No policy bundle key/);
  });
  it("refuses malformed bundles", () => {
    const keys = [parseTrustedKey(pem(a.publicKey))];
    const good = JSON.parse(bundle(a.privateKey, 1));
    for (const bad of ["not json", "[]", JSON.stringify({ ...good, format: "x" }), JSON.stringify({ ...good, version: 0 }), JSON.stringify({ ...good, version: 1.5 }), JSON.stringify({ ...good, policy: "" }), JSON.stringify({ ...good, signature: "AAAA" }), JSON.stringify({ ...good, signature: 5 })]) {
      expect(() => verifyPolicyBundle(bad, keys)).toThrow();
    }
    expect(() => parseTrustedKey("zzz")).toThrow(/valid Ed25519/);
    expect(() => parseTrustedKey(pem(generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey))).toThrow(/Ed25519/);
  });
});

describe("loadPolicyBundle", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "pb-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const a = pair();
  const write = (name: string, text: string) => { const p = join(dir, name); writeFileSync(p, text); return p; };
  const opts = (file: string) => ({ policyBundle: file, policyBundleKey: [pem(a.publicKey)] });

  it("applies a newer version and refuses replay of an older one", async () => {
    const v2 = write("v2.json", bundle(a.privateKey, 2));
    const v1 = write("v1.json", bundle(a.privateKey, 1, JSON.stringify({ rules: ["old"] })));
    const v3 = write("v3.json", bundle(a.privateKey, 3));
    expect((await loadPolicyBundle(opts(v2), dir, {}))?.version).toBe(2);
    await expect(loadPolicyBundle(opts(v1), dir, {})).rejects.toThrow(/replay/);
    expect((await loadPolicyBundle(opts(v2), dir, {}))?.version).toBe(2);
    expect((await loadPolicyBundle(opts(v3), dir, {}))?.version).toBe(3);
    expect(JSON.parse(readFileSync(policyBundleStatePath(dir), "utf8"))).toBeTruthy();
  });
  it("refuses the same version with different content", async () => {
    await loadPolicyBundle(opts(write("a.json", bundle(a.privateKey, 5))), dir, {});
    await expect(loadPolicyBundle(opts(write("b.json", bundle(a.privateKey, 5, JSON.stringify({ rules: ["other"] })))), dir, {})).rejects.toThrow(/replay/);
  });
  it("does not record a refused bundle", async () => {
    const other = pair();
    await expect(loadPolicyBundle({ policyBundle: write("x.json", bundle(other.privateKey, 9)), policyBundleKey: [pem(a.publicKey)] }, dir, {})).rejects.toThrow(/does not match/);
    expect((await loadPolicyBundle(opts(write("y.json", bundle(a.privateKey, 1))), dir, {}))?.version).toBe(1);
  });
  it("reads keys from a file or the environment, and refuses http and enterprise mode", async () => {
    const keyFile = write("k.pem", pem(a.publicKey));
    const f = write("f.json", bundle(a.privateKey, 1));
    expect((await loadPolicyBundle({ policyBundle: f, policyBundleKey: [keyFile] }, dir, {}))?.version).toBe(1);
    expect((await loadPolicyBundle({ policyBundle: f }, dir, { ZERO_POLICY_BUNDLE_KEY: keyFile }))?.version).toBe(1);
    await expect(loadPolicyBundle({ policyBundle: "http://example.com/b.json", policyBundleKey: [keyFile] }, dir, {})).rejects.toThrow(/https/);
    await expect(loadPolicyBundle({ policyBundle: "https://example.com/b.json", policyBundleKey: [keyFile] }, dir, { ZERO_ENTERPRISE: "1" })).rejects.toThrow();
    await expect(loadPolicyBundle({ policyBundle: join(dir, "missing.json"), policyBundleKey: [keyFile] }, dir, {})).rejects.toThrow(/not found/);
  });
});
