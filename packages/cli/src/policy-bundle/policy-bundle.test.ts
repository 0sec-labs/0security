import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { acceptPolicyBundle, configuredKeys, loadPolicyBundle, parseTrustedKey, policyBundleStatePath, verifyPolicyBundle, BUNDLE_FORMAT, signedBytes } from "./index.js";

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
    expect((await loadPolicyBundle({ policyBundle: f, policyBundleKeyFile: [keyFile] }, dir, {}))?.version).toBe(1);
    expect((await loadPolicyBundle({ policyBundle: f }, dir, { ZERO_POLICY_BUNDLE_KEY_FILE: keyFile }))?.version).toBe(1);
    expect((await loadPolicyBundle({ policyBundle: f }, dir, { ZERO_POLICY_BUNDLE_KEY: pem(a.publicKey) }))?.version).toBe(1);
    await expect(loadPolicyBundle({ policyBundle: "http://example.com/b.json", policyBundleKeyFile: [keyFile] }, dir, {})).rejects.toThrow(/https/);
    await expect(loadPolicyBundle({ policyBundle: "https://example.com/b.json", policyBundleKeyFile: [keyFile] }, dir, { ZERO_ENTERPRISE: "1" })).rejects.toThrow();
    await expect(loadPolicyBundle({ policyBundle: join(dir, "missing.json"), policyBundleKeyFile: [keyFile] }, dir, {})).rejects.toThrow(/not found/);
  });
});

describe("key sources", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "pbk-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const a = pair(); const evil = pair();
  const raw = (k: KeyObject) => (k.export({ format: "der", type: "spki" }) as Buffer).subarray(-32).toString("hex");

  it("never reads a file named like the inline key", () => {
    const repo = join(dir, "repo"); mkdirSync(repo);
    const text = raw(a.publicKey);
    writeFileSync(join(repo, text), pem(evil.publicKey));
    const keys = configuredKeys([text], [], {}, repo);
    expect(keys).toHaveLength(1);
    expect(keys[0].id).toBe(parseTrustedKey(text).id);
    expect(keys[0].id).not.toBe(parseTrustedKey(pem(evil.publicKey)).id);
  });
  it("errors on an invalid inline key instead of trying it as a path", () => {
    const file = join(dir, "k.pem"); writeFileSync(file, pem(a.publicKey));
    expect(() => configuredKeys([file], [], {}, dir)).toThrow(/valid Ed25519/);
    expect(() => configuredKeys([], [], { ZERO_POLICY_BUNDLE_KEY: file }, dir)).toThrow(/valid Ed25519/);
  });
  it("key files must be absolute, plain files outside the working tree", () => {
    const repo = join(dir, "repo"); mkdirSync(join(repo, ".git"), { recursive: true });
    const outside = join(dir, "outside.pem"); writeFileSync(outside, pem(a.publicKey));
    const inside = join(repo, "k.pem"); writeFileSync(inside, pem(a.publicKey));
    expect(configuredKeys([], [outside], {}, repo)).toHaveLength(1);
    expect(() => configuredKeys([], ["outside.pem"], {}, dir)).toThrow(/absolute/);
    expect(() => configuredKeys([], [inside], {}, repo)).toThrow(/working tree/);
    expect(() => configuredKeys([], [inside], {}, join(repo, "sub"))).toThrow(/working tree/);
    const link = join(dir, "link.pem"); symlinkSync(outside, link);
    expect(() => configuredKeys([], [link], {}, repo)).toThrow(/symlink/);
    expect(() => configuredKeys([], [join(dir, "nope.pem")], {}, repo)).toThrow(/not found/);
    expect(() => configuredKeys([], [], { ZERO_POLICY_BUNDLE_KEY_FILE: inside }, repo)).toThrow(/working tree/);
  });
  it("a key file's content is never treated as a path and a path is never treated as key text", () => {
    const f = join(dir, "bad.pem"); writeFileSync(f, "not a key");
    expect(() => configuredKeys([], [f], {}, join(tmpdir(), "elsewhere"))).toThrow(/valid Ed25519/);
  });
});

describe("replay floor under concurrency", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "pbr-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const verified = (version: number) => ({ keyId: "k1", version, digest: `d${version}`, policyText: "{}" });
  it("ends at the highest version whatever the order", async () => {
    for (const order of [[5, 3], [3, 5]]) {
      const home = mkdtempSync(join(dir, "h-"));
      await Promise.allSettled(order.map(v => Promise.resolve().then(() => acceptPolicyBundle(verified(v), home))));
      expect(JSON.parse(readFileSync(policyBundleStatePath(home), "utf8")).k1.version).toBe(5);
    }
  });
  it("never lowers a version that appeared on disk after the read", () => {
    const home = mkdtempSync(join(dir, "h-"));
    acceptPolicyBundle(verified(2), home);
    acceptPolicyBundle(verified(5), home);
    expect(() => acceptPolicyBundle(verified(3), home)).toThrow(/replay/);
    expect(JSON.parse(readFileSync(policyBundleStatePath(home), "utf8")).k1.version).toBe(5);
  });
  it("is safe across real processes", async () => {
    const { spawn } = await import("node:child_process");
    const home = mkdtempSync(join(dir, "h-"));
    const script = fileURLToPath(new URL("./state.ts", import.meta.url));
    const run = (v: number) => new Promise<void>(res => {
      const c = spawn(process.execPath, ["--import", "tsx", "-e", `import("${script}").then(m => { try { m.acceptPolicyBundle({ keyId: "k1", version: ${v}, digest: "d${v}", policyText: "{}" }, ${JSON.stringify(home)}); } catch {} })`], { stdio: "ignore", cwd: process.cwd() });
      c.on("exit", () => res());
    });
    await Promise.all([run(5), run(3), run(4), run(1)]);
    expect(JSON.parse(readFileSync(policyBundleStatePath(home), "utf8")).k1.version).toBe(5);
  }, 60_000);
});

describe("bundle fetch destination", () => {
  const key = pem(pair().publicKey);
  it("refuses loopback, private and http addresses even when the user gave that URL", async () => {
    for (const url of ["https://127.0.0.1/b.json", "https://localhost/b.json", "https://[::1]/b.json", "https://10.0.0.5/b.json", "https://169.254.169.254/b.json"]) {
      await expect(loadPolicyBundle({ policyBundle: url, policyBundleKey: [key] }, tmpdir(), {})).rejects.toThrow(/blocked|Local|internal/i);
    }
    await expect(loadPolicyBundle({ policyBundle: "http://127.0.0.1/b.json", policyBundleKey: [key] }, tmpdir(), {})).rejects.toThrow(/https/);
  });
});
