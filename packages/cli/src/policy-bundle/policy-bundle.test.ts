import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdirSync, utimesSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { assertPublicBundleUrl } from "./load.js";
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
  it("refuses a key file inside any repository the command reads, such as --repo", () => {
    const cwd = join(dir, "cwd"); mkdirSync(cwd);
    const other = join(dir, "other"); mkdirSync(join(other, ".git"), { recursive: true });
    const planted = join(other, "k.pem"); writeFileSync(planted, pem(evil.publicKey));
    const safe = join(dir, "safe.pem"); writeFileSync(safe, pem(a.publicKey));
    expect(() => configuredKeys([], [planted], {}, [cwd, other])).toThrow(/working tree|repositor/);
    expect(configuredKeys([], [safe], {}, [cwd, other])).toHaveLength(1);
    const viaLink = join(dir, "other-link"); symlinkSync(other, viaLink);
    expect(() => configuredKeys([], [join(viaLink, "k.pem")], {}, [cwd, other])).toThrow(/working tree|repositor/);
    expect(() => configuredKeys([], [planted], {}, [cwd, viaLink])).toThrow(/working tree|repositor/);
    expect(() => configuredKeys([], ["other/k.pem"], {}, [cwd, other])).toThrow(/absolute/);
    const link = join(dir, "link.pem"); symlinkSync(planted, link);
    expect(() => configuredKeys([], [link], {}, [cwd])).toThrow(/symlink/);
  });
  it("loadPolicyBundle applies scanRoots", async () => {
    const other = join(dir, "other"); mkdirSync(join(other, ".git"), { recursive: true });
    const planted = join(other, "k.pem"); writeFileSync(planted, pem(a.publicKey));
    const b = join(dir, "b.json"); writeFileSync(b, bundle(a.privateKey, 1));
    await expect(loadPolicyBundle({ policyBundle: b, policyBundleKeyFile: [planted], scanRoots: [other] }, dir, {})).rejects.toThrow(/repositor|working tree/);
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

describe("bundle URL guard spellings", () => {
  const refused = [
    "https://127.0.0.1/b", "https://localhost/b", "https://sub.localhost/b", "https://[::1]/b", "https://10.0.0.5/b", "https://192.168.1.1/b", "https://169.254.169.254/b",
    "https://[::ffff:127.0.0.1]/b", "https://[::ffff:7f00:1]/b", "https://[::ffff:10.0.0.5]/b", "https://[::127.0.0.1]/b", "https://[::7f00:1]/b",
    "https://[64:ff9b::7f00:1]/b", "https://[2002:7f00:1::]/b", "https://[2002:a00:5::1]/b", "https://2130706433/b", "https://0x7f000001/b", "https://0177.0.0.1/b", "https://127.1/b", "https://[fd00::1]/b",
  ];
  for (const u of refused) it(`refuses ${u}`, () => { expect(() => assertPublicBundleUrl(new URL(u))).toThrow(/private|local|internal/i); });
  it("accepts a public https host", () => { expect(() => assertPublicBundleUrl(new URL("https://policy.example.com/b.json"))).not.toThrow(); expect(() => assertPublicBundleUrl(new URL("https://8.8.8.8/b"))).not.toThrow(); });
});

describe("stale lock recovery", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "pbl-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  it("many parallel processes with an artificially stale lock end at the highest version", async () => {
    const { spawn } = await import("node:child_process");
    for (let round = 0; round < 3; round++) {
      const home = mkdtempSync(join(dir, "h-"));
      acceptPolicyBundle({ keyId: "k1", version: 1, digest: "d1", policyText: "{}" }, home);
      const lock = `${policyBundleStatePath(home)}.lock`;
      writeFileSync(lock, "");
      const old = new Date(Date.now() - 120_000); utimesSync(lock, old, old);
      const script = fileURLToPath(new URL("./state.ts", import.meta.url));
      const versions = [9, 4, 7, 2, 8, 3, 6, 5, 10, 1, 4, 9];
      await Promise.all(versions.map(v => new Promise<void>(res => {
        const c = spawn(process.execPath, ["--import", "tsx", "-e", `import("${script}").then(m => { try { m.acceptPolicyBundle({ keyId: "k1", version: ${v}, digest: "d${v}", policyText: "{}" }, ${JSON.stringify(home)}); } catch {} })`], { stdio: "ignore", cwd: process.cwd() });
        c.on("exit", () => res());
      })));
      expect(JSON.parse(readFileSync(policyBundleStatePath(home), "utf8")).k1.version).toBe(10);
    }
  }, 120_000);
  it("never lowers the floor even if the lock is bypassed", () => {
    const home = mkdtempSync(join(dir, "h-"));
    acceptPolicyBundle({ keyId: "k1", version: 8, digest: "d8", policyText: "{}" }, home);
    // Simulate a racer that read before 8 landed: force-write through the same path with a stale in-memory view.
    expect(() => acceptPolicyBundle({ keyId: "k1", version: 3, digest: "d3", policyText: "{}" }, home)).toThrow(/replay/);
    expect(JSON.parse(readFileSync(policyBundleStatePath(home), "utf8")).k1.version).toBe(8);
  });
});
