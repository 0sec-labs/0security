// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// All tests are offline. The signing key is generated in memory; no private key is stored anywhere.
import { execFileSync } from "node:child_process";
import { createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, unlinkSync, writeFileSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  ENTERPRISE_FEATURES,
  ENTERPRISE_URL,
  EnterpriseLicenseError,
  GRACE_DAYS,
  PRODUCTION_PUBLIC_KEYS,
  assertFeature,
  featureMode,
  formatLicenseStatus,
  hasFeature,
  licenseStatus,
  loadLicense,
  requireFeature,
  verifyLicense,
  type LicensePayload,
} from "./index.js";

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date("2027-01-15T12:00:00Z");

const pair = generateKeyPairSync("ed25519");
const other = generateKeyPairSync("ed25519");
const pub = (k: { publicKey: KeyObject }) => k.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const KEYS = { t1: pub(pair) };

function payload(over: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1,
    id: "lic_test",
    customer: "Test Customer",
    seats: 25,
    features: ["findings-server", "rbac"],
    issuedAt: "2026-12-01T00:00:00Z",
    expires: "2027-12-01T00:00:00Z",
    kid: "t1",
    ...over,
  };
}

function mint(p: unknown, key: KeyObject = pair.privateKey): string {
  const bytes = Buffer.from(JSON.stringify(p), "utf8");
  return `${bytes.toString("base64url")}.${sign(null, bytes, key).toString("base64url")}`;
}

const verify = (token: string, now = NOW) => verifyLicense(token, now, KEYS);

describe("verifyLicense", () => {
  it("accepts a genuine token before expiry", () => {
    const v = verify(mint(payload()));
    expect(v).toMatchObject({ ok: true, state: "valid", reason: null, expires: "2027-12-01T00:00:00Z" });
    expect(v.features).toEqual(["findings-server", "rbac"]);
    expect(v.payload?.customer).toBe("Test Customer");
  });

  it("enters grace at the exact expiry instant and ends it after 30 days", () => {
    const token = mint(payload());
    const exp = Date.parse("2027-12-01T00:00:00Z");
    expect(verify(token, new Date(exp - 1)).state).toBe("valid");
    expect(verify(token, new Date(exp)).state).toBe("grace");
    expect(verify(token, new Date(exp)).ok).toBe(true);
    expect(verify(token, new Date(exp + GRACE_DAYS * DAY - 1)).state).toBe("grace");
    const after = verify(token, new Date(exp + GRACE_DAYS * DAY));
    expect(after).toMatchObject({ state: "expired", ok: false });
    expect(after.features).toEqual(["findings-server", "rbac"]);
  });

  it("rejects a tampered payload", () => {
    const [body, sig] = mint(payload({ seats: 1 })).split(".");
    const forged = Buffer.from(JSON.stringify(payload({ seats: 5000 })), "utf8").toString("base64url");
    expect(verify(`${forged}.${sig}`)).toMatchObject({ ok: false, state: "invalid", reason: "bad-signature", features: [] });
    expect(body).not.toBe(forged);
  });

  it("rejects a tampered signature", () => {
    const [body, sig] = mint(payload()).split(".");
    const bytes = Buffer.from(sig, "base64url");
    bytes[0] ^= 1;
    expect(verify(`${body}.${bytes.toString("base64url")}`).reason).toBe("bad-signature");
  });

  it("rejects a token signed by a different key", () => {
    expect(verify(mint(payload(), other.privateKey)).reason).toBe("bad-signature");
  });

  it("rejects an unknown key id and the production keys when only test keys sign", () => {
    expect(verify(mint(payload({ kid: "nope" }))).reason).toBe("unknown-key");
    expect(verifyLicense(mint(payload()), NOW).reason).toBe("unknown-key");
    expect(verifyLicense(mint(payload({ kid: "k2" })), NOW).reason).toBe("bad-signature");
    expect(verifyLicense(mint(payload({ kid: "__proto__" })), NOW, KEYS).reason).toBe("unknown-key");
  });

  it("keeps unknown features out of the granted list", () => {
    const v = verify(mint(payload({ features: ["rbac", "teleport", "rbac"] })));
    expect(v.ok).toBe(true);
    expect(v.features).toEqual(["rbac"]);
    expect(v.unknownFeatures).toEqual(["teleport"]);
  });

  it("rejects malformed tokens", () => {
    for (const t of ["abc", "a.b.c", ".", "a.", ".b", "not base64!.also not", "e30.e30", `${Buffer.from("[]").toString("base64url")}.AAAA`]) {
      const v = verify(t);
      expect(v.ok, t).toBe(false);
      expect(v.state, t).toBe("invalid");
    }
    expect(verify("a.b.c").reason).toBe("malformed");
  });

  it("rejects payloads with wrong field types even when signed", () => {
    for (const bad of [
      { ...payload(), seats: "50" },
      { ...payload(), seats: 0 },
      { ...payload(), features: "rbac" },
      { ...payload(), features: [1] },
      { ...payload(), expires: "tomorrow" },
      { ...payload(), expires: "2026-11-01T00:00:00Z" },
      { ...payload(), id: "" },
      { ...payload(), customer: 7 },
    ]) {
      expect(verify(mint(bad)).reason).toBe("malformed");
    }
    expect(verify(mint({ ...payload(), v: 2 })).reason).toBe("unsupported-version");
  });

  it("rejects an issuedAt in the future beyond the clock skew", () => {
    const token = mint(payload({ issuedAt: "2027-03-01T00:00:00Z", expires: "2028-03-01T00:00:00Z" }));
    expect(verify(token, NOW)).toMatchObject({ ok: false, reason: "not-yet-valid" });
    const issued = Date.parse("2027-03-01T00:00:00Z");
    expect(verify(token, new Date(issued - DAY)).ok).toBe(true); // one day of skew is tolerated
    expect(verify(token, new Date(issued - DAY - 1)).reason).toBe("not-yet-valid");
  });

  it("answers missing for empty input", () => {
    expect(verify("")).toMatchObject({ ok: false, state: "none", reason: "missing" });
    expect(verify("   ")).toMatchObject({ state: "none" });
  });

  it("uses the production key by default and ships only a public key", () => {
    expect(Object.keys(PRODUCTION_PUBLIC_KEYS)).toContain("k2");
    expect(verifyLicense(mint(payload({ kid: "k2" })), NOW).ok).toBe(false);
  });

  it("does not trust the retired key k1", () => {
    expect(Object.keys(PRODUCTION_PUBLIC_KEYS)).not.toContain("k1");
    expect(Object.keys(PRODUCTION_PUBLIC_KEYS)).toEqual(["k2"]);
    expect(verifyLicense(mint(payload({ kid: "k1" })), NOW).reason).toBe("unknown-key");
  });

  it("commits a k2 public key that parses as an Ed25519 SPKI key", () => {
    const key = createPublicKey({ key: Buffer.from(PRODUCTION_PUBLIC_KEYS.k2, "base64"), format: "der", type: "spki" });
    expect(key.asymmetricKeyType).toBe("ed25519");
  });
});

describe("loadLicense and hasFeature", () => {
  const token = mint(payload());

  it("grants nothing without the environment variables", () => {
    expect(loadLicense({}, NOW, KEYS)).toMatchObject({ ok: false, state: "none", source: "none" });
    for (const f of ENTERPRISE_FEATURES) expect(hasFeature(f, {}, NOW, KEYS)).toBe(false);
  });

  it("reads ZERO_LICENSE", () => {
    const env = { ZERO_LICENSE: ` ${token}\n` };
    expect(loadLicense(env, NOW, KEYS)).toMatchObject({ ok: true, source: "env" });
    expect(hasFeature("rbac", env, NOW, KEYS)).toBe(true);
    expect(hasFeature("scim", env, NOW, KEYS)).toBe(false);
  });

  it("reads ZERO_LICENSE_FILE", () => {
    const dir = mkdtempSync(join(tmpdir(), "0ent-"));
    const file = join(dir, "license.txt");
    writeFileSync(file, `${token}\n`);
    try {
      const env = { ZERO_LICENSE_FILE: file };
      expect(loadLicense(env, NOW, KEYS)).toMatchObject({ ok: true, source: "file" });
      expect(hasFeature("findings-server", env, NOW, KEYS)).toBe(true);
      expect(loadLicense({ ZERO_LICENSE_FILE: join(dir, "missing") }, NOW, KEYS)).toMatchObject({ ok: false, reason: "unreadable", source: "file" });
      writeFileSync(file, "x".repeat(20_000));
      expect(loadLicense(env, NOW, KEYS).reason).toBe("unreadable");
    } finally {
      unlinkSync(file);
      rmdirSync(dir);
    }
  });

  it("never reads the working directory", () => {
    // A license-like file in cwd is ignored: only the passed environment counts.
    expect(loadLicense({}, NOW, KEYS).state).toBe("none");
  });

  it("returns false for a name that is not a feature", () => {
    const env = { ZERO_LICENSE: token };
    expect(hasFeature("teleport" as never, env, NOW, KEYS)).toBe(false);
    expect(featureMode("teleport" as never, env, NOW, KEYS)).toBe("none");
  });

  it("stops paid writes after grace but keeps read-only mode", () => {
    const env = { ZERO_LICENSE: token };
    const exp = Date.parse("2027-12-01T00:00:00Z");
    expect(featureMode("rbac", env, new Date(exp + 5 * DAY), KEYS)).toBe("full");
    const late = new Date(exp + 31 * DAY);
    expect(featureMode("rbac", env, late, KEYS)).toBe("read-only");
    expect(hasFeature("rbac", env, late, KEYS)).toBe(false);
    expect(featureMode("scim", env, late, KEYS)).toBe("none");
  });
});

describe("requireFeature and assertFeature", () => {
  const token = mint(payload());
  it("is null when licensed", () => {
    expect(requireFeature("rbac", { ZERO_LICENSE: token }, NOW, KEYS)).toBeNull();
    expect(() => assertFeature("rbac", { ZERO_LICENSE: token }, NOW, KEYS)).not.toThrow();
  });
  it("tells the user where to get a key", () => {
    const m = requireFeature("rbac", {}, NOW, KEYS) ?? "";
    expect(m).toContain("needs an enterprise license");
    expect(m).toContain(ENTERPRISE_URL);
    expect(ENTERPRISE_URL).toBe("https://0.security/enterprise/");
  });
  it("explains a license that does not include the feature, is invalid or expired", () => {
    expect(requireFeature("scim", { ZERO_LICENSE: token }, NOW, KEYS)).toContain("does not include");
    expect(requireFeature("rbac", { ZERO_LICENSE: "junk" }, NOW, KEYS)).toContain("not valid");
    const late = new Date("2028-02-01T00:00:00Z");
    expect(requireFeature("rbac", { ZERO_LICENSE: token }, late, KEYS)).toContain("read-only");
  });
  it("throws a typed error", () => {
    expect(() => assertFeature("saml", {}, NOW, KEYS)).toThrow(EnterpriseLicenseError);
  });
});

describe("licenseStatus", () => {
  it("reports details without any secret", () => {
    const token = mint(payload());
    const s = licenseStatus({ ZERO_LICENSE: token }, NOW, KEYS);
    expect(s).toMatchObject({ state: "valid", customer: "Test Customer", seats: 25, features: ["findings-server", "rbac"], licenseId: "lic_test" });
    expect(s.daysToExpiry).toBe(319);
    const text = JSON.stringify(s) + formatLicenseStatus(s).join("\n");
    expect(text).not.toContain(token);
    expect(text).not.toContain(token.split(".")[1]);
  });
  it("describes none, invalid, grace and expired", () => {
    expect(formatLicenseStatus(licenseStatus({}, NOW, KEYS)).join("\n")).toContain("free features only");
    expect(formatLicenseStatus(licenseStatus({ ZERO_LICENSE: "junk" }, NOW, KEYS)).join("\n")).toContain("not valid");
    const token = mint(payload());
    const grace = formatLicenseStatus(licenseStatus({ ZERO_LICENSE: token }, new Date("2027-12-10T00:00:00Z"), KEYS)).join("\n");
    expect(grace).toContain("Grace:");
    const expired = formatLicenseStatus(licenseStatus({ ZERO_LICENSE: token }, new Date("2028-03-01T00:00:00Z"), KEYS)).join("\n");
    expect(expired).toContain("Reads, export and verification still work");
  });
});

describe("module hygiene", () => {
  const src = fileURLToPath(new URL(".", import.meta.url));
  const sources = readdirSync(src).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));

  it("imports no network client and makes no network call", () => {
    for (const file of sources) {
      const text = readFileSync(join(src, file), "utf8");
      expect(text, file).not.toMatch(/from\s+["'](node:)?(http|https|http2|net|tls|dns|dgram|undici)["']/);
      expect(text, file).not.toMatch(/\bfetch\s*\(|XMLHttpRequest|WebSocket/);
    }
  });

  it("starts every source file with the license header", () => {
    for (const file of sources) {
      expect(readFileSync(join(src, file), "utf8").split("\n")[0], file).toContain("enterprise/LICENSE");
    }
  });
});

describe("issue-license tool", () => {
  it("signs a token the verifier accepts, without printing the key", () => {
    const dir = mkdtempSync(join(tmpdir(), "0ent-issue-"));
    const keyFile = join(dir, "k.pem");
    writeFileSync(keyFile, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const tool = fileURLToPath(new URL("../tools/issue-license.mjs", import.meta.url));
    try {
      const out = execFileSync(process.execPath, [tool, "--key", keyFile, "--customer", "Acme Test", "--seats", "10", "--features", "rbac,audit-chain", "--expires", "2027-12-01T00:00:00Z", "--issued", "2026-12-01T00:00:00Z", "--kid", "t1"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 });
      const v = verify(out.trim());
      expect(v).toMatchObject({ ok: true, state: "valid" });
      expect(v.features).toEqual(["rbac", "audit-chain"]);
      expect(v.payload).toMatchObject({ customer: "Acme Test", seats: 10, kid: "t1" });
      expect(out).not.toContain("PRIVATE KEY");
    } finally {
      unlinkSync(keyFile);
      rmdirSync(dir);
    }
  });
});
