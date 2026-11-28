#!/usr/bin/env node
// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Regenerates license-vectors.json, the contract every license checker must pass (this repo's
// enterprise/src/license.ts and the closed entitlements package, which copies the file).
//   node enterprise/test-vectors/generate.mjs           write license-vectors.json
//   node enterprise/test-vectors/generate.mjs --check   exit 1 when the file on disk differs
// The signing key is derived from a fixed public test seed so the output is reproducible (Ed25519
// is deterministic). It trusts nothing: its public key is listed only inside the vectors file.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const out = fileURLToPath(new URL("./license-vectors.json", import.meta.url));
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const seed = Buffer.alloc(32, 7);
const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
const pubB64 = createPublicKey(priv).export({ type: "spki", format: "der" }).toString("base64");

const NOW = "2027-01-15T12:00:00Z";
const day = (iso, n) => new Date(Date.parse(iso) + n * 86400000).toISOString().replace(/\.\d+Z$/, "Z");

const mint = (payload, key = priv) => {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  return `${bytes.toString("base64url")}.${sign(null, bytes, key).toString("base64url")}`;
};
const v1 = (over = {}) => ({ v: 1, id: "lic_v1", customer: "Vector Customer", seats: 25, features: ["findings-server", "rbac"], issuedAt: "2026-12-01T00:00:00Z", expires: "2027-12-01T00:00:00Z", kid: "t1", ...over });
const v2 = (over = {}) => ({
  v: 2, id: "lic_v2", customer: "Vector Customer", plan: "team", seats: 25, aud: ["cli", "hub"],
  entitlements: { "findings-server": {}, saml: {}, ha: { nodes: 3 } },
  issuedAt: "2026-12-01T00:00:00Z", nbf: "2026-12-01T00:00:00Z", expires: "2027-12-01T00:00:00Z", kid: "t1", rid: "rid_v2", ...over,
});
const tamper = (token) => {
  const [p, s] = token.split(".");
  const b = Buffer.from(s, "base64url");
  b[0] ^= 1;
  return `${p}.${b.toString("base64url")}`;
};
const wrongKid = (over) => v2({ kid: "nope", ...over });

const cases = [
  { name: "v1 valid", token: mint(v1()), expect: { ok: true, state: "valid", reason: null, features: ["findings-server", "rbac"], unknownFeatures: [], entitlements: { "findings-server": {}, rbac: {} }, expires: "2027-12-01T00:00:00Z" } },
  { name: "v1 audience is not checked", audience: "brain", token: mint(v1()), expect: { ok: true, state: "valid", reason: null, features: ["findings-server", "rbac"] } },
  { name: "v1 expired within grace", now: "2027-12-10T00:00:00Z", token: mint(v1()), expect: { ok: true, state: "grace", reason: null, features: ["findings-server", "rbac"], graceEndsAt: "2027-12-31T00:00:00.000Z" } },
  { name: "v1 expired past grace", now: "2028-02-01T00:00:00Z", token: mint(v1()), expect: { ok: false, state: "expired", reason: null, features: ["findings-server", "rbac"] } },
  { name: "v1 unknown feature ignored", token: mint(v1({ features: ["rbac", "future-thing"] })), expect: { ok: true, state: "valid", features: ["rbac"], unknownFeatures: ["future-thing"] } },
  { name: "v2 valid", audience: "cli", token: mint(v2()), expect: { ok: true, state: "valid", reason: null, features: ["findings-server", "saml", "ha"], unknownFeatures: [], entitlements: { "findings-server": {}, saml: {}, ha: { nodes: 3 } }, expires: "2027-12-01T00:00:00Z", plan: "team", rid: "rid_v2" } },
  { name: "v2 valid without an asking component", token: mint(v2()), expect: { ok: true, state: "valid", reason: null } },
  { name: "v2 rid defaults to id", token: mint((({ rid, ...rest }) => rest)(v2())), expect: { ok: true, state: "valid", rid: "lic_v2" } },
  { name: "v2 expired within grace", now: "2027-12-10T00:00:00Z", audience: "hub", token: mint(v2()), expect: { ok: true, state: "grace", reason: null, features: ["findings-server", "saml", "ha"], graceEndsAt: "2027-12-31T00:00:00.000Z" } },
  { name: "v2 expired past grace", now: "2028-02-01T00:00:00Z", audience: "hub", token: mint(v2()), expect: { ok: false, state: "expired", reason: null } },
  { name: "v2 bad signature", token: tamper(mint(v2())), expect: { ok: false, state: "invalid", reason: "bad-signature", features: [] } },
  { name: "v2 signed by another key", token: mint(v2(), createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, 9)]), format: "der", type: "pkcs8" })), expect: { ok: false, state: "invalid", reason: "bad-signature" } },
  { name: "v2 wrong kid", token: mint(wrongKid()), expect: { ok: false, state: "invalid", reason: "unknown-key", features: [] } },
  { name: "v2 unknown entitlement ignored", token: mint(v2({ entitlements: { saml: {}, "future-thing": { widgets: 5 }, "bb-managed": { repos: 200 } } })), expect: { ok: true, state: "valid", features: ["saml"], unknownFeatures: ["future-thing", "bb-managed"], entitlements: { saml: {} } } },
  { name: "v2 audience mismatch", audience: "brain", token: mint(v2()), expect: { ok: false, state: "invalid", reason: "audience-mismatch", features: [] } },
  { name: "v2 nbf in the future", token: mint(v2({ nbf: day(NOW, 10) })), expect: { ok: false, state: "invalid", reason: "not-yet-valid", features: [] } },
  { name: "v2 nbf reached", now: day(NOW, 10), token: mint(v2({ nbf: day(NOW, 10), expires: day(NOW, 400) })), expect: { ok: true, state: "valid" } },
  { name: "v2 negative limit is malformed", token: mint(v2({ entitlements: { saml: { repos: -1 } } })), expect: { ok: false, state: "invalid", reason: "malformed" } },
  { name: "v2 empty audience is malformed", token: mint(v2({ aud: [] })), expect: { ok: false, state: "invalid", reason: "malformed" } },
  { name: "unsupported version", token: mint({ ...v2(), v: 3 }), expect: { ok: false, state: "invalid", reason: "unsupported-version" } },
];

const doc = {
  description: "License token vectors. A checker passes when, for every case, verifying `token` at `now` (default defaultNow) against `keys`, with `audience` when present, yields every field listed in `expect` (deep equality per field). `known` is the entitlement list the checker is built with; any other name must land in unknownFeatures and be otherwise ignored. Regenerate with node enterprise/test-vectors/generate.mjs; the key is a public test seed and signs nothing real.",
  defaultNow: NOW,
  keys: { t1: pubB64 },
  known: ["findings-server", "rbac", "scim", "saml", "evidence-signing", "audit-chain", "retention", "ha"],
  cases: cases.map((c) => ({ ...c, now: c.now ?? NOW })),
};
const text = `${JSON.stringify(doc, null, 2)}\n`;
if (process.argv.includes("--check")) {
  let disk = "";
  try { disk = readFileSync(out, "utf8"); } catch {}
  if (disk !== text) {
    console.error("license-vectors.json is stale; run node enterprise/test-vectors/generate.mjs");
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out} (${cases.length} cases)`);
}
