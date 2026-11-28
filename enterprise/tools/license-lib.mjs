// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Shared by issue-license.mjs and sign-revocations.mjs. The private key is read from a file path
// that the caller passes in. Nothing here reads the environment.
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

export const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
export const AUDIENCES = ["cli", "hub", "brain", "runner"];
export const NAME = /^[a-z][a-z0-9-]{0,62}$/;
/** Days a token lives for each billing term. Short terms are the only mitigation for an offline token that cannot be revoked. */
export const TERM_DAYS = { monthly: 35, annual: 400 };
const DAY_MS = 86400000;

export class ToolError extends Error {}

export const isoNow = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
export const addDays = (iso, days) => new Date(Date.parse(iso) + days * DAY_MS).toISOString().replace(/\.\d+Z$/, "Z");

/** Read an Ed25519 private key from a file. Warns on stderr when the file is readable by others. */
export function readPrivateKey(file, warn = (m) => console.error(m)) {
  if (!file) throw new ToolError("--key <private-key-file> is required");
  let key;
  try {
    if ((statSync(file).mode & 0o077) !== 0) warn(`warning: ${file} is readable by other users; chmod 600 it`);
    key = createPrivateKey(readFileSync(file));
  } catch {
    throw new ToolError("could not read an Ed25519 private key from the --key file");
  }
  if (key.asymmetricKeyType !== "ed25519") throw new ToolError("the key must be Ed25519");
  return key;
}

/** Canonical token: payload bytes are the JSON as given (callers pass a fixed key order), signed as is. */
export function signToken(payload, key) {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  return `${bytes.toString("base64url")}.${sign(null, bytes, key).toString("base64url")}`;
}

/** Verify `payload.signature` against a base64 SPKI public key. Returns the parsed payload or null. */
export function openToken(token, publicKeyB64) {
  const parts = token.trim().split(".");
  if (parts.length !== 2) return null;
  try {
    const bytes = Buffer.from(parts[0], "base64url");
    const key = createPublicKey({ key: Buffer.from(publicKeyB64.trim(), "base64"), format: "der", type: "spki" });
    if (!verify(null, bytes, key, Buffer.from(parts[1], "base64url"))) return null;
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
}

const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);

/** Build a v2 payload from a customer file's parsed JSON. Throws ToolError on any problem. */
export function buildV2Payload(c, defaults) {
  if (!isObject(c)) throw new ToolError("the customer file must hold a JSON object");
  const customer = c.customer;
  if (typeof customer !== "string" || customer.trim() === "") throw new ToolError("customer is required");
  if (typeof c.plan !== "string" || c.plan === "") throw new ToolError("plan is required (for example team)");
  if (!Number.isInteger(c.seats) || c.seats < 1) throw new ToolError("seats must be a whole number of 1 or more");
  if (!Array.isArray(c.aud) || c.aud.length === 0) throw new ToolError(`aud is required, a list of ${AUDIENCES.join(", ")}`);
  for (const a of c.aud) if (!AUDIENCES.includes(a)) throw new ToolError(`unknown audience "${a}" (known: ${AUDIENCES.join(", ")})`);
  if (!isObject(c.entitlements) || Object.keys(c.entitlements).length === 0) throw new ToolError("entitlements is required, for example {\"saml\": {}, \"bb-managed\": {\"repos\": 200}}");
  const entitlements = {};
  for (const [name, limits] of Object.entries(c.entitlements)) {
    if (!NAME.test(name)) throw new ToolError(`bad entitlement name "${name}"`);
    if (!isObject(limits)) throw new ToolError(`entitlement "${name}" must map to an object of limits`);
    const out = {};
    for (const [k, n] of Object.entries(limits)) {
      if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,62}$/.test(k)) throw new ToolError(`bad limit name "${k}" in "${name}"`);
      if (!Number.isInteger(n) || n < 0) throw new ToolError(`limit "${name}.${k}" must be a whole number of 0 or more`);
      out[k] = n;
    }
    entitlements[name] = out;
  }
  const issuedAt = c.issuedAt ?? defaults.issuedAt;
  if (!ISO.test(issuedAt)) throw new ToolError("issuedAt must be an ISO UTC time like 2027-01-01T00:00:00Z");
  const nbf = c.nbf ?? issuedAt;
  if (!ISO.test(nbf)) throw new ToolError("nbf must be an ISO UTC time");
  let expires = c.expires;
  if (expires === undefined) {
    if (!(c.term in TERM_DAYS)) throw new ToolError(`give expires, or term: ${Object.keys(TERM_DAYS).join(" or ")}`);
    expires = addDays(issuedAt, TERM_DAYS[c.term]);
  } else if (c.term !== undefined) throw new ToolError("give expires or term, not both");
  if (!ISO.test(expires)) throw new ToolError("expires must be an ISO UTC time");
  if (Date.parse(expires) <= Date.parse(issuedAt)) throw new ToolError("expires must be after issuedAt");
  if (Date.parse(nbf) >= Date.parse(expires)) throw new ToolError("nbf must be before expires");
  const id = c.id ?? defaults.id;
  const rid = c.rid ?? id;
  for (const [k, v] of [["id", id], ["rid", rid], ["kid", c.kid ?? defaults.kid]]) if (typeof v !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(v)) throw new ToolError(`bad ${k}`);
  // Fixed key order, no whitespace: the signature covers exactly these bytes.
  return { v: 2, id, customer, plan: c.plan, seats: c.seats, aud: [...new Set(c.aud)], entitlements, issuedAt, nbf, expires, kid: c.kid ?? defaults.kid, rid };
}

/** Build a revocation list payload. `entries` is a list of { rid, effective }. */
export function buildRevocationPayload({ kid, seq, issuedAt, entries }) {
  if (typeof kid !== "string" || kid === "") throw new ToolError("--kid is required");
  if (!Number.isInteger(seq) || seq < 1) throw new ToolError("--seq must be a whole number of 1 or more, higher than the last published list");
  if (!ISO.test(issuedAt)) throw new ToolError("--issued must be an ISO UTC time");
  if (!Array.isArray(entries)) throw new ToolError("entries must be a list");
  const byRid = new Map();
  for (const e of entries) {
    if (!isObject(e) || typeof e.rid !== "string" || e.rid === "") throw new ToolError("every entry needs a rid");
    if (typeof e.effective !== "string" || !ISO.test(e.effective)) throw new ToolError(`entry ${e.rid}: effective must be an ISO UTC time`);
    const have = byRid.get(e.rid);
    if (have === undefined || Date.parse(e.effective) < Date.parse(have)) byRid.set(e.rid, e.effective);
  }
  return { v: 1, kind: "revocations", kid, seq, issuedAt, entries: [...byRid].sort(([a], [b]) => (a < b ? -1 : 1)).map(([rid, effective]) => ({ rid, effective })) };
}
