// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Offline license check. A license is a signed token, `payload.signature`, both base64url.
// The payload is JSON; the signature is Ed25519 over the exact payload bytes. Verification is
// local math with the local clock. This module opens no network connection and reports nothing
// to anyone. The key comes only from the process environment (ZERO_LICENSE) or from a file whose
// path is named in the process environment (ZERO_LICENSE_FILE). A repository, a project file or
// a database cannot supply it.
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

/** The single list of paid features. Add a name here and nowhere else. */
export const ENTERPRISE_FEATURES = [
  "findings-server",
  "rbac",
  "scim",
  "saml",
  "evidence-signing",
  "audit-chain",
  "retention",
] as const;

export type EnterpriseFeature = (typeof ENTERPRISE_FEATURES)[number];

/** Where to get a license key. */
export const ENTERPRISE_URL = "https://0.security/enterprise/";

/** Days after `expires` during which paid features keep working with a warning. */
export const GRACE_DAYS = 30;

/** How far `issuedAt` may be ahead of the local clock before the key is refused. */
export const CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_LICENSE_BYTES = 16 * 1024;

/**
 * Public verification keys by key id, as base64 of the SPKI DER. Only public keys live in the
 * repository. A rotation adds a new id here and ships in a release.
 */
export const PRODUCTION_PUBLIC_KEYS: Readonly<Record<string, string>> = {
  k1: "MCowBQYDK2VwAyEAwpGf0MiOWLDJs7KDAtnswhrMaL23pqcpBUin4bUJMqY=",
};

export interface LicensePayload {
  v: 1;
  id: string;
  customer: string;
  seats: number;
  features: string[];
  issuedAt: string;
  expires: string;
  kid: string;
}

/** `valid`: before expiry. `grace`: expired less than GRACE_DAYS ago. `expired`: past grace. */
export type LicenseState = "valid" | "grace" | "expired" | "none" | "invalid";

export type LicenseFailure =
  | "missing"
  | "unreadable"
  | "malformed"
  | "unsupported-version"
  | "unknown-key"
  | "bad-signature"
  | "invalid-payload"
  | "not-yet-valid";

export interface LicenseVerdict {
  /** True when the license is genuine and paid writes are allowed (state valid or grace). */
  ok: boolean;
  state: LicenseState;
  /** Known features granted by the license. Empty unless the signature verified. */
  features: EnterpriseFeature[];
  /** Feature names in the token that this build does not know. */
  unknownFeatures: string[];
  /** ISO expiry, or null when no genuine license was read. */
  expires: string | null;
  /** ISO end of the grace period, or null. */
  graceEndsAt: string | null;
  payload: LicensePayload | null;
  reason: LicenseFailure | null;
}

export type PublicKeys = Readonly<Record<string, string>>;

function verdict(partial: Partial<LicenseVerdict> & Pick<LicenseVerdict, "state">): LicenseVerdict {
  return { ok: false, features: [], unknownFeatures: [], expires: null, graceEndsAt: null, payload: null, reason: null, ...partial };
}

function invalid(reason: LicenseFailure): LicenseVerdict {
  return verdict({ state: "invalid", reason });
}

/** Strict base64url decode: rejects anything that does not round-trip. */
function decodeBase64Url(text: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return null;
  const bytes = Buffer.from(text, "base64url");
  return bytes.toString("base64url") === text ? bytes : null;
}

function parseIso(value: unknown): number | null {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function parsePayload(bytes: Buffer): { payload: LicensePayload; issuedMs: number; expiresMs: number } | "unsupported-version" | null {
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const p = raw as Record<string, unknown>;
  if (p.v !== 1) return typeof p.v === "number" ? "unsupported-version" : null;
  const issuedMs = parseIso(p.issuedAt);
  const expiresMs = parseIso(p.expires);
  if (
    typeof p.id !== "string" || p.id === "" ||
    typeof p.customer !== "string" ||
    typeof p.kid !== "string" || p.kid === "" ||
    typeof p.seats !== "number" || !Number.isInteger(p.seats) || p.seats < 1 ||
    !Array.isArray(p.features) || !p.features.every((f) => typeof f === "string") ||
    issuedMs === null || expiresMs === null || expiresMs <= issuedMs
  ) {
    return null;
  }
  return {
    payload: { v: 1, id: p.id, customer: p.customer, seats: p.seats, features: p.features as string[], issuedAt: p.issuedAt as string, expires: p.expires as string, kid: p.kid },
    issuedMs,
    expiresMs,
  };
}

function importKey(b64: string): KeyObject | null {
  try {
    return createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

/**
 * Check a token against the public keys and the clock. Never throws.
 * `keys` defaults to the production keys; tests pass their own.
 */
export function verifyLicense(token: string, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): LicenseVerdict {
  if (typeof token !== "string" || token.trim() === "") return verdict({ state: "none", reason: "missing" });
  const parts = token.trim().split(".");
  if (parts.length !== 2) return invalid("malformed");
  const payloadBytes = decodeBase64Url(parts[0]);
  const signature = decodeBase64Url(parts[1]);
  if (!payloadBytes || !signature) return invalid("malformed");

  const parsed = parsePayload(payloadBytes);
  if (parsed === "unsupported-version") return invalid("unsupported-version");
  if (!parsed) return invalid("malformed");

  const keyText = Object.prototype.hasOwnProperty.call(keys, parsed.payload.kid) ? keys[parsed.payload.kid] : undefined;
  const key = keyText === undefined ? null : importKey(keyText);
  if (!key) return invalid("unknown-key");
  let genuine = false;
  try {
    genuine = verify(null, payloadBytes, key, signature);
  } catch {
    genuine = false;
  }
  if (!genuine) return invalid("bad-signature");

  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs)) return invalid("invalid-payload");
  if (parsed.issuedMs > nowMs + CLOCK_SKEW_MS) return invalid("not-yet-valid");

  const known = new Set<string>(ENTERPRISE_FEATURES);
  const features = [...new Set(parsed.payload.features.filter((f): f is EnterpriseFeature => known.has(f)))];
  const unknownFeatures = [...new Set(parsed.payload.features.filter((f) => !known.has(f)))];
  const graceEndMs = parsed.expiresMs + GRACE_DAYS * DAY_MS;
  const state: LicenseState = nowMs < parsed.expiresMs ? "valid" : nowMs < graceEndMs ? "grace" : "expired";
  return verdict({
    ok: state !== "expired",
    state,
    features,
    unknownFeatures,
    expires: parsed.payload.expires,
    graceEndsAt: new Date(graceEndMs).toISOString(),
    payload: parsed.payload,
  });
}

export type LicenseSource = "env" | "file" | "none";

export interface LoadedLicense extends LicenseVerdict {
  source: LicenseSource;
}

type Env = Readonly<Record<string, string | undefined>>;

/**
 * Read the license from `env` (ZERO_LICENSE, else the file named by ZERO_LICENSE_FILE) and verify it.
 * Nothing else is consulted. No key means the free behaviour.
 */
export function loadLicense(env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): LoadedLicense {
  const inline = env.ZERO_LICENSE?.trim();
  if (inline) return { ...verifyLicense(inline, now, keys), source: "env" };
  const file = env.ZERO_LICENSE_FILE?.trim();
  if (file) {
    let text: string;
    try {
      if (statSync(file).size > MAX_LICENSE_BYTES) return { ...invalid("unreadable"), source: "file" };
      text = readFileSync(file, "utf8");
    } catch {
      return { ...invalid("unreadable"), source: "file" };
    }
    return { ...verifyLicense(text, now, keys), source: "file" };
  }
  return { ...verdict({ state: "none", reason: "missing" }), source: "none" };
}

/**
 * How a feature behaves under the current license.
 * `full`: paid reads and writes. `read-only`: licensed but past grace; paid writes stop, reads,
 * export and verification keep working. `none`: not licensed.
 */
export type FeatureMode = "full" | "read-only" | "none";

export function featureMode(name: EnterpriseFeature, env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): FeatureMode {
  if (!(ENTERPRISE_FEATURES as readonly string[]).includes(name)) return "none";
  const lic = loadLicense(env, now, keys);
  if (!lic.features.includes(name)) return "none";
  return lic.ok ? "full" : "read-only";
}

/** True when paid writes for the feature are allowed (license valid or in grace). */
export function hasFeature(name: EnterpriseFeature, env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): boolean {
  return featureMode(name, env, now, keys) === "full";
}

const FEATURE_LABELS: Record<EnterpriseFeature, string> = {
  "findings-server": "the shared findings server",
  rbac: "role-based access control",
  scim: "SCIM provisioning",
  saml: "SAML sign-in",
  "evidence-signing": "signed evidence bundles",
  "audit-chain": "the tamper-evident audit log",
  retention: "retention policies",
};

/** User-facing message for a feature that is not available, or null when it is. */
export function requireFeature(name: EnterpriseFeature, env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): string | null {
  const label = FEATURE_LABELS[name] ?? name;
  const lic = loadLicense(env, now, keys);
  const mode = featureMode(name, env, now, keys);
  if (mode === "full") return null;
  if (mode === "read-only") {
    return `Your 0security enterprise license expired on ${lic.expires?.slice(0, 10)}. ${label[0].toUpperCase()}${label.slice(1)} is read-only until you renew. Your data stays readable and exportable. Renew at ${ENTERPRISE_URL}`;
  }
  if (lic.state === "invalid") {
    return `The 0security enterprise license is not valid (${lic.reason}). ${label[0].toUpperCase()}${label.slice(1)} needs a valid enterprise license. Get a key at ${ENTERPRISE_URL}`;
  }
  if (lic.state === "none") {
    return `${label[0].toUpperCase()}${label.slice(1)} needs an enterprise license. Get a key at ${ENTERPRISE_URL}, then set ZERO_LICENSE or ZERO_LICENSE_FILE.`;
  }
  return `Your 0security enterprise license does not include ${label}. Contact us at ${ENTERPRISE_URL}`;
}

export class EnterpriseLicenseError extends Error {
  readonly feature: EnterpriseFeature;
  constructor(feature: EnterpriseFeature, message: string) {
    super(message);
    this.name = "EnterpriseLicenseError";
    this.feature = feature;
  }
}

/** Throwing form of requireFeature. */
export function assertFeature(name: EnterpriseFeature, env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): void {
  const message = requireFeature(name, env, now, keys);
  if (message) throw new EnterpriseLicenseError(name, message);
}

export interface LicenseStatus {
  state: LicenseState;
  source: LicenseSource;
  customer: string | null;
  licenseId: string | null;
  seats: number | null;
  features: EnterpriseFeature[];
  unknownFeatures: string[];
  issuedAt: string | null;
  expires: string | null;
  graceEndsAt: string | null;
  /** Whole days until expiry (negative once expired); null without a genuine license. */
  daysToExpiry: number | null;
  reason: LicenseFailure | null;
}

/** Diagnostics for `config get license` and the startup line. Contains no secret. */
export function licenseStatus(env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS): LicenseStatus {
  const lic = loadLicense(env, now, keys);
  const expiresMs = lic.expires ? Date.parse(lic.expires) : null;
  return {
    state: lic.state,
    source: lic.source,
    customer: lic.payload?.customer ?? null,
    licenseId: lic.payload?.id ?? null,
    seats: lic.payload?.seats ?? null,
    features: lic.features,
    unknownFeatures: lic.unknownFeatures,
    issuedAt: lic.payload?.issuedAt ?? null,
    expires: lic.expires,
    graceEndsAt: lic.graceEndsAt,
    daysToExpiry: expiresMs === null ? null : Math.floor((expiresMs - now.getTime()) / DAY_MS),
    reason: lic.reason,
  };
}

/** Plain-text lines for the CLI and the startup log. */
export function formatLicenseStatus(status: LicenseStatus): string[] {
  if (status.state === "none") return ["License: none (free features only)", `Enterprise features need a key: ${ENTERPRISE_URL}`];
  if (status.state === "invalid") return [`License: not valid (${status.reason})`, `Get a key at ${ENTERPRISE_URL}`];
  const lines = [
    `License: ${status.state}`,
    `Customer: ${status.customer}`,
    `Seats: ${status.seats}`,
    `Features: ${status.features.length ? status.features.join(", ") : "none"}`,
    `Expires: ${status.expires?.slice(0, 10)}`,
  ];
  if (status.state === "grace") lines.push(`Grace: paid features keep working until ${status.graceEndsAt?.slice(0, 10)}. Renew at ${ENTERPRISE_URL}`);
  if (status.state === "expired") lines.push(`Expired: paid writes are stopped. Reads, export and verification still work. Renew at ${ENTERPRISE_URL}`);
  return lines;
}
