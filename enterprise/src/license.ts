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
  "ha",
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
 * repository. A rotation adds a new id here and ships in a release. The first key (k1) was retired before any
 * license was issued, so it is not trusted.
 */
export const PRODUCTION_PUBLIC_KEYS: Readonly<Record<string, string>> = {
  k2: "MCowBQYDK2VwAyEAUxEPtyoYm5GKqhDt8/eTJ6URcS8Gl/Gkm1ipEF26pNU=",
};

export interface LicensePayloadV1 {
  v: 1;
  id: string;
  customer: string;
  seats: number;
  features: string[];
  issuedAt: string;
  expires: string;
  kid: string;
}

/** Limits of one entitlement, for example `{ repos: 200 }`. Names are free; values are whole numbers of 0 or more. */
export type EntitlementLimits = Readonly<Record<string, number>>;

/** Components that may honour a token. Unknown names are kept, so new components need no release. */
export const LICENSE_AUDIENCES = ["cli", "hub", "brain", "runner"] as const;

export interface LicensePayloadV2 {
  v: 2;
  id: string;
  customer: string;
  plan: string;
  seats: number;
  /** Components allowed to honour this token. */
  aud: string[];
  /** Entitlement name to its limits. An empty object means no limit beyond the grant. */
  entitlements: Record<string, EntitlementLimits>;
  issuedAt: string;
  /** Not valid before this time. */
  nbf: string;
  expires: string;
  kid: string;
  /** Revocation id. Defaults to `id` when the token omits it. */
  rid: string;
}

export type LicensePayload = LicensePayloadV1 | LicensePayloadV2;

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
  | "not-yet-valid"
  | "audience-mismatch";

export interface LicenseVerdict {
  /** True when the license is genuine and paid writes are allowed (state valid or grace). */
  ok: boolean;
  state: LicenseState;
  /** Known features granted by the license. Empty unless the signature verified. */
  features: EnterpriseFeature[];
  /** Feature names in the token that this build does not know. */
  unknownFeatures: string[];
  /** Limits per known entitlement (v1 tokens grant every feature with no limits). Empty unless the signature verified. */
  entitlements: Record<string, EntitlementLimits>;
  /** ISO expiry, or null when no genuine license was read. */
  expires: string | null;
  /** ISO end of the grace period, or null. */
  graceEndsAt: string | null;
  payload: LicensePayload | null;
  reason: LicenseFailure | null;
}

export type PublicKeys = Readonly<Record<string, string>>;

function verdict(partial: Partial<LicenseVerdict> & Pick<LicenseVerdict, "state">): LicenseVerdict {
  return { ok: false, features: [], unknownFeatures: [], entitlements: {}, expires: null, graceEndsAt: null, payload: null, reason: null, ...partial };
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

interface Parsed {
  payload: LicensePayload;
  issuedMs: number;
  expiresMs: number;
  nbfMs: number | null;
  /** Granted names in token order, with their limits. */
  grants: [string, EntitlementLimits][];
}

function parseLimits(value: unknown): EntitlementLimits | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(value)) {
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return null;
    out[k] = n;
  }
  return out;
}

function parsePayload(bytes: Buffer): Parsed | "unsupported-version" | null {
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const p = raw as Record<string, unknown>;
  if (p.v !== 1 && p.v !== 2) return typeof p.v === "number" ? "unsupported-version" : null;
  const issuedMs = parseIso(p.issuedAt);
  const expiresMs = parseIso(p.expires);
  if (
    typeof p.id !== "string" || p.id === "" ||
    typeof p.customer !== "string" ||
    typeof p.kid !== "string" || p.kid === "" ||
    typeof p.seats !== "number" || !Number.isInteger(p.seats) || p.seats < 1 ||
    issuedMs === null || expiresMs === null || expiresMs <= issuedMs
  ) {
    return null;
  }
  if (p.v === 1) {
    if (!Array.isArray(p.features) || !p.features.every((f) => typeof f === "string")) return null;
    const features = p.features as string[];
    return {
      payload: { v: 1, id: p.id, customer: p.customer, seats: p.seats, features, issuedAt: p.issuedAt as string, expires: p.expires as string, kid: p.kid },
      issuedMs,
      expiresMs,
      nbfMs: null,
      grants: features.map((f): [string, EntitlementLimits] => [f, {}]),
    };
  }
  const nbfMs = parseIso(p.nbf);
  if (
    typeof p.plan !== "string" || p.plan === "" ||
    !Array.isArray(p.aud) || p.aud.length === 0 || !p.aud.every((a) => typeof a === "string" && a !== "") ||
    nbfMs === null || nbfMs >= expiresMs ||
    (p.rid !== undefined && (typeof p.rid !== "string" || p.rid === "")) ||
    typeof p.entitlements !== "object" || p.entitlements === null || Array.isArray(p.entitlements)
  ) {
    return null;
  }
  const entitlements: Record<string, EntitlementLimits> = {};
  for (const [name, value] of Object.entries(p.entitlements)) {
    const limits = parseLimits(value);
    if (!limits) return null;
    entitlements[name] = limits;
  }
  return {
    payload: {
      v: 2, id: p.id, customer: p.customer, plan: p.plan, seats: p.seats, aud: p.aud as string[], entitlements,
      issuedAt: p.issuedAt as string, nbf: p.nbf as string, expires: p.expires as string, kid: p.kid, rid: (p.rid as string | undefined) ?? p.id,
    },
    issuedMs,
    expiresMs,
    nbfMs,
    grants: Object.entries(entitlements),
  };
}

function importKey(b64: string): KeyObject | null {
  try {
    return createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

export interface VerifyOptions {
  /** The component asking (cli, hub, brain, runner). A v2 token whose `aud` omits it is refused. v1 tokens carry no audience and pass. */
  audience?: string;
}

/**
 * Check a token against the public keys and the clock. Never throws.
 * `keys` defaults to the production keys; tests pass their own.
 */
export function verifyLicense(token: string, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS, options: VerifyOptions = {}): LicenseVerdict {
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
  if (parsed.nbfMs !== null && parsed.nbfMs > nowMs + CLOCK_SKEW_MS) return invalid("not-yet-valid");
  if (parsed.payload.v === 2 && options.audience !== undefined && !parsed.payload.aud.includes(options.audience)) return invalid("audience-mismatch");

  const known = new Set<string>(ENTERPRISE_FEATURES);
  const entitlements: Record<string, EntitlementLimits> = {};
  const unknownFeatures: string[] = [];
  for (const [name, limits] of parsed.grants) {
    if (!known.has(name)) {
      if (!unknownFeatures.includes(name)) unknownFeatures.push(name);
    } else if (!(name in entitlements)) entitlements[name] = limits;
  }
  const features = Object.keys(entitlements) as EnterpriseFeature[];
  const graceEndMs = parsed.expiresMs + GRACE_DAYS * DAY_MS;
  const state: LicenseState = nowMs < parsed.expiresMs ? "valid" : nowMs < graceEndMs ? "grace" : "expired";
  return verdict({
    ok: state !== "expired",
    state,
    features,
    unknownFeatures,
    entitlements,
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
export function loadLicense(env: Env = process.env, now: Date = new Date(), keys: PublicKeys = PRODUCTION_PUBLIC_KEYS, options: VerifyOptions = {}): LoadedLicense {
  const inline = env.ZERO_LICENSE?.trim();
  if (inline) return { ...verifyLicense(inline, now, keys, options), source: "env" };
  const file = env.ZERO_LICENSE_FILE?.trim();
  if (file) {
    let text: string;
    try {
      if (statSync(file).size > MAX_LICENSE_BYTES) return { ...invalid("unreadable"), source: "file" };
      text = readFileSync(file, "utf8");
    } catch {
      return { ...invalid("unreadable"), source: "file" };
    }
    return { ...verifyLicense(text, now, keys, options), source: "file" };
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

/**
 * Limit `limit` of a granted entitlement, or undefined when the license grants no such limit.
 * Offline checkers treat it as a hard cap; the CLI shows a banner instead of stopping.
 */
export function entitlementLimit(lic: Pick<LicenseVerdict, "entitlements">, name: string, limit: string): number | undefined {
  const limits = Object.prototype.hasOwnProperty.call(lic.entitlements, name) ? lic.entitlements[name] : undefined;
  return limits !== undefined && Object.prototype.hasOwnProperty.call(limits, limit) ? limits[limit] : undefined;
}

const FEATURE_LABELS: Record<EnterpriseFeature, string> = {
  "findings-server": "the shared findings server",
  rbac: "role-based access control",
  scim: "SCIM provisioning",
  saml: "SAML sign-in",
  "evidence-signing": "evidence signing",
  "audit-chain": "the tamper-evident audit log",
  retention: "retention policies",
  ha: "high availability with a shared database",
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
  /** v2 tokens only. */
  plan: string | null;
  /** Revocation id (v2; for v1 the license id). */
  rid: string | null;
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
    plan: lic.payload?.v === 2 ? lic.payload.plan : null,
    rid: lic.payload ? (lic.payload.v === 2 ? lic.payload.rid : lic.payload.id) : null,
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
    ...(status.plan ? [`Plan: ${status.plan}`] : []),
    `Features: ${status.features.length ? status.features.join(", ") : "none"}`,
    `Expires: ${status.expires?.slice(0, 10)}`,
  ];
  if (status.state === "grace") lines.push(`Grace: paid features keep working until ${status.graceEndsAt?.slice(0, 10)}. Renew at ${ENTERPRISE_URL}`);
  if (status.state === "expired") lines.push(`Expired: paid writes are stopped. Reads, export and verification still work. Renew at ${ENTERPRISE_URL}`);
  return lines;
}
