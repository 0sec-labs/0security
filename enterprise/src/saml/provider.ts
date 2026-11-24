// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// SAML 2.0 Web Browser SSO, service provider side. SP-initiated only: the AuthnRequest goes out over
// the HTTP-Redirect binding and the Response comes back over the HTTP-POST binding
// (SAML 2.0 Profiles section 4.1, Bindings sections 3.4 and 3.5).
//
// XML signature checking is done by @node-saml/node-saml and the xml-crypto it builds on. Nothing in
// this folder implements XML-DSig, canonicalisation or XML parsing of responses. What this file adds
// is the profile rules the library leaves to the caller, applied only to the assertion text the
// library returns as verified:
//   - the response is size-capped and free of DTDs, entities, comments, CDATA and processing
//     instructions before any parser sees it, and of SHA-1 and MD5 signature algorithms;
//   - the request is remembered by an opaque RelayState, once, and the response must answer it
//     (Profiles 4.1.4.2: InResponseTo; 4.1.4.5: one-time use);
//   - the assertion is addressed to this service (Audience, Recipient), comes from the configured
//     identity provider (Issuer), carries a bearer confirmation and an authentication statement,
//     and has explicit validity bounds (Profiles 4.1.4.3, Core 2.5.1).
import { randomBytes } from "node:crypto";
import { SAML, ValidateInResponseTo, generateServiceProviderMetadata } from "@node-saml/node-saml";
import { BoundedCache } from "./cache.js";
import { SamlError } from "./errors.js";
import type { IdpMetadata } from "./metadata.js";
import { assertSafeResponseXml, assertStrongSignatureAlgorithms } from "./xml-guard.js";

const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const MAX_PENDING = 1000;
const REQUEST_TTL_MS = 5 * 60 * 1000;
const MAX_ASSERTION_AGE_MS = 10 * 60 * 1000;
const MAX_RESPONSE_B64 = 700_000;
const MAX_NAME_ID = 512;

export type SignatureRequirement = "assertion" | "either";

export interface SamlSettings {
  /** The service provider entity id. It is also the only audience an assertion may name. */
  entityId: string;
  /** The assertion consumer service URL. It is also the only recipient an assertion may name. */
  acsUrl: string;
  idp: IdpMetadata;
  /** "assertion" (default): the assertion itself must be signed. "either": a signed Response is enough. */
  requireSignature?: SignatureRequirement;
  /** Allowed clock difference with the identity provider. Default 60 seconds, at most 300. */
  clockSkewMs?: number;
}

export interface SamlIdentity {
  nameId: string;
  issuer: string;
  assertionId: string;
  /** Every string value of every attribute, by attribute name. */
  attributes: Record<string, string[]>;
}

export interface SamlStart { url: string; relayState: string }

type Xml2js = Record<string, unknown>;
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : value === undefined || value === null ? [] : [value]);
const attrs = (node: unknown): Record<string, string> => ((node as { $?: Record<string, string> } | undefined)?.$ ?? {});
function text(node: unknown): string | undefined {
  if (typeof node === "string") return node;
  const value = (node as { _?: unknown } | undefined)?._;
  return typeof value === "string" ? value : undefined;
}
function child(node: unknown, name: string): unknown[] { return asArray((node as Xml2js | undefined)?.[name]); }

function instant(value: string | undefined): number | null {
  if (!value || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function fail(message: string): never { throw new SamlError("assertion-invalid", message); }

export class SamlServiceProvider {
  private readonly cache = new BoundedCache(4096);
  private readonly pending = new Map<string, { requestId: string; binding: string; expires: number }>();
  private readonly skew: number;
  private readonly requirement: SignatureRequirement;
  private readonly now: () => number;

  constructor(readonly settings: SamlSettings, options: { now?: () => number } = {}) {
    this.now = options.now ?? Date.now;
    this.skew = Math.min(Math.max(settings.clockSkewMs ?? 60_000, 0), 300_000);
    this.requirement = settings.requireSignature ?? "assertion";
    if (!settings.entityId) throw new SamlError("config", "SAML needs an SP entityId.", 400);
    new URL(settings.acsUrl);
    this.saml(() => "_probe"); // fail at start, not at the first sign-in
  }

  private saml(generateUniqueId: () => string): SAML {
    const { idp, entityId, acsUrl } = this.settings;
    return new SAML({
      callbackUrl: acsUrl,
      entryPoint: idp.ssoUrl,
      issuer: entityId,
      audience: entityId,
      idpCert: idp.certificates,
      idpIssuer: idp.entityId,
      wantAssertionsSigned: this.requirement === "assertion",
      wantAuthnResponseSigned: false, // with both off the library still demands a valid signature on the Response or the assertion
      validateInResponseTo: ValidateInResponseTo.always,
      rejectReplayedAssertions: true,
      cacheProvider: this.cache,
      acceptedClockSkewMs: this.skew,
      maxAssertionAgeMs: MAX_ASSERTION_AGE_MS,
      requestIdExpirationPeriodMs: REQUEST_TTL_MS,
      disableRequestedAuthnContext: true,
      identifierFormat: null,
      generateUniqueId,
    });
  }

  /** The service provider metadata to hand to the identity provider (Metadata 2.4.4). */
  metadataXml(): string {
    return generateServiceProviderMetadata({
      issuer: this.settings.entityId,
      callbackUrl: this.settings.acsUrl,
      wantAssertionsSigned: this.requirement === "assertion",
      identifierFormat: null,
    });
  }

  private sweep(): void {
    const t = this.now();
    for (const [key, entry] of this.pending) if (entry.expires <= t) this.pending.delete(key);
  }

  /**
   * Start a sign-in. `binding` is an opaque value the caller ties to the browser (a cookie secret);
   * it is handed back with the identity so the caller can check the same browser finishes the flow.
   * The RelayState is a random lookup key, never a URL, so it cannot be turned into a redirect.
   */
  async begin(binding: string): Promise<SamlStart> {
    this.sweep();
    if (this.pending.size >= MAX_PENDING) throw new SamlError("pending-full", "Too many pending sign-ins.", 429);
    const relayState = randomBytes(24).toString("base64url");
    let requestId = "";
    const url = await this.saml(() => (requestId = `_${randomBytes(20).toString("hex")}`)).getAuthorizeUrlAsync(relayState, undefined, {});
    this.pending.set(relayState, { requestId, binding, expires: this.now() + REQUEST_TTL_MS });
    return { url, relayState };
  }

  /** Check a POSTed response against the request it answers. Throws SamlError on any doubt. */
  async consume(form: { SAMLResponse?: unknown; RelayState?: unknown }): Promise<{ identity: SamlIdentity; binding: string }> {
    const { SAMLResponse, RelayState } = form;
    if (typeof SAMLResponse !== "string" || typeof RelayState !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(RelayState)) {
      throw new SamlError("bad-request", "The SAML response is not a valid form post.", 400);
    }
    // Used once, whether or not the response turns out to be good.
    const pending = this.pending.get(RelayState);
    this.pending.delete(RelayState);
    if (!pending || pending.expires <= this.now()) throw new SamlError("unknown-relay-state", "This sign-in was not started here, has expired or was already used.");

    if (SAMLResponse.length > MAX_RESPONSE_B64 || !/^[A-Za-z0-9+/=\s]+$/.test(SAMLResponse)) throw new SamlError("bad-request", "The SAML response is not valid base64.", 400);
    const xml = Buffer.from(SAMLResponse, "base64").toString("utf8");
    assertSafeResponseXml(xml);
    assertStrongSignatureAlgorithms(xml);

    let profile;
    try {
      const result = await this.saml(() => "_unused").validatePostResponseAsync({ SAMLResponse });
      profile = result.loggedOut ? null : result.profile;
    } catch (cause) {
      if (cause instanceof SamlError) throw cause;
      throw new SamlError("verification", cause instanceof Error ? cause.message : "SAML verification failed.");
    }
    if (!profile?.getAssertion) throw new SamlError("verification", "The response carried no assertion.");
    const identity = this.checkAssertion((profile.getAssertion() as { Assertion?: unknown }).Assertion, pending.requestId);
    return { identity, binding: pending.binding };
  }

  /** The profile rules, applied to the verified assertion only. */
  private checkAssertion(assertion: unknown, requestId: string): SamlIdentity {
    if (!assertion || typeof assertion !== "object") return fail("The assertion is missing.");
    const t = this.now();
    const id = attrs(assertion).ID;
    if (!id) fail("The assertion has no ID.");

    const issuer = child(assertion, "Issuer");
    if (issuer.length !== 1 || text(issuer[0]) !== this.settings.idp.entityId) fail("The assertion was not issued by the configured identity provider.");

    const conditions = child(assertion, "Conditions");
    if (conditions.length !== 1) fail("The assertion must have exactly one Conditions element.");
    const bounds = attrs(conditions[0]);
    const notOnOrAfter = instant(bounds.NotOnOrAfter);
    if (notOnOrAfter === null) fail("The assertion has no valid NotOnOrAfter.");
    if (t - this.skew >= notOnOrAfter!) fail("The assertion has expired.");
    if (bounds.NotBefore !== undefined) {
      const notBefore = instant(bounds.NotBefore);
      if (notBefore === null || t + this.skew < notBefore) fail("The assertion is not valid yet.");
    }
    const audiences = child(conditions[0], "AudienceRestriction");
    if (audiences.length < 1 || !audiences.every(r => child(r, "Audience").map(text).includes(this.settings.entityId))) fail("The assertion is not addressed to this service.");

    const subject = child(assertion, "Subject");
    if (subject.length !== 1) fail("The assertion must have exactly one Subject.");
    const nameIds = child(subject[0], "NameID");
    const nameId = nameIds.length === 1 ? text(nameIds[0]) : undefined;
    if (!nameId || nameId.length > MAX_NAME_ID || nameId !== nameId.trim()) fail("The assertion has no usable NameID.");

    const bearer = child(subject[0], "SubjectConfirmation").some(confirmation => {
      if (attrs(confirmation).Method !== BEARER) return false;
      const data = child(confirmation, "SubjectConfirmationData");
      if (data.length !== 1) return false;
      const a = attrs(data[0]);
      const until = instant(a.NotOnOrAfter);
      const from = a.NotBefore === undefined ? 0 : instant(a.NotBefore);
      return a.Recipient === this.settings.acsUrl && a.InResponseTo === requestId && until !== null && t - this.skew < until && from !== null && t + this.skew >= from;
    });
    if (!bearer) fail("The assertion has no bearer confirmation for this service and this sign-in request.");
    if (child(assertion, "AuthnStatement").length < 1) fail("The assertion has no authentication statement.");

    const attributes: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
    for (const statement of child(assertion, "AttributeStatement")) for (const attribute of child(statement, "Attribute")) {
      const name = attrs(attribute).Name;
      if (!name) continue;
      const values = child(attribute, "AttributeValue").map(text).filter((v): v is string => typeof v === "string" && v !== "");
      attributes[name] = [...(attributes[name] ?? []), ...values];
    }
    return { nameId, issuer: this.settings.idp.entityId, assertionId: id!, attributes };
  }
}
