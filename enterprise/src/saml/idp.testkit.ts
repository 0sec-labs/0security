// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Test identity provider. Generates a throwaway RSA key and certificate and writes real, signed SAML
// responses with the same xml-crypto the service provider verifies with. Never shipped: excluded from
// the build and used only by tests.
import { createSign, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { SignedXml } from "xml-crypto";

const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

// --- minimal DER writer, enough for a self-signed certificate -------------------------------------
const len = (n: number): Buffer => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (tag: number, ...parts: Buffer[]): Buffer => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(body.length), body]); };
const seq = (...p: Buffer[]) => tlv(0x30, ...p);
const oid = (bytes: number[]) => tlv(0x06, Buffer.from(bytes));
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s));
const utc = (d: Date) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));

function selfSignedCertificate(publicKey: KeyObject, privateKey: KeyObject, commonName: string): string {
  const rsaSha256 = seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), tlv(0x05));
  const name = seq(tlv(0x31, seq(oid([0x55, 0x04, 0x03]), utf8(commonName))));
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, Buffer.from([1, ...randomBytes(8)].map((b, i) => (i === 1 ? b & 0x7f : b)))),
    rsaSha256, name,
    seq(utc(new Date(Date.now() - 86_400_000)), utc(new Date(Date.now() + 365 * 86_400_000))),
    name, publicKey.export({ type: "spki", format: "der" }),
  );
  const signature = createSign("sha256").update(tbs).sign(privateKey);
  const der = seq(tbs, rsaSha256, tlv(0x03, Buffer.from([0]), signature));
  return der.toString("base64");
}

export interface TestKey { publicKey: KeyObject; privateKey: KeyObject; certificateBase64: string; pem: string }

export function makeKey(commonName = "test-idp"): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const certificateBase64 = selfSignedCertificate(publicKey, privateKey, commonName);
  return { publicKey, privateKey, certificateBase64, pem: `-----BEGIN CERTIFICATE-----\n${certificateBase64.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n` };
}

export interface ResponseOptions {
  requestId: string;
  nameId?: string;
  /** Raw XML placed inside NameID instead of `nameId` (for injection tests). */
  nameIdXml?: string;
  issuer?: string;
  audience?: string;
  recipient?: string;
  assertionId?: string;
  notBefore?: Date;
  notOnOrAfter?: Date;
  subjectNotOnOrAfter?: Date;
  attributes?: Record<string, string[]>;
  /** Which element carries a signature. Default "assertion". */
  sign?: "assertion" | "response" | "both" | "none";
  signWith?: TestKey;
  weakSignature?: boolean;
  omitInResponseTo?: boolean;
  omitAuthnStatement?: boolean;
  omitConditionsExpiry?: boolean;
  /** Text placed before the root element, for DTD tests. */
  prolog?: string;
}

const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

export class TestIdp {
  readonly key = makeKey();
  constructor(readonly entityId = "https://idp.test/entity", readonly ssoUrl = "https://idp.test/sso", readonly sp = { entityId: "https://0.test/saml", acsUrl: "https://0.test/api/team/auth/saml/acs" }) {}

  metadataXml(options: { key?: TestKey; redirect?: boolean; ssoUrl?: string } = {}): string {
    const key = options.key ?? this.key;
    return `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${this.entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="${SAMLP}"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${key.certificateBase64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>${options.redirect === false ? "" : `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${options.ssoUrl ?? this.ssoUrl}"/>`}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${this.ssoUrl}/post"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
  }

  assertionXml(o: ResponseOptions): string {
    const now = Date.now();
    const notBefore = o.notBefore ?? new Date(now - 30_000);
    const notOnOrAfter = o.notOnOrAfter ?? new Date(now + 300_000);
    const id = o.assertionId ?? `_a${randomBytes(8).toString("hex")}`;
    const attributes = Object.entries(o.attributes ?? {}).map(([name, values]) => `<saml:Attribute Name="${esc(name)}">${values.map(v => `<saml:AttributeValue>${esc(v)}</saml:AttributeValue>`).join("")}</saml:Attribute>`).join("");
    return `<saml:Assertion xmlns:saml="${SAML}" ID="${id}" Version="2.0" IssueInstant="${iso(new Date(now))}">` +
      `<saml:Issuer>${o.issuer ?? this.entityId}</saml:Issuer>` +
      `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.nameIdXml ?? esc(o.nameId ?? "alex@corp.test")}</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${o.omitInResponseTo ? "" : ` InResponseTo="${o.requestId}"`} NotOnOrAfter="${iso(o.subjectNotOnOrAfter ?? notOnOrAfter)}" Recipient="${o.recipient ?? this.sp.acsUrl}"/></saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${iso(notBefore)}"${o.omitConditionsExpiry ? "" : ` NotOnOrAfter="${iso(notOnOrAfter)}"`}><saml:AudienceRestriction><saml:Audience>${o.audience ?? this.sp.entityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
      (o.omitAuthnStatement ? "" : `<saml:AuthnStatement AuthnInstant="${iso(new Date(now))}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`) +
      (attributes ? `<saml:AttributeStatement>${attributes}</saml:AttributeStatement>` : "") +
      `</saml:Assertion>`;
  }

  /** Sign the element named by `localName` (the document root of `xml`), placing the signature after its Issuer. */
  sign(xml: string, localName: "Assertion" | "Response", options: { key?: TestKey; weak?: boolean } = {}): string {
    const key = options.key ?? this.key;
    const sig = new SignedXml({
      privateKey: key.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      publicCert: key.pem,
      signatureAlgorithm: options.weak ? RSA_SHA1 : RSA_SHA256,
      canonicalizationAlgorithm: EXC_C14N,
    });
    sig.addReference({ xpath: `/*[local-name(.)='${localName}']`, transforms: [ENVELOPED, EXC_C14N], digestAlgorithm: options.weak ? SHA1 : SHA256 });
    sig.computeSignature(xml, { location: { reference: `/*[local-name(.)='${localName}']/*[local-name(.)='Issuer']`, action: "after" } });
    return sig.getSignedXml();
  }

  /** Wrap an assertion in a Response. `inner` is the serialised assertion (signed or not). */
  wrap(inner: string, o: Pick<ResponseOptions, "requestId" | "issuer" | "omitInResponseTo" | "prolog">): string {
    const id = `_r${randomBytes(8).toString("hex")}`;
    return `${o.prolog ?? ""}<samlp:Response xmlns:samlp="${SAMLP}" xmlns:saml="${SAML}" ID="${id}" Version="2.0" IssueInstant="${iso(new Date())}" Destination="${this.sp.acsUrl}"${o.omitInResponseTo ? "" : ` InResponseTo="${o.requestId}"`}>` +
      `<saml:Issuer>${o.issuer ?? this.entityId}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${inner}</samlp:Response>`;
  }

  response(o: ResponseOptions): string {
    const mode = o.sign ?? "assertion";
    let assertion = this.assertionXml(o);
    if (mode === "assertion" || mode === "both") assertion = this.sign(assertion, "Assertion", { key: o.signWith, weak: o.weakSignature });
    let response = this.wrap(assertion, o);
    if (mode === "response" || mode === "both") response = this.sign(response, "Response", { key: o.signWith, weak: o.weakSignature });
    return response;
  }

  /** What a browser would POST: base64 of the response. */
  static encode(xml: string): string { return Buffer.from(xml, "utf8").toString("base64"); }
}

/** The AuthnRequest id and fields carried in a redirect URL produced by the service provider. */
export async function readAuthnRequest(redirectUrl: string): Promise<{ id: string; destination: string; issuer: string; acsUrl: string; relayState: string; xml: string }> {
  const { inflateRawSync } = await import("node:zlib");
  const url = new URL(redirectUrl);
  const xml = inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest")!, "base64")).toString("utf8");
  const pick = (re: RegExp) => re.exec(xml)?.[1] ?? "";
  return {
    id: pick(/\bID="([^"]+)"/), destination: pick(/\bDestination="([^"]+)"/), acsUrl: pick(/AssertionConsumerServiceURL="([^"]+)"/),
    issuer: pick(/<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/), relayState: url.searchParams.get("RelayState") ?? "", xml,
  };
}
