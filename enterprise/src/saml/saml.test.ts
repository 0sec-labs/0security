// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { describe, expect, it } from "vitest";
import { SamlError, SamlServiceProvider, parseIdpMetadata } from "./index.js";
import { assertNoDtd, assertSafeResponseXml, assertStrongSignatureAlgorithms } from "./xml-guard.js";
import { BoundedCache } from "./cache.js";
import { TestIdp, makeKey, readAuthnRequest, type ResponseOptions } from "./idp.testkit.js";

const idp = new TestIdp();

function provider(options: { requireSignature?: "assertion" | "either"; clockSkewMs?: number } = {}): SamlServiceProvider {
  return new SamlServiceProvider({ ...idp.sp, idp: parseIdpMetadata(idp.metadataXml()), ...options });
}

/** Start a sign-in and return what the identity provider would see. */
async function start(sp: SamlServiceProvider, binding = "browser-1") {
  const { url, relayState } = await sp.begin(binding);
  const request = await readAuthnRequest(url);
  return { url, relayState, request };
}

async function login(sp: SamlServiceProvider, o: Partial<ResponseOptions> = {}, post: (xml: string) => string = x => x) {
  const { relayState, request } = await start(sp);
  const xml = post(idp.response({ requestId: request.id, ...o }));
  return sp.consume({ SAMLResponse: TestIdp.encode(xml), RelayState: relayState });
}

const reason = async (promise: Promise<unknown>): Promise<string> => {
  try { await promise; } catch (error) { return error instanceof SamlError ? error.reason : `non-saml:${String(error)}`; }
  return "accepted";
};

describe("SP-initiated login", () => {
  it("sends an AuthnRequest over HTTP-Redirect and accepts a signed assertion over HTTP-POST", async () => {
    const sp = provider();
    const { url, request, relayState } = await start(sp);
    expect(url.startsWith(`${idp.ssoUrl}?`)).toBe(true);
    expect(request).toMatchObject({ destination: idp.ssoUrl, issuer: idp.sp.entityId, acsUrl: idp.sp.acsUrl });
    expect(request.id).toMatch(/^_[0-9a-f]{40}$/);
    expect(relayState).toMatch(/^[A-Za-z0-9_-]{32}$/);
    const result = await sp.consume({ SAMLResponse: TestIdp.encode(idp.response({ requestId: request.id, attributes: { groups: ["sec-owners", "everyone"] } })), RelayState: relayState });
    expect(result.binding).toBe("browser-1");
    expect(result.identity).toMatchObject({ nameId: "alex@corp.test", issuer: idp.entityId });
    expect(result.identity.attributes.groups).toEqual(["sec-owners", "everyone"]);
  });

  it("accepts a signed Response only when the operator allows it", async () => {
    expect(await reason(login(provider(), { sign: "response" }))).toBe("verification");
    const result = await login(provider({ requireSignature: "either" }), { sign: "response" });
    expect(result.identity.nameId).toBe("alex@corp.test");
  });

  it("accepts both signed", async () => { expect((await login(provider(), { sign: "both" })).identity.nameId).toBe("alex@corp.test"); });

  it("reads Okta and Entra style attribute names", async () => {
    const entra = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
    const result = await login(provider(), { attributes: { [entra]: ["0d4c6e8e-0000-0000-0000-000000000001"], groups: ["Everyone"] } });
    expect(result.identity.attributes[entra]).toEqual(["0d4c6e8e-0000-0000-0000-000000000001"]);
    expect(result.identity.attributes.groups).toEqual(["Everyone"]);
  });
});

describe("signature attacks", () => {
  it("rejects an unsigned assertion and an unsigned response", async () => {
    expect(await reason(login(provider(), { sign: "none" }))).toBe("verification");
    expect(await reason(login(provider({ requireSignature: "either" }), { sign: "none" }))).toBe("verification");
  });

  it("rejects a tampered assertion", async () => {
    expect(await reason(login(provider(), {}, xml => xml.replace("alex@corp.test", "admin@corp.test")))).toBe("verification");
    expect(await reason(login(provider(), { attributes: { groups: ["viewers"] } }, xml => xml.replace(">viewers<", ">owners<")))).toBe("verification");
  });

  it("rejects an assertion signed by another key", async () => {
    expect(await reason(login(provider(), { signWith: makeKey("attacker") }))).toBe("verification");
  });

  it("rejects a SHA-1 signature", async () => {
    expect(await reason(login(provider(), { weakSignature: true }))).toBe("weak-algorithm");
  });

  it("rejects signature wrapping: unsigned assertion first, the signed one second", async () => {
    const sp = provider();
    const { relayState, request } = await start(sp);
    const signed = idp.sign(idp.assertionXml({ requestId: request.id }), "Assertion");
    const evil = idp.assertionXml({ requestId: request.id, nameId: "admin@corp.test", assertionId: "_evil" });
    const xml = idp.wrap(evil + signed, { requestId: request.id });
    expect(await reason(sp.consume({ SAMLResponse: TestIdp.encode(xml), RelayState: relayState }))).toBe("verification");
  });

  it("rejects signature wrapping: the signed assertion hidden inside an unsigned one", async () => {
    const sp = provider();
    const { relayState, request } = await start(sp);
    const signed = idp.sign(idp.assertionXml({ requestId: request.id }), "Assertion");
    const evil = idp.assertionXml({ requestId: request.id, nameId: "admin@corp.test", assertionId: "_evil" }).replace("<saml:AuthnStatement", `<saml:Advice>${signed}</saml:Advice><saml:AuthnStatement`);
    const xml = idp.wrap(evil, { requestId: request.id });
    expect(await reason(sp.consume({ SAMLResponse: TestIdp.encode(xml), RelayState: relayState }))).toBe("verification");
  });

  it("rejects a valid signature copied onto a different assertion", async () => {
    const sp = provider();
    const { relayState, request } = await start(sp);
    const signed = idp.sign(idp.assertionXml({ requestId: request.id, assertionId: "_good" }), "Assertion");
    const signature = /<ds:Signature[\s\S]*<\/ds:Signature>|<Signature[\s\S]*<\/Signature>/.exec(signed)![0];
    const evil = idp.assertionXml({ requestId: request.id, nameId: "admin@corp.test", assertionId: "_good" }).replace("</saml:Issuer>", `</saml:Issuer>${signature}`);
    const xml = idp.wrap(evil, { requestId: request.id });
    expect(await reason(sp.consume({ SAMLResponse: TestIdp.encode(xml), RelayState: relayState }))).toBe("verification");
  });
});

describe("XML attacks", () => {
  it("rejects a comment injected into the NameID, even when the IdP signed it", async () => {
    expect(await reason(login(provider(), { nameIdXml: "admin@corp.test<!---->.evil.example" }))).toBe("xml-comment");
  });

  it("rejects a DTD with an external entity before it is parsed", async () => {
    const prolog = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`;
    expect(await reason(login(provider(), { prolog, nameIdXml: "&xxe;" }))).toBe("xml-dtd");
    expect(await reason(login(provider(), { prolog: `<!DOCTYPE r>` }))).toBe("xml-dtd");
  });

  it("rejects entity expansion, CDATA and processing instructions", () => {
    expect(() => assertNoDtd(`<a>&lol9;</a>`)).toThrow(SamlError);
    expect(() => assertSafeResponseXml(`<a><![CDATA[x]]></a>`)).toThrow(SamlError);
    expect(() => assertSafeResponseXml(`<a><?pi x?></a>`)).toThrow(SamlError);
    expect(() => assertSafeResponseXml(`<?xml version="1.0"?><a>&amp;&#65;&#x41;</a>`)).not.toThrow();
    expect(() => assertSafeResponseXml(`\uFEFF<?xml version="1.0" encoding="UTF-8"?><a/>`)).not.toThrow();
  });

  it("rejects DTD, comment and encoding variants", () => {
    for (const xml of [`<!doctype a><a/>`, `<!DocType a [ ]><a/>`, `<!ENTITY x "y"><a/>`, `<a><!-- x --></a>`, `<a><!----></a>`, `<?xml version="1.0" encoding="UTF-16"?><a/>`, `<?xml version='1.0' encoding='iso-8859-1'?><a/>`, `<a>\u0000</a>`, `<a><?xml-stylesheet href="x"?></a>`]) {
      expect(() => assertSafeResponseXml(xml), xml).toThrow(SamlError);
    }
    const utf16 = Buffer.from(`\uFEFF<a/>`, "utf16le").toString("utf8");
    expect(() => assertSafeResponseXml(utf16)).toThrow(SamlError);
  });

  it("allows only listed signature algorithms, read from the parsed document", () => {
    const ds = (tag: string, algorithm: string) => `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:${tag} Algorithm="${algorithm}"/></ds:SignedInfo></ds:Signature>`;
    const sha1Sig = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    const ok = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    expect(() => assertStrongSignatureAlgorithms(ds("SignatureMethod", ok))).not.toThrow();
    expect(() => assertStrongSignatureAlgorithms(ds("SignatureMethod", sha1Sig))).toThrow(/not allowed/);
    // decimal, hex, mixed, case and doubled-encoding spellings of the same weak algorithm
    for (const spelled of [
      "http://www.w3.org/2000/09/xmldsig#rsa-&#115;ha1", "http://www.w3.org/2000/09/xmldsig#rsa-&#x73;ha1", "http://www.w3.org/2000/09/xmldsig#rsa-&#X73;&#104;a1",
      "http://www.w3.org/2000/09/xmldsig#rsa-SHA1", "http://www.w3.org/2000/09/xmldsig#rsa-sha&#49;", "&#104;ttp://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "http://www.w3.org/2000/09/xmldsig#rsa-&amp;#115;ha1", "http://www.w3.org/2000/09/xmldsig#rsa-md5", "", "urn:unknown",
    ]) expect(() => assertStrongSignatureAlgorithms(ds("SignatureMethod", spelled)), spelled).toThrow(/not allowed/);
    expect(() => assertStrongSignatureAlgorithms(ds("DigestMethod", "http://www.w3.org/2000/09/xmldsig#sha1"))).toThrow(/not allowed/);
    expect(() => assertStrongSignatureAlgorithms(ds("DigestMethod", "http://www.w3.org/2000/09/xmldsig#&#115;ha1"))).toThrow(/not allowed/);
    expect(() => assertStrongSignatureAlgorithms(ds("DigestMethod", "http://www.w3.org/2001/04/xmlenc#sha256"))).not.toThrow();
    expect(() => assertStrongSignatureAlgorithms(ds("CanonicalizationMethod", "http://www.w3.org/2001/10/xml-exc-c14n#"))).not.toThrow();
    expect(() => assertStrongSignatureAlgorithms(ds("Transform", "http://www.w3.org/TR/1999/REC-xpath-19991116"))).toThrow(/not allowed/);
    expect(() => assertStrongSignatureAlgorithms(`<a><b`)).toThrow(SamlError);
  });

  it("rejects a validly SHA-1-signed assertion even when 'sha1' is spelled with character references", async () => {
    for (const encode of [(t: string) => t.replace(/sha1/g, "&#115;ha1"), (t: string) => t.replace(/sha1/g, "&#x73;&#x68;a&#49;")]) {
      const sp = provider();
      const { relayState, request } = await start(sp);
      const signed = idp.response({ requestId: request.id, weakSignature: true });
      const spelled = encode(signed);
      expect(spelled).not.toBe(signed);
      expect(spelled).not.toMatch(/sha1/);
      try { await sp.consume({ SAMLResponse: TestIdp.encode(spelled), RelayState: relayState }); expect.unreachable(); } catch (error) { expect((error as SamlError).reason).toBe("weak-algorithm"); }
    }
  });

  it("rejects an oversized or malformed body", async () => {
    const sp = provider();
    const { relayState } = await start(sp);
    expect(await reason(sp.consume({ SAMLResponse: "A".repeat(800_000), RelayState: relayState }))).toBe("bad-request");
    const second = await start(sp);
    expect(await reason(sp.consume({ SAMLResponse: "not base64 !!", RelayState: second.relayState }))).toBe("bad-request");
    const third = await start(sp);
    expect(await reason(sp.consume({ SAMLResponse: Buffer.from("<not xml").toString("base64"), RelayState: third.relayState }))).toBe("xml-unsafe");
  });
});

describe("assertion rules", () => {
  it("rejects an expired assertion and one that is not valid yet", async () => {
    expect(await reason(login(provider(), { notOnOrAfter: new Date(Date.now() - 600_000), subjectNotOnOrAfter: new Date(Date.now() - 600_000) }))).toBe("verification");
    expect(await reason(login(provider(), { notBefore: new Date(Date.now() + 600_000) }))).toBe("verification");
  });

  it("allows a small clock skew and no more", async () => {
    const soon = new Date(Date.now() + 20_000);
    expect((await login(provider({ clockSkewMs: 60_000 }), { notBefore: soon })).identity.nameId).toBe("alex@corp.test");
    expect(await reason(login(provider({ clockSkewMs: 5_000 }), { notBefore: new Date(Date.now() + 20_000) }))).toBe("verification");
  });

  it("requires an expiry on the conditions", async () => {
    expect(await reason(login(provider(), { omitConditionsExpiry: true }))).toBe("verification");
  });

  it("rejects a wrong audience", async () => {
    expect(await reason(login(provider(), { audience: "https://other.test/saml" }))).toBe("verification");
  });

  it("rejects a wrong recipient", async () => {
    expect(await reason(login(provider(), { recipient: "https://evil.test/api/team/auth/saml/acs" }))).toBe("assertion-invalid");
  });

  it("rejects a wrong issuer", async () => {
    expect(await reason(login(provider(), { issuer: "https://evil.test/entity" }))).toBe("verification");
  });

  it("rejects a response to a different request", async () => {
    const sp = provider();
    const a = await start(sp);
    const b = await start(sp);
    const xml = idp.response({ requestId: a.request.id });
    expect(await reason(sp.consume({ SAMLResponse: TestIdp.encode(xml), RelayState: b.relayState }))).toBe("assertion-invalid");
  });

  it("rejects an unsolicited response (no InResponseTo, IdP-initiated)", async () => {
    expect(await reason(login(provider(), { omitInResponseTo: true }))).toBe("verification");
  });

  it("rejects a response with no authentication statement", async () => {
    expect(await reason(login(provider(), { omitAuthnStatement: true }))).toBe("assertion-invalid");
  });
});

describe("one-time use and replay", () => {
  it("accepts a response once", async () => {
    const sp = provider();
    const { relayState, request } = await start(sp);
    const body = { SAMLResponse: TestIdp.encode(idp.response({ requestId: request.id })), RelayState: relayState };
    expect((await sp.consume(body)).identity.nameId).toBe("alex@corp.test");
    expect(await reason(sp.consume(body))).toBe("unknown-relay-state");
  });

  it("spends the sign-in even when the first attempt fails", async () => {
    const sp = provider();
    const { relayState, request } = await start(sp);
    const bad = { SAMLResponse: TestIdp.encode(idp.response({ requestId: request.id, sign: "none" })), RelayState: relayState };
    expect(await reason(sp.consume(bad))).toBe("verification");
    const good = { SAMLResponse: TestIdp.encode(idp.response({ requestId: request.id })), RelayState: relayState };
    expect(await reason(sp.consume(good))).toBe("unknown-relay-state");
  });

  it("remembers assertion ids: a second sign-in cannot reuse one", async () => {
    const sp = provider();
    const first = await login(sp, { assertionId: "_same-assertion" });
    expect(first.identity.assertionId).toBe("_same-assertion");
    expect(await reason(login(sp, { assertionId: "_same-assertion" }))).toBe("verification");
  });

  it("expires pending sign-ins", async () => {
    let now = Date.now();
    const sp = new SamlServiceProvider({ ...idp.sp, idp: parseIdpMetadata(idp.metadataXml()) }, { now: () => now });
    const { relayState, request } = await start(sp);
    now += 6 * 60 * 1000;
    expect(await reason(sp.consume({ SAMLResponse: TestIdp.encode(idp.response({ requestId: request.id })), RelayState: relayState }))).toBe("unknown-relay-state");
  });

  it("bounds pending sign-ins per client and in total", async () => {
    const sp = provider();
    for (let i = 0; i < 20; i++) await sp.begin("b", "203.0.113.1");
    expect(await reason(sp.begin("b", "203.0.113.1"))).toBe("pending-full");
    await sp.begin("b", "203.0.113.2"); // another client is not locked out by the first
  }, 120_000);

  it("takes the pending slot before awaiting, so parallel starts cannot pass the caps", async () => {
    const sp = provider();
    const results = await Promise.allSettled(Array.from({ length: 60 }, () => sp.begin("b", "198.51.100.7")));
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(20);
    expect(results.filter(r => r.status === "rejected")).toHaveLength(40);
  }, 120_000);

  it("enforces the global cap under parallel starts", async () => {
    const sp = provider();
    const results = await Promise.allSettled(Array.from({ length: 1100 }, (_, i) => sp.begin("b", `c${i}`)));
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1000);
    expect(await reason(sp.begin("b", "late"))).toBe("pending-full");
  }, 180_000);
});

describe("RelayState", () => {
  it("is an opaque key: a forged, guessed or URL-shaped value is refused", async () => {
    const sp = provider();
    const { request } = await start(sp);
    const SAMLResponse = TestIdp.encode(idp.response({ requestId: request.id }));
    expect(await reason(sp.consume({ SAMLResponse, RelayState: "https://evil.test/" }))).toBe("bad-request");
    expect(await reason(sp.consume({ SAMLResponse, RelayState: "/admin" }))).toBe("bad-request");
    expect(await reason(sp.consume({ SAMLResponse, RelayState: "A".repeat(32) }))).toBe("unknown-relay-state");
    expect(await reason(sp.consume({ SAMLResponse }))).toBe("bad-request");
    expect(await reason(sp.consume({ SAMLResponse, RelayState: ["x"] }))).toBe("bad-request");
  });

  it("hands back only the browser binding it was given", async () => {
    const sp = provider();
    const { relayState, request } = await start(sp, "secret-for-this-browser");
    const result = await sp.consume({ SAMLResponse: TestIdp.encode(idp.response({ requestId: request.id })), RelayState: relayState });
    expect(result.binding).toBe("secret-for-this-browser");
  });
});

describe("metadata", () => {
  it("reads the redirect endpoint, entity id and signing certificate", () => {
    const meta = parseIdpMetadata(idp.metadataXml());
    expect(meta).toMatchObject({ entityId: idp.entityId, ssoUrl: idp.ssoUrl });
    expect(meta.certificates).toEqual([idp.key.pem]);
  });
  it("refuses a DTD, a missing certificate, a missing redirect endpoint and a plain http endpoint", () => {
    expect(() => parseIdpMetadata(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` + idp.metadataXml())).toThrow(/DTD/);
    expect(() => parseIdpMetadata(idp.metadataXml().replace(/<ds:X509Certificate>.*<\/ds:X509Certificate>/, ""))).toThrow(/signing certificate/);
    expect(() => parseIdpMetadata(idp.metadataXml({ redirect: false }))).toThrow(/Redirect/);
    expect(() => parseIdpMetadata(idp.metadataXml({ ssoUrl: "http://idp.test/sso" }))).toThrow(/HTTPS/);
    expect(() => parseIdpMetadata("<md:EntityDescriptor")).toThrow(/well-formed/);
    expect(() => parseIdpMetadata(idp.metadataXml().replace("MIIC", "@@@@"))).toThrow(SamlError);
  });
  it("accepts certificate text that carries line-break character references", () => {
    const meta = parseIdpMetadata(idp.metadataXml().replace(/(<ds:X509Certificate>)(.{64})/, "$1$2&#13;\n"));
    expect(meta.certificates).toEqual([idp.key.pem]);
  });
  it("describes this service for the identity provider", () => {
    const xml = provider().metadataXml();
    expect(xml).toContain(`entityID="${idp.sp.entityId}"`);
    expect(xml).toContain(`Location="${idp.sp.acsUrl}"`);
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    expect(xml).toContain('WantAssertionsSigned="true"');
  });
});

describe("bounded cache", () => {
  it("stops growing at its limit and forgets expired entries", async () => {
    let now = 0;
    const cache = new BoundedCache(2, () => now);
    await cache.saveAsync("a", "1");
    await cache.saveAsync("b", "2");
    await expect(cache.saveAsync("c", "3")).rejects.toThrow(/Too many/);
    now += 11 * 60 * 1000;
    await cache.saveAsync("c", "3");
    expect(await cache.getAsync("a")).toBeNull();
    expect(await cache.consumeAsync("c")).toBe("3");
    expect(await cache.consumeAsync("c")).toBeNull();
    expect(await cache.saveIfAbsentAsync("k", "v", now + 1000)).toBe(true);
    expect(await cache.saveIfAbsentAsync("k", "v", now + 1000)).toBe(false);
  });
});
