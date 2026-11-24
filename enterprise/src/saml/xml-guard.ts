// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Refuses XML that SAML never needs and attackers like. Checked on the raw text before any parser or
// signature library sees it, so a parser difference cannot hide anything from these rules.
import { DOMParser } from "@xmldom/xmldom";
import { SamlError } from "./errors.js";

/** Largest decoded SAML response or metadata document accepted. Real responses are a few kilobytes. */
export const MAX_SAML_XML_BYTES = 512 * 1024;

// A document type declaration is how XXE, entity expansion and external subsets are written.
const DTD = /<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)/i;
// Only the five predefined entities and numeric references are legal without a DTD.
const UNKNOWN_ENTITY = /&(?!(?:amp|lt|gt|quot|apos|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});)/;

/** Refuse a DTD, an unknown entity reference and control bytes. Used for metadata and responses. */
export function assertNoDtd(xml: string): void {
  if (xml.length > MAX_SAML_XML_BYTES) throw new SamlError("xml-too-large", "The SAML message is too large.", 400);
  if (xml.includes("\u0000")) throw new SamlError("xml-unsafe", "The SAML message contains a NUL character.", 400);
  if (DTD.test(xml)) throw new SamlError("xml-dtd", "The SAML message contains a DTD, which is not allowed.", 400);
  if (UNKNOWN_ENTITY.test(xml)) throw new SamlError("xml-dtd", "The SAML message uses an entity reference that is not allowed.", 400);
}

/**
 * Stricter rules for a login response. No comments, CDATA sections or processing instructions:
 * identity providers do not emit them, and a comment inside a NameID is the classic way to make two
 * parsers read two different users out of one signed value.
 */
export function assertSafeResponseXml(xml: string): void {
  assertNoDtd(xml);
  if (xml.includes("<!--")) throw new SamlError("xml-comment", "The SAML message contains an XML comment, which is not allowed.", 400);
  if (xml.includes("<![CDATA[")) throw new SamlError("xml-unsafe", "The SAML message contains a CDATA section, which is not allowed.", 400);
  const declared = /^\uFEFF?\s*<\?xml\s[^>]*?encoding\s*=\s*["']([^"']+)["']/.exec(xml)?.[1];
  if (declared && declared.toLowerCase() !== "utf-8") throw new SamlError("xml-unsafe", "The SAML message must be UTF-8.", 400);
  // Only a leading XML declaration may use <? ... ?>.
  const withoutDeclaration = xml.replace(/^﻿?\s*<\?xml\s[^>]*\?>/, "");
  if (withoutDeclaration.includes("<?")) throw new SamlError("xml-unsafe", "The SAML message contains a processing instruction, which is not allowed.", 400);
}

const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
// Allow-list, compared against the decoded attribute value in the parsed document. Anything not listed is
// refused, so no spelling of SHA-1, MD5 or an unknown algorithm gets through, whatever encoding it uses.
const SIGNATURE_METHODS = new Set([
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
  "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
]);
const DIGEST_METHODS = new Set([
  "http://www.w3.org/2001/04/xmlenc#sha256",
  "http://www.w3.org/2001/04/xmldsig-more#sha384",
  "http://www.w3.org/2001/04/xmlenc#sha512",
]);
const CANONICALIZATION_METHODS = new Set([
  "http://www.w3.org/2001/10/xml-exc-c14n#",
  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
  "http://www.w3.org/2006/12/xml-c14n11",
]);
const TRANSFORMS = new Set(["http://www.w3.org/2000/09/xmldsig#enveloped-signature", ...CANONICALIZATION_METHODS]);
const ALLOWED: Record<string, Set<string>> = { SignatureMethod: SIGNATURE_METHODS, DigestMethod: DIGEST_METHODS, CanonicalizationMethod: CANONICALIZATION_METHODS, Transform: TRANSFORMS };

/**
 * Refuse any signature, digest, canonicalisation or transform algorithm that is not on the allow-list.
 * Reads the decoded attribute values from the parsed document, with the same XML parser the signature
 * library uses, so character references, entity forms and case tricks cannot hide a weak algorithm.
 */
export function assertStrongSignatureAlgorithms(xml: string): void {
  const failures: string[] = [];
  const doc = new DOMParser({ errorHandler: { warning: (m: string) => failures.push(String(m)), error: (m: string) => failures.push(String(m)), fatalError: (m: string) => failures.push(String(m)) } }).parseFromString(xml, "text/xml");
  if (failures.length || !doc?.documentElement) throw new SamlError("xml-unsafe", "The SAML message is not well-formed XML.", 400);
  const visit = (node: Node): void => {
    for (let n: Node | null = node.firstChild; n; n = n.nextSibling) {
      if (n.nodeType !== 1) continue;
      const el = n as Element;
      if (el.namespaceURI === NS_DS && Object.hasOwn(ALLOWED, el.localName)) {
        const algorithm = el.getAttribute("Algorithm");
        if (algorithm === null || !ALLOWED[el.localName]!.has(algorithm)) throw new SamlError("weak-algorithm", "The SAML signature uses an algorithm that is not allowed.", 400);
      }
      visit(el);
    }
  };
  visit(doc);
}
