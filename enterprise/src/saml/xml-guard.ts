// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Refuses XML that SAML never needs and attackers like. Checked on the raw text before any parser or
// signature library sees it, so a parser difference cannot hide anything from these rules.
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
  // Only a leading XML declaration may use <? ... ?>.
  const withoutDeclaration = xml.replace(/^﻿?\s*<\?xml\s[^>]*\?>/, "");
  if (withoutDeclaration.includes("<?")) throw new SamlError("xml-unsafe", "The SAML message contains a processing instruction, which is not allowed.", 400);
}

const WEAK_ALGORITHM = /Algorithm\s*=\s*["'][^"']*(?:sha1|md5|ripemd)[^"']*["']/i;

/** Refuse signatures and digests built on SHA-1, MD5 or RIPEMD. Looks at every algorithm attribute. */
export function assertStrongSignatureAlgorithms(xml: string): void {
  if (WEAK_ALGORITHM.test(xml)) throw new SamlError("weak-algorithm", "The SAML signature uses a weak algorithm.", 400);
}
