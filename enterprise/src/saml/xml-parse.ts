// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// The one place SAML XML is parsed by this folder. It must use the same @xmldom/xmldom the signature library
// (@node-saml/node-saml and xml-crypto) verifies with: a guard and a verifier that read the same text as two
// different documents is how signature-wrapping bypasses work. scripts/check-enterprise-boundary.mjs fails
// when the lockfile resolves more than one @xmldom/xmldom line.
import { DOMParser } from "@xmldom/xmldom";
import { SamlError, type SamlFailure } from "./errors.js";

/** Parse XML and refuse anything the parser reports, warnings included. Written for @xmldom/xmldom 0.8 (`errorHandler`). */
export function parseStrictXml(xml: string, reason: SamlFailure, message: string): Document {
  const failures: string[] = [];
  const note = (text: string): void => { failures.push(String(text)); };
  let doc: Document | undefined;
  try {
    doc = new DOMParser({ errorHandler: { warning: note, error: note, fatalError: note } }).parseFromString(xml, "text/xml") as unknown as Document;
  } catch {
    throw new SamlError(reason, message, 400);
  }
  if (failures.length || !doc?.documentElement) throw new SamlError(reason, message, 400);
  return doc;
}
