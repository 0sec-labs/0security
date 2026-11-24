// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { DOMParser, type Document } from "@xmldom/xmldom";
import { SamlError, type SamlFailure } from "./errors.js";

/** Parse XML and refuse anything the parser reports, warnings included. Written for @xmldom/xmldom 0.9 (`onError`). */
export function parseStrictXml(xml: string, reason: SamlFailure, message: string): Document {
  try {
    const doc = new DOMParser({ onError: (level, text) => { throw new Error(`${level}: ${text}`); } }).parseFromString(xml, "text/xml");
    if (!doc?.documentElement) throw new Error("no root element");
    return doc;
  } catch {
    throw new SamlError(reason, message, 400);
  }
}
