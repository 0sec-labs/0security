// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// The one place SAML XML is parsed by this folder. It must use the same @xmldom/xmldom the signature library
// (@node-saml/node-saml and xml-crypto) verifies with: a guard and a verifier that read the same text as two
// different documents is how signature-wrapping bypasses work. scripts/check-enterprise-boundary.mjs fails
// when the lockfile resolves more than one @xmldom/xmldom line.
import { DOMParser } from "@xmldom/xmldom";
import { SamlError, type SamlFailure } from "./errors.js";

/** Deepest element nesting accepted. A signed assertion in a response is about 15 levels deep. */
export const MAX_XML_DEPTH = 64;
/** Most tags accepted. A response with a thousand group values has a few thousand. */
export const MAX_XML_TAGS = 20_000;
const MAX_TAG_NAME = 256;

/**
 * One linear pass over the tags, before the parser sees the text. The XML parser's running time grows with the
 * square of the nesting depth and of the number of mismatched closing tags, so a 500 KB message of `<a>` or `</`
 * would keep it busy for minutes. This pass refuses what is not plainly well nested: too deep, too many tags, a
 * `<` inside a tag, a closing tag that does not match the open one, text left open. Each search for `<` and `>`
 * starts where the previous one stopped, so no character is scanned more than a few times. Comments are skipped
 * only when `allowComments` is set (operator-supplied metadata); responses never contain them.
 */
export function assertBoundedStructure(xml: string, reason: SamlFailure, message: string, allowComments = false): void {
  const refuse = (): never => { throw new SamlError(reason, message, 400); };
  const stack: string[] = [];
  let tags = 0;
  let lt = xml.indexOf("<");
  while (lt !== -1) {
    if (++tags > MAX_XML_TAGS) refuse();
    const kind = xml[lt + 1];
    if (kind === "!") {
      if (!allowComments || !xml.startsWith("<!--", lt)) return refuse();
      const end = xml.indexOf("-->", lt + 4);
      if (end < 0) return refuse();
      lt = xml.indexOf("<", end + 3);
      continue;
    }
    if (kind === "?") {
      const end = xml.indexOf("?>", lt + 2);
      if (end < 0) return refuse();
      lt = xml.indexOf("<", end + 2);
      continue;
    }
    const gt = xml.indexOf(">", lt);
    const next = xml.indexOf("<", lt + 1);
    if (gt < 0 || (next !== -1 && next < gt)) return refuse();
    if (kind === "/") {
      const name = xml.slice(lt + 2, gt).trim();
      if (name.length === 0 || name.length > MAX_TAG_NAME || stack.pop() !== name) return refuse();
    } else {
      let nameEnd = lt + 1;
      while (nameEnd < gt && !/[\s/]/.test(xml[nameEnd]!)) { nameEnd++; if (nameEnd - lt > MAX_TAG_NAME) return refuse(); }
      const name = xml.slice(lt + 1, nameEnd);
      if (name.length === 0) return refuse();
      if (xml[gt - 1] !== "/") {
        stack.push(name);
        if (stack.length > MAX_XML_DEPTH) return refuse();
      }
    }
    lt = next;
  }
  if (stack.length !== 0) refuse();
}

/** Parse XML and refuse anything the parser reports, warnings included. Written for @xmldom/xmldom 0.8 (`errorHandler`). */
export function parseStrictXml(xml: string, reason: SamlFailure, message: string, options: { allowComments?: boolean } = {}): Document {
  assertBoundedStructure(xml, reason, message, options.allowComments === true);
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
