// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Reads the identity provider's metadata (SAML 2.0 Metadata, sections 2.4.1 and 2.4.3). The file or
// https address is named by the operator and is trusted as the pin for the signing certificate.
// The metadata's own signature is not checked.
import { X509Certificate } from "node:crypto";
import { SamlError } from "./errors.js";
import { assertNoDtd } from "./xml-guard.js";
import { parseStrictXml } from "./xml-parse.js";

const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

export interface IdpMetadata {
  entityId: string;
  /** HTTP-Redirect single sign-on endpoint. */
  ssoUrl: string;
  /** PEM certificates the identity provider signs with. */
  certificates: string[];
}

type El = Element;

function children(parent: El, ns: string, name: string): El[] {
  const out: El[] = [];
  for (let n = parent.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1 && (n as El).localName === name && (n as El).namespaceURI === ns) out.push(n as El);
  }
  return out;
}

function pem(base64: string): string {
  const body = base64.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) throw new SamlError("metadata", "The identity provider certificate is not valid base64.", 400);
  try { new X509Certificate(Buffer.from(body, "base64")); } catch { throw new SamlError("metadata", "The identity provider certificate cannot be read.", 400); }
  return `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function secureUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new SamlError("metadata", "The single sign-on address in the metadata is not a URL.", 400); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.username || url.password || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))) {
    throw new SamlError("metadata", "The single sign-on address must use HTTPS (HTTP only on loopback).", 400);
  }
  return url.href;
}

export function parseIdpMetadata(xml: string): IdpMetadata {
  assertNoDtd(xml);
  const doc = parseStrictXml(xml, "metadata", "The identity provider metadata is not well-formed XML.", { allowComments: true });
  let entity = doc.documentElement as El;
  if (entity.namespaceURI === NS_MD && entity.localName === "EntitiesDescriptor") {
    const inner = children(entity, NS_MD, "EntityDescriptor");
    if (inner.length !== 1) throw new SamlError("metadata", "The metadata must describe exactly one identity provider.", 400);
    entity = inner[0]!;
  }
  if (entity.namespaceURI !== NS_MD || entity.localName !== "EntityDescriptor") throw new SamlError("metadata", "The metadata root is not an EntityDescriptor.", 400);
  const entityId = entity.getAttribute("entityID");
  if (!entityId) throw new SamlError("metadata", "The metadata has no entityID.", 400);
  const idps = children(entity, NS_MD, "IDPSSODescriptor");
  if (idps.length !== 1) throw new SamlError("metadata", "The metadata must contain exactly one IDPSSODescriptor.", 400);
  const idp = idps[0]!;

  const sso = children(idp, NS_MD, "SingleSignOnService").find(s => s.getAttribute("Binding") === REDIRECT);
  if (!sso?.getAttribute("Location")) throw new SamlError("metadata", "The identity provider offers no HTTP-Redirect single sign-on endpoint.", 400);

  const certificates: string[] = [];
  for (const key of children(idp, NS_MD, "KeyDescriptor")) {
    const use = key.getAttribute("use");
    if (use && use !== "signing") continue;
    for (const info of children(key, NS_DS, "KeyInfo")) for (const data of children(info, NS_DS, "X509Data")) for (const cert of children(data, NS_DS, "X509Certificate")) {
      const value = pem(cert.textContent ?? "");
      if (!certificates.includes(value)) certificates.push(value);
    }
  }
  if (certificates.length === 0) throw new SamlError("metadata", "The metadata has no signing certificate.", 400);
  return { entityId, ssoUrl: secureUrl(sso.getAttribute("Location")!), certificates };
}
