import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { assertEgressAllowed } from "@0/engine";
import { TeamAuthError } from "./team-auth-error.js";

const MAX_METADATA_BYTES = 1_000_000;

/**
 * Read identity provider metadata from the file or https address the operator named in the team config.
 * A file needs no network. An address is a new outbound call: ZERO_ENTERPRISE refuses it (use a file), redirects
 * are refused, and the body is size-capped. The XML itself is checked by the enterprise metadata parser.
 */
export async function readIdpMetadataXml(source: { metadataUrl?: string; metadataFile?: string }): Promise<string> {
  if (source.metadataFile) {
    if (!isAbsolute(source.metadataFile)) throw new TeamAuthError("SAML metadata file must be an absolute path", 500);
    try {
      if (statSync(source.metadataFile).size > MAX_METADATA_BYTES) throw new Error("too large");
      return readFileSync(source.metadataFile, "utf8");
    } catch { throw new TeamAuthError("SAML metadata file cannot be read", 500); }
  }
  if (!source.metadataUrl) throw new TeamAuthError("SAML metadata is not configured", 500);
  const url = new URL(source.metadataUrl);
  assertEgressAllowed(`${url.hostname} (SAML identity provider metadata)`);
  let response: Response;
  try { response = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: "error", headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" } }); }
  catch { throw new TeamAuthError("SAML identity provider is unavailable", 502); }
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (!response.ok || declared > MAX_METADATA_BYTES) throw new TeamAuthError("SAML identity provider metadata could not be fetched", 502);
  const body = await response.text();
  if (body.length > MAX_METADATA_BYTES) throw new TeamAuthError("SAML identity provider metadata is too large", 502);
  return body;
}
