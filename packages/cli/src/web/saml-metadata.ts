import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { assertEgressAllowed } from "@0/engine";
import { TeamAuthError } from "./team-auth-error.js";

const MAX_METADATA_BYTES = 1_000_000;

/**
 * Read identity provider metadata from the file or https address the operator named in the team config.
 * A file needs no network. An address is a new outbound call: ZERO_ENTERPRISE refuses it (use a file), redirects
 * are refused, and the body is size-capped while it is read. The XML itself is checked by the enterprise metadata parser.
 */
export async function readIdpMetadataXml(source: { metadataUrl?: string; metadataFile?: string }, options: { timeoutMs?: number; maxBytes?: number } = {}): Promise<string> {
  const maxBytes = options.maxBytes ?? MAX_METADATA_BYTES;
  if (source.metadataFile) {
    if (!isAbsolute(source.metadataFile)) throw new TeamAuthError("SAML metadata file must be an absolute path", 500);
    try {
      if (statSync(source.metadataFile).size > maxBytes) throw new Error("too large");
      return readFileSync(source.metadataFile, "utf8");
    } catch { throw new TeamAuthError("SAML metadata file cannot be read", 500); }
  }
  if (!source.metadataUrl) throw new TeamAuthError("SAML metadata is not configured", 500);
  const url = new URL(source.metadataUrl);
  assertEgressAllowed(`${url.hostname} (SAML identity provider metadata)`);
  // One deadline covers connecting and reading the whole body. The cap is enforced while reading: the request
  // is aborted as soon as more than maxBytes arrive, so an oversized or endless body is never buffered.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: "error", headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" } });
    if (!response.ok || !response.body || Number(response.headers.get("content-length") ?? 0) > maxBytes) {
      controller.abort();
      throw new TeamAuthError("SAML identity provider metadata could not be fetched", 502);
    }
    const chunks: Uint8Array[] = [];
    let received = 0;
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) { controller.abort(); throw new TeamAuthError("SAML identity provider metadata is too large", 502); }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } catch (error) {
    if (error instanceof TeamAuthError) throw error;
    throw new TeamAuthError("SAML identity provider is unavailable", 502);
  } finally { clearTimeout(timer); }
}
