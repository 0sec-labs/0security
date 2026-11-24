// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Signs an evidence statement with a key the customer holds. The output is a DSSE envelope
// (https://github.com/secure-systems-lab/dsse) around an in-toto Statement. The private key is read by the
// caller, used here to sign and never stored, logged or put in an error message. The matching verifier is free and
// lives outside this folder (packages/cli/src/commands/evidence-signature.ts), so an auditor needs no license.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";

export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";

export interface DsseEnvelope {
  payloadType: string;
  /** Standard base64 of the statement JSON. */
  payload: string;
  signatures: Array<{ keyid: string; sig: string }>;
}

export class EvidenceKeyError extends Error {}

/** DSSE pre-authentication encoding: the exact bytes that are signed. */
export function dssePae(payloadType: string, payload: Buffer): Buffer {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `, "utf8"), type, Buffer.from(` ${payload.length} `, "utf8"), payload]);
}

/** Key id of a public key: the SHA-256 of its SPKI DER, in hex. */
export function evidenceKeyId(publicKeyDer: Buffer): string {
  return createHash("sha256").update(publicKeyDer).digest("hex");
}

/** Signs `statementJson` with an Ed25519 private key in PEM (PKCS#8). Throws EvidenceKeyError without echoing the key. */
export function signEvidenceStatement(statementJson: string, privateKeyPem: string): DsseEnvelope {
  let key;
  try {
    key = createPrivateKey({ key: privateKeyPem, format: "pem" });
  } catch {
    throw new EvidenceKeyError("The key file is not a private key in PEM format. Create one with: openssl genpkey -algorithm ed25519 -out evidence-key.pem");
  }
  if (key.asymmetricKeyType !== "ed25519") throw new EvidenceKeyError(`The key is ${key.asymmetricKeyType ?? "of an unknown type"}, not Ed25519. Create one with: openssl genpkey -algorithm ed25519 -out evidence-key.pem`);
  const keyid = evidenceKeyId(createPublicKey(key).export({ type: "spki", format: "der" }));
  const payload = Buffer.from(statementJson, "utf8");
  const signature = sign(null, dssePae(DSSE_PAYLOAD_TYPE, payload), key);
  return { payloadType: DSSE_PAYLOAD_TYPE, payload: payload.toString("base64"), signatures: [{ keyid, sig: signature.toString("base64") }] };
}
