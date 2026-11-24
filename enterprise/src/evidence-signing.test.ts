// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Keys are generated in memory for each test. No private key is stored anywhere.
import { generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DSSE_PAYLOAD_TYPE, EvidenceKeyError, dssePae, evidenceKeyId, signEvidenceStatement } from "./index.js";

describe("signEvidenceStatement", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  it("makes a DSSE envelope that verifies over the pre-authentication encoding", () => {
    const statement = JSON.stringify({ hello: "world" });
    const envelope = signEvidenceStatement(statement, pem);
    expect(envelope.payloadType).toBe(DSSE_PAYLOAD_TYPE);
    expect(Buffer.from(envelope.payload, "base64").toString("utf8")).toBe(statement);
    const [signature] = envelope.signatures;
    expect(signature!.keyid).toBe(evidenceKeyId(publicKey.export({ type: "spki", format: "der" })));
    expect(verify(null, dssePae(DSSE_PAYLOAD_TYPE, Buffer.from(statement)), publicKey, Buffer.from(signature!.sig, "base64"))).toBe(true);
    expect(verify(null, dssePae(DSSE_PAYLOAD_TYPE, Buffer.from("other")), publicKey, Buffer.from(signature!.sig, "base64"))).toBe(false);
  });

  it("matches the DSSE specification's pre-authentication encoding", () => {
    expect(dssePae("http://example.com/HelloWorld", Buffer.from("hello world")).toString("utf8")).toBe("DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  });

  it("refuses garbage and non-Ed25519 keys without echoing the input", () => {
    expect(() => signEvidenceStatement("{}", "SECRET-GARBAGE")).toThrow(EvidenceKeyError);
    try { signEvidenceStatement("{}", "SECRET-GARBAGE"); } catch (error) { expect((error as Error).message).not.toContain("SECRET-GARBAGE"); }
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    expect(() => signEvidenceStatement("{}", rsa)).toThrow(/not Ed25519/);
  });
});
