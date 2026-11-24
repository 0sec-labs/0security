#!/usr/bin/env node
// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Create an Ed25519 license signing keypair.
//   node enterprise/tools/generate-keypair.mjs <private-key-file>
// Writes the private key (PKCS8 PEM, mode 0600) to <private-key-file> and the public key to
// <private-key-file>.pub.b64 (base64 of the SPKI DER, the format of PRODUCTION_PUBLIC_KEYS).
// The private key is never printed. Keep it out of the repository; store it in a secret manager.
import { generateKeyPairSync } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const target = process.argv[2];
if (!target) {
  console.error("usage: node enterprise/tools/generate-keypair.mjs <private-key-file>");
  process.exit(2);
}
const privatePath = resolve(target);
const publicPath = `${privatePath}.pub.b64`;
if (existsSync(privatePath) || existsSync(publicPath)) {
  console.error("refusing to overwrite an existing key file");
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
const publicB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
writeFileSync(publicPath, `${publicB64}\n`, { mode: 0o644, flag: "wx" });
console.log(`private key written to ${privatePath} (mode 0600, not shown)`);
console.log(`public key (safe to commit): ${publicB64}`);
