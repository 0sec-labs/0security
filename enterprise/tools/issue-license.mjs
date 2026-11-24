#!/usr/bin/env node
// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Sign a license token.
//   node enterprise/tools/issue-license.mjs --key <private-key-file> --customer <name> --seats <n> \
//     --features findings-server,rbac --expires 2027-12-01T00:00:00Z [--id <id>] [--kid k1] [--issued <iso>]
// The private key is read from the file path only. It is never printed and never copied. The token is
// printed to stdout; a one-line summary goes to stderr. Keep a ledger of issued ids outside this repository.
import { createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

const FEATURES = ["findings-server", "rbac", "scim", "saml", "evidence-signing", "audit-chain", "retention"];
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(2);
}

const { values } = parseArgs({
  options: {
    key: { type: "string" },
    customer: { type: "string" },
    seats: { type: "string" },
    features: { type: "string" },
    expires: { type: "string" },
    issued: { type: "string" },
    id: { type: "string" },
    kid: { type: "string", default: "k1" },
  },
  strict: true,
});

if (!values.key) fail("--key <private-key-file> is required");
if (!values.customer) fail("--customer is required");
const seats = Number(values.seats);
if (!Number.isInteger(seats) || seats < 1) fail("--seats must be a whole number of 1 or more");
const features = (values.features ?? "").split(",").map((f) => f.trim()).filter(Boolean);
if (features.length === 0) fail(`--features is required (${FEATURES.join(", ")})`);
for (const f of features) if (!FEATURES.includes(f)) fail(`unknown feature "${f}" (known: ${FEATURES.join(", ")})`);
const issuedAt = values.issued ?? new Date().toISOString().replace(/\.\d+Z$/, "Z");
if (!values.expires || !ISO.test(values.expires)) fail("--expires must be an ISO UTC time like 2027-12-01T00:00:00Z");
if (!ISO.test(issuedAt)) fail("--issued must be an ISO UTC time");
if (Date.parse(values.expires) <= Date.parse(issuedAt)) fail("--expires must be after the issue time");

const id = values.id ?? `lic_${randomBytes(8).toString("hex")}`;
// Canonical JSON: fixed key order, no whitespace.
const payload = {
  customer: values.customer,
  expires: values.expires,
  features: [...new Set(features)],
  id,
  issuedAt,
  kid: values.kid,
  seats,
  v: 1,
};
const payloadBytes = Buffer.from(JSON.stringify(payload), "utf8");

let privateKey;
try {
  privateKey = createPrivateKey(readFileSync(values.key));
} catch {
  fail("could not read an Ed25519 private key from the --key file");
}
if (privateKey.asymmetricKeyType !== "ed25519") fail("the key must be Ed25519");

const signature = sign(null, payloadBytes, privateKey);
process.stdout.write(`${payloadBytes.toString("base64url")}.${signature.toString("base64url")}\n`);
console.error(`issued ${id} for ${values.customer}: ${seats} seats, ${payload.features.join(",")}, expires ${values.expires}`);
