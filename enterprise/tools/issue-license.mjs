#!/usr/bin/env node
// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Sign a license token. The private key is read from the file path only, never from the environment,
// never printed and never copied. The token goes to stdout; a one-line summary goes to stderr.
// Keep a ledger of issued ids and rids outside this repository (see enterprise/tools/README.md).
//
// v2 (default), from a customer file:
//   node enterprise/tools/issue-license.mjs --key <private-key-file> --customer-file acme.json [--id <id>] [--kid k2] [--issued <iso>]
//   acme.json: { "customer": "Acme", "plan": "team", "seats": 25, "aud": ["cli","hub"],
//                "entitlements": { "saml": {}, "bb-managed": { "repos": 200 } }, "term": "annual" }
//   term is monthly (35 days) or annual (400 days); or give "expires". Optional: id, rid, kid, nbf, issuedAt.
//
// v1 (kept for tokens older components still read):
//   node enterprise/tools/issue-license.mjs --key <private-key-file> --customer <name> --seats <n> \
//     --features findings-server,rbac --expires 2027-12-01T00:00:00Z [--id <id>] [--kid k2] [--issued <iso>]
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

import { ISO, ToolError, buildV2Payload, isoNow, readPrivateKey, signToken } from "./license-lib.mjs";

const FEATURES = ["findings-server", "rbac", "scim", "saml", "evidence-signing", "audit-chain", "retention", "ha"];

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(2);
}

function buildV1(values) {
  if (!values.customer) throw new ToolError("--customer is required");
  const seats = Number(values.seats);
  if (!Number.isInteger(seats) || seats < 1) throw new ToolError("--seats must be a whole number of 1 or more");
  const features = (values.features ?? "").split(",").map((f) => f.trim()).filter(Boolean);
  if (features.length === 0) throw new ToolError(`--features is required (${FEATURES.join(", ")})`);
  for (const f of features) if (!FEATURES.includes(f)) throw new ToolError(`unknown feature "${f}" (known: ${FEATURES.join(", ")})`);
  const issuedAt = values.issued ?? isoNow();
  if (!values.expires || !ISO.test(values.expires)) throw new ToolError("--expires must be an ISO UTC time like 2027-12-01T00:00:00Z");
  if (!ISO.test(issuedAt)) throw new ToolError("--issued must be an ISO UTC time");
  if (Date.parse(values.expires) <= Date.parse(issuedAt)) throw new ToolError("--expires must be after the issue time");
  // Canonical JSON: fixed key order, no whitespace.
  return { customer: values.customer, expires: values.expires, features: [...new Set(features)], id: values.id ?? `lic_${randomBytes(8).toString("hex")}`, issuedAt, kid: values.kid ?? "k2", seats, v: 1 };
}

try {
  const { values } = parseArgs({
    options: {
      key: { type: "string" },
      "customer-file": { type: "string" },
      customer: { type: "string" },
      seats: { type: "string" },
      features: { type: "string" },
      expires: { type: "string" },
      issued: { type: "string" },
      id: { type: "string" },
      kid: { type: "string" },
    },
    strict: true,
  });
  let payload;
  if (values["customer-file"]) {
    for (const flag of ["customer", "seats", "features", "expires"]) if (values[flag] !== undefined) throw new ToolError(`--${flag} belongs to v1; put it in the customer file`);
    let file;
    try {
      file = JSON.parse(readFileSync(values["customer-file"], "utf8"));
    } catch {
      throw new ToolError("could not read JSON from --customer-file");
    }
    payload = buildV2Payload(file, { issuedAt: values.issued ?? isoNow(), id: values.id ?? `lic_${randomBytes(8).toString("hex")}`, kid: values.kid ?? "k2" });
  } else {
    payload = buildV1(values);
  }
  const token = signToken(payload, readPrivateKey(values.key));
  process.stdout.write(`${token}\n`);
  const what = payload.v === 2 ? `${payload.plan}, ${payload.seats} seats, ${Object.keys(payload.entitlements).join(",")}, aud ${payload.aud.join(",")}, rid ${payload.rid}` : `${payload.seats} seats, ${payload.features.join(",")}`;
  console.error(`issued v${payload.v} ${payload.id} for ${payload.customer}: ${what}, expires ${payload.expires}`);
} catch (e) {
  fail(e instanceof ToolError || e?.code?.startsWith?.("ERR_PARSE_ARGS") ? e.message : "unexpected failure");
}
