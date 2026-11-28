#!/usr/bin/env node
// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
// Sign or check a revocation list. Online components (hub, brain, runner heartbeat) refuse a license
// whose rid is on the list once the entry's effective time has passed. The offline CLI cannot be
// revoked before expiry; see enterprise/tools/README.md.
//
// Sign (key from a file path only, never the environment):
//   node enterprise/tools/sign-revocations.mjs --key <private-key-file> --kid k2 --seq 7 \
//     [--entries revocations.json] [--revoke lic_ab12@2027-03-01T00:00:00Z ...] [--issued <iso>]
//   revocations.json: { "entries": [ { "rid": "lic_ab12", "effective": "2027-03-01T00:00:00Z" } ] }
//   Prints `payload.signature` (base64url) to stdout. seq must rise with every published list.
//
// Check a published list against a public key (base64 SPKI DER, as in PRODUCTION_PUBLIC_KEYS):
//   node enterprise/tools/sign-revocations.mjs --verify <list-file> --pub <public-key-b64-file>
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

import { ISO, ToolError, buildRevocationPayload, isoNow, openToken, readPrivateKey, signToken } from "./license-lib.mjs";

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(2);
}

function readText(file, what) {
  try {
    return readFileSync(file, "utf8");
  } catch {
    throw new ToolError(`could not read ${what}`);
  }
}

try {
  const { values } = parseArgs({
    options: {
      key: { type: "string" },
      kid: { type: "string" },
      seq: { type: "string" },
      entries: { type: "string" },
      revoke: { type: "string", multiple: true },
      issued: { type: "string" },
      verify: { type: "string" },
      pub: { type: "string" },
    },
    strict: true,
  });
  if (values.verify) {
    if (!values.pub) throw new ToolError("--pub <public-key-b64-file> is required with --verify");
    const payload = openToken(readText(values.verify, "--verify file"), readText(values.pub, "--pub file"));
    if (!payload || payload.kind !== "revocations") throw new ToolError("the list is not signed by that key");
    console.log(`ok: seq ${payload.seq}, kid ${payload.kid}, ${payload.entries.length} revoked`);
  } else {
    let entries = [];
    if (values.entries) {
      try {
        entries = JSON.parse(readText(values.entries, "--entries file")).entries;
      } catch (e) {
        throw e instanceof ToolError ? e : new ToolError("--entries must be JSON with an entries list");
      }
    }
    for (const spec of values.revoke ?? []) {
      const [rid, effective] = spec.split("@");
      entries = [...(entries ?? []), { rid, effective: effective ?? "" }];
    }
    if (!entries || entries.length === 0) {
      // An empty list is legal (it supersedes an older one) but must be asked for explicitly.
      if (!values.entries) throw new ToolError("give --entries or --revoke; an empty list needs --entries with an empty entries array");
    }
    const issued = values.issued ?? isoNow();
    if (!ISO.test(issued)) throw new ToolError("--issued must be an ISO UTC time");
    const payload = buildRevocationPayload({ kid: values.kid, seq: Number(values.seq), issuedAt: issued, entries: entries ?? [] });
    process.stdout.write(`${signToken(payload, readPrivateKey(values.key))}\n`);
    console.error(`signed revocation list seq ${payload.seq} with ${payload.entries.length} entries`);
  }
} catch (e) {
  fail(e instanceof ToolError || e?.code?.startsWith?.("ERR_PARSE_ARGS") ? e.message : "unexpected failure");
}
