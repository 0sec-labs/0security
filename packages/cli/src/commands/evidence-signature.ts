/**
 * The signed evidence format and its verifier. Verifying is free and offline: it needs a public key and the folder,
 * no license and no network.
 *
 * Format: `evidence.dsse.json` in the evidence folder is a DSSE envelope (secure-systems-lab/dsse, v1) around an
 * in-toto Statement v1. The statement's subjects are every other file in the folder with its SHA-256. The predicate
 * (type https://0.security/evidence/v1) records when it was signed, the tool version, the models, scan ids and the
 * git commit. The signature is Ed25519 over the DSSE pre-authentication encoding, made with a key the customer holds.
 * Signing is a paid feature and lives in enterprise/; this file only builds the statement and checks signatures.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

export const EVIDENCE_SIGNATURE_FILE = "evidence.dsse.json";
export const EVIDENCE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const EVIDENCE_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const EVIDENCE_PREDICATE_TYPE = "https://0.security/evidence/v1";

export interface EvidencePredicate {
  signedAt: string;
  generatedAt: string;
  tool: { name: string; version: string };
  models: string[];
  scanIds: string[];
  repository: { name: string; commit: string | null; uncommittedChanges: boolean } | null;
  counts: { findings: number; sbomComponents: number | null; advisories: number | null };
}

export interface EvidenceSubject { name: string; sha256: string }

/** The statement JSON that gets signed. Subjects are sorted by name so the bytes do not depend on write order. */
export function buildEvidenceStatement(files: readonly EvidenceSubject[], predicate: EvidencePredicate): string {
  const subject = [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)).map(file => ({ name: file.name, digest: { sha256: file.sha256 } }));
  return JSON.stringify({ _type: EVIDENCE_STATEMENT_TYPE, subject, predicateType: EVIDENCE_PREDICATE_TYPE, predicate });
}

const dssePae = (payloadType: string, payload: Buffer): Buffer => {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `, "utf8"), type, Buffer.from(` ${payload.length} `, "utf8"), payload]);
};

const keyIdOf = (der: Buffer): string => createHash("sha256").update(der).digest("hex");
const sha256File = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

export type EvidenceProblemKind = "no-signature" | "malformed" | "wrong-key" | "bad-signature" | "modified" | "missing" | "added";
export interface EvidenceProblem { kind: EvidenceProblemKind; file?: string; message: string }

export interface EvidenceVerification {
  ok: boolean;
  keyId: string | null;
  signedAt: string | null;
  commit: string | null;
  filesChecked: number;
  problems: EvidenceProblem[];
}

const MAX_ENVELOPE_BYTES = 4 * 1024 * 1024;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Checks the signature with `publicKeyPem` and every file in `folder` against the signed hashes. Never throws for bad input. */
export function verifyEvidenceFolder(folder: string, publicKeyPem: string): EvidenceVerification {
  const dir = resolve(folder);
  const result: EvidenceVerification = { ok: false, keyId: null, signedAt: null, commit: null, filesChecked: 0, problems: [] };
  const fail = (kind: EvidenceProblemKind, message: string, file?: string): EvidenceVerification => { result.problems.push({ kind, message, ...(file ? { file } : {}) }); return result; };

  let publicKey;
  try { publicKey = createPublicKey(publicKeyPem); } catch { return fail("malformed", "The public key file is not a public key in PEM format."); }
  if (publicKey.asymmetricKeyType !== "ed25519") return fail("malformed", "The public key is not an Ed25519 key.");
  result.keyId = keyIdOf(publicKey.export({ type: "spki", format: "der" }));

  let raw: string;
  try {
    if (!statSync(dir).isDirectory()) return fail("malformed", `'${folder}' is not a folder.`);
    const path = join(dir, EVIDENCE_SIGNATURE_FILE);
    const info = lstatSync(path);
    if (!info.isFile() || info.size > MAX_ENVELOPE_BYTES) return fail("malformed", `${EVIDENCE_SIGNATURE_FILE} is not a regular file of a sensible size.`);
    raw = readFileSync(path, "utf8");
  } catch {
    return fail("no-signature", `No ${EVIDENCE_SIGNATURE_FILE} in '${folder}'. The folder was not signed, or the signature was removed.`);
  }

  let envelope: { payloadType?: unknown; payload?: unknown; signatures?: unknown };
  let payload: Buffer;
  try {
    envelope = JSON.parse(raw) as typeof envelope;
    if (envelope.payloadType !== EVIDENCE_PAYLOAD_TYPE || typeof envelope.payload !== "string" || !Array.isArray(envelope.signatures)) throw new Error("shape");
    payload = Buffer.from(envelope.payload, "base64");
  } catch { return fail("malformed", `${EVIDENCE_SIGNATURE_FILE} is not a DSSE envelope for an in-toto statement.`); }

  const signatures = (envelope.signatures as Array<{ keyid?: unknown; sig?: unknown }>).filter(s => s && typeof s.sig === "string");
  if (!signatures.length) return fail("malformed", `${EVIDENCE_SIGNATURE_FILE} holds no signature.`);
  const candidates = signatures.filter(s => s.keyid === undefined || s.keyid === "" || s.keyid === result.keyId);
  if (!candidates.length) return fail("wrong-key", `The folder was signed with a different key (key id ${String(signatures[0]!.keyid).slice(0, 16)}...). This public key has id ${result.keyId.slice(0, 16)}....`);
  const pae = dssePae(EVIDENCE_PAYLOAD_TYPE, payload);
  const genuine = candidates.some(s => { try { return verify(null, pae, publicKey, Buffer.from(String(s.sig), "base64")); } catch { return false; } });
  if (!genuine) return fail("bad-signature", "The signature does not match the signed statement. The envelope was changed or signed with another key.");

  let statement: { _type?: unknown; subject?: unknown; predicateType?: unknown; predicate?: Partial<EvidencePredicate> };
  try {
    statement = JSON.parse(payload.toString("utf8")) as typeof statement;
    if (statement._type !== EVIDENCE_STATEMENT_TYPE || statement.predicateType !== EVIDENCE_PREDICATE_TYPE || !Array.isArray(statement.subject)) throw new Error("shape");
  } catch { return fail("malformed", "The signed statement is not a 0security evidence statement."); }
  result.signedAt = typeof statement.predicate?.signedAt === "string" ? statement.predicate.signedAt : null;
  result.commit = typeof statement.predicate?.repository?.commit === "string" ? statement.predicate.repository.commit : null;

  const signed = new Map<string, string>();
  for (const entry of statement.subject as Array<{ name?: unknown; digest?: { sha256?: unknown } }>) {
    const name = entry?.name; const digest = entry?.digest?.sha256;
    if (typeof name !== "string" || !SAFE_NAME.test(name) || name === EVIDENCE_SIGNATURE_FILE || typeof digest !== "string") return fail("malformed", "The signed statement lists a file name or digest that is not valid.");
    signed.set(name, digest);
  }

  for (const [name, digest] of signed) {
    const path = join(dir, name);
    let info;
    try { info = lstatSync(path); } catch { fail("missing", `${name} was signed but is not in the folder.`, name); continue; }
    if (!info.isFile()) { fail("modified", `${name} is not a regular file.`, name); continue; }
    result.filesChecked += 1;
    if (sha256File(path) !== digest) fail("modified", `${name} was changed after it was signed.`, name);
  }
  for (const name of readdirSync(dir).sort()) {
    if (name === EVIDENCE_SIGNATURE_FILE || signed.has(name)) continue;
    fail("added", `${name} is in the folder but was not signed.`, name);
  }
  result.ok = result.problems.length === 0;
  return result;
}
