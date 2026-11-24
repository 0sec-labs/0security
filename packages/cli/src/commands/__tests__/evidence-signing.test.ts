import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { signEvidence as signEvidenceStatement } from "../../enterprise-bridge.js";
import type { Finding } from "@0/engine/shared";
import { runEvidenceVerify } from "../evidence.js";
import { EVIDENCE_SIGNATURE_FILE, verifyEvidenceFolder } from "../evidence-signature.js";
import { buildEvidence, type EvidenceDeps, type EvidenceInput } from "../findings-evidence.js";

// All keys here are generated in memory for the test and written to a throwaway folder. None is stored.
const dirs: string[] = [];
afterEach(() => { dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })); process.exitCode = 0; });
const tmp = () => { const dir = mkdtempSync(join(tmpdir(), "0-evsign-")); dirs.push(dir); return dir; };

const pair = () => generateKeyPairSync("ed25519");
const privatePem = (key: KeyObject) => key.export({ type: "pkcs8", format: "pem" }) as string;
const publicPem = (key: KeyObject) => key.export({ type: "spki", format: "pem" }) as string;

const finding = (id: string): Finding => ({
  id, templateId: "t", title: `Finding ${id}`, description: "d", severity: "high", category: "injection", status: "confirmed",
  evidence: { request: "", response: "" }, fingerprint: `fp-${id}`, timestamp: Date.UTC(2026, 8, 1), reviewAnnotation: { path: "src/a.ts", startLine: 3 },
} as unknown as Finding);
const input: EvidenceInput = { findings: [{ finding: finding("a"), scanId: "scan-1", scanTarget: "/srv/app", scanStartedAt: "2026-09-01T00:00:00.000Z", scanModel: "model-x" }], unreadable: [] };
const licensed: EvidenceDeps["signing"] = { refusal: () => null, sign: (json, pem) => signEvidenceStatement(json, pem) };
const deps = (extra: Partial<EvidenceDeps> = {}): EvidenceDeps => ({ err: () => undefined, load: () => input, git: (_r, args) => (args[0] === "rev-parse" ? "abc123def456\n" : args[0] === "status" ? "" : undefined), now: () => new Date("2026-11-21T00:00:00Z"), version: () => "9.9.9", signing: licensed, ...extra });

function signedFolder() {
  const base = tmp();
  const { privateKey, publicKey } = pair();
  const keyPath = join(base, "key.pem"); writeFileSync(keyPath, privatePem(privateKey), { mode: 0o600 });
  const pubPath = join(base, "pub.pem"); writeFileSync(pubPath, publicPem(publicKey));
  const repo = join(base, "repo"); const folder = join(base, "evidence");
  return { base, keyPath, pubPath, repo, folder, publicKey, run: async () => { const { mkdirSync } = await import("node:fs"); mkdirSync(repo); writeFileSync(join(repo, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } } })); return buildEvidence(folder, { repo, sign: keyPath }, deps()); } };
}

describe("0 findings evidence --sign", () => {
  it("writes a DSSE envelope whose statement lists every file with its hash, scan ids, tool version and commit", async () => {
    const s = signedFolder();
    const result = await s.run();
    expect(result.signed).toBe(true);
    const envelope = JSON.parse(readFileSync(join(s.folder, EVIDENCE_SIGNATURE_FILE), "utf8"));
    expect(envelope.payloadType).toBe("application/vnd.in-toto+json");
    expect(envelope.signatures).toHaveLength(1);
    const statement = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
    expect(statement._type).toBe("https://in-toto.io/Statement/v1");
    expect(statement.subject.map((x: { name: string }) => x.name)).toEqual(["README.md", "findings.json", "findings.md", "findings.sarif", "fixes.md", "manifest.json", "sbom.cdx.json"]);
    expect(statement.predicate).toMatchObject({ signedAt: "2026-11-21T00:00:00.000Z", tool: { name: "0", version: "9.9.9" }, scanIds: ["scan-1"], models: ["model-x"], repository: { commit: "abc123def456" } });
    expect(readFileSync(join(s.folder, "README.md"), "utf8")).toContain(EVIDENCE_SIGNATURE_FILE);
    expect(JSON.parse(readFileSync(join(s.folder, "manifest.json"), "utf8")).scanIds).toEqual(["scan-1"]);
  });

  it("is refused without the license, before anything is written", async () => {
    const s = signedFolder();
    const { mkdirSync } = await import("node:fs");
    mkdirSync(s.repo);
    await expect(buildEvidence(s.folder, { repo: s.repo, sign: s.keyPath }, deps({ signing: { refusal: () => "Signed evidence bundles needs an enterprise license.", sign: licensed!.sign } }))).rejects.toThrow(/needs an enterprise license/);
    expect(() => readdirSync(s.folder)).toThrow();
  });

  it("is refused with the real license check when no key is set", async () => {
    const s = signedFolder();
    const { mkdirSync } = await import("node:fs");
    mkdirSync(s.repo);
    const { signing: _ignored, ...bare } = deps();
    const before = { a: process.env.ZERO_LICENSE, b: process.env.ZERO_LICENSE_FILE };
    delete process.env.ZERO_LICENSE; delete process.env.ZERO_LICENSE_FILE;
    try {
      await expect(buildEvidence(s.folder, { repo: s.repo, sign: s.keyPath }, bare)).rejects.toThrow(/enterprise license/);
    } finally { if (before.a) process.env.ZERO_LICENSE = before.a; if (before.b) process.env.ZERO_LICENSE_FILE = before.b; }
  });

  it("refuses a missing, non-Ed25519 or non-key file without echoing its content", async () => {
    const s = signedFolder();
    await expect(buildEvidence(s.folder, { sign: join(s.base, "nope.pem") }, deps())).rejects.toThrow(/was not found/);
    const garbage = join(s.base, "garbage.pem"); writeFileSync(garbage, "TOP-SECRET-CONTENT");
    const error = (await buildEvidence(s.folder, { sign: garbage }, deps()).catch(e => e)) as Error;
    expect(error.message).toMatch(/not a private key in PEM/);
    expect(error.message).not.toContain("TOP-SECRET-CONTENT");
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    const rsaPath = join(s.base, "rsa.pem"); writeFileSync(rsaPath, privatePem(rsa));
    await expect(buildEvidence(s.folder, { sign: rsaPath }, deps())).rejects.toThrow(/not Ed25519/);
    expect(() => readdirSync(s.folder)).toThrow();
  });

  it("warns when the key file is readable by others, and never puts the key in any output", async () => {
    const s = signedFolder();
    chmodSync(s.keyPath, 0o644);
    const { mkdirSync } = await import("node:fs");
    mkdirSync(s.repo);
    const result = await buildEvidence(s.folder, { repo: s.repo, sign: s.keyPath }, deps());
    expect(result.warnings.join(" ")).toContain("can be read by other users");
    const key = readFileSync(s.keyPath, "utf8").split("\n")[1]!;
    for (const name of readdirSync(s.folder)) expect(readFileSync(join(s.folder, name), "utf8")).not.toContain(key);
    expect(JSON.stringify(result)).not.toContain(key);
  });

  it("removes a stale signature when the folder is rewritten without --sign", async () => {
    const s = signedFolder();
    await s.run();
    await buildEvidence(s.folder, { repo: s.repo }, deps());
    expect(readdirSync(s.folder)).not.toContain(EVIDENCE_SIGNATURE_FILE);
  });
});

describe("0 evidence verify", () => {
  it("accepts an untouched signed folder, even without any license", async () => {
    const s = signedFolder();
    await s.run();
    const result = verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8"));
    expect(result).toMatchObject({ ok: true, problems: [], filesChecked: 7, commit: "abc123def456", signedAt: "2026-11-21T00:00:00.000Z" });
  });

  it("detects a changed file", async () => {
    const s = signedFolder();
    await s.run();
    writeFileSync(join(s.folder, "findings.json"), "{}\n");
    const result = verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8"));
    expect(result.ok).toBe(false);
    expect(result.problems).toEqual([expect.objectContaining({ kind: "modified", file: "findings.json" })]);
  });

  it("detects an added file", async () => {
    const s = signedFolder();
    await s.run();
    writeFileSync(join(s.folder, "extra.txt"), "x");
    const result = verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8"));
    expect(result.problems).toEqual([expect.objectContaining({ kind: "added", file: "extra.txt" })]);
  });

  it("detects a removed file", async () => {
    const s = signedFolder();
    await s.run();
    unlinkSync(join(s.folder, "sbom.cdx.json"));
    const result = verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8"));
    expect(result.problems).toEqual([expect.objectContaining({ kind: "missing", file: "sbom.cdx.json" })]);
  });

  it("detects a replaced file with the same name via a symlink", async () => {
    const s = signedFolder();
    await s.run();
    unlinkSync(join(s.folder, "fixes.md"));
    symlinkSync(join(s.folder, "README.md"), join(s.folder, "fixes.md"));
    expect(verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8")).ok).toBe(false);
  });

  it("rejects the wrong key", async () => {
    const s = signedFolder();
    await s.run();
    const result = verifyEvidenceFolder(s.folder, publicPem(pair().publicKey));
    expect(result.ok).toBe(false);
    expect(result.problems[0]!.kind).toBe("wrong-key");
  });

  it("rejects a re-signed folder that uses an attacker's key as if it were the original", async () => {
    const s = signedFolder();
    await s.run();
    const attacker = pair();
    const envelope = JSON.parse(readFileSync(join(s.folder, EVIDENCE_SIGNATURE_FILE), "utf8"));
    const forged = signEvidenceStatement(Buffer.from(envelope.payload, "base64").toString("utf8"), privatePem(attacker.privateKey));
    forged.signatures[0]!.keyid = envelope.signatures[0].keyid; // claims the real key id
    writeFileSync(join(s.folder, EVIDENCE_SIGNATURE_FILE), JSON.stringify(forged));
    const result = verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8"));
    expect(result.problems[0]!.kind).toBe("bad-signature");
  });

  it("rejects an edited statement", async () => {
    const s = signedFolder();
    await s.run();
    const path = join(s.folder, EVIDENCE_SIGNATURE_FILE);
    const envelope = JSON.parse(readFileSync(path, "utf8"));
    envelope.payload = Buffer.from(Buffer.from(envelope.payload, "base64").toString("utf8").replace("abc123def456", "000000000000")).toString("base64");
    writeFileSync(path, JSON.stringify(envelope));
    expect(verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8")).problems[0]!.kind).toBe("bad-signature");
  });

  it("reports an unsigned folder and a missing signature", async () => {
    const s = signedFolder();
    await s.run();
    unlinkSync(join(s.folder, EVIDENCE_SIGNATURE_FILE));
    expect(verifyEvidenceFolder(s.folder, readFileSync(s.pubPath, "utf8")).problems[0]!.kind).toBe("no-signature");
  });

  it("exits 0 for a valid folder and 1 for a tampered one, and refuses a private key as --pub", async () => {
    const s = signedFolder();
    await s.run();
    const out: string[] = []; const err: string[] = [];
    runEvidenceVerify(s.folder, { pub: s.pubPath }, { out: t => out.push(t), err: t => err.push(t) });
    expect(process.exitCode).toBe(0);
    expect(out[0]).toMatch(/^Signature valid\. 7 files match/);
    writeFileSync(join(s.folder, "findings.md"), "changed");
    out.length = 0;
    runEvidenceVerify(s.folder, { pub: s.pubPath }, { out: t => out.push(t), err: t => err.push(t) });
    expect(process.exitCode).toBe(1);
    expect(out.join("\n")).toContain("findings.md was changed after it was signed");
    runEvidenceVerify(s.folder, { pub: s.keyPath }, { out: t => out.push(t), err: t => err.push(t) });
    expect(process.exitCode).toBe(2);
    expect(err.join(" ")).toContain("holds a private key");
  });
});
