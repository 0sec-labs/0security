import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@0/engine/shared";
import { buildEvidence, EVIDENCE_FILES, type EvidenceDeps, type EvidenceInput } from "../findings-evidence.js";
import { fixBranchName } from "../fix.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const tmp = () => { const dir = mkdtempSync(join(tmpdir(), "0-evid-")); dirs.push(dir); return dir; };

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id, templateId: "t", title: `Finding ${id}`, description: "d", severity: "high", category: "injection", status: "confirmed",
  evidence: { request: "SECRET-REQUEST", response: "SECRET-RESPONSE", analysis: "SECRET-ANALYSIS" }, fingerprint: `fp-${id}`, triageStatus: "accepted", triageNote: "known issue",
  timestamp: Date.UTC(2026, 8, 1), workflowUpdatedAt: "2026-09-02T00:00:00.000Z", reviewAnnotation: { path: "src/a.ts", startLine: 3 },
  pocSteps: [{ id: "s", kind: "exploit", summary: "SECRET-POC", action: { type: "note" } }] as never, ...extra,
} as Finding);
const input = (...findings: Finding[]): EvidenceInput => ({ findings: findings.map(f => ({ finding: f, scanId: "scan-1", scanTarget: "/srv/app", scanStartedAt: "2026-09-01T00:00:00.000Z", scanModel: "model-x" })), unreadable: [] });
const deps = (load: EvidenceInput, extra: Partial<EvidenceDeps> = {}): EvidenceDeps => ({ err: () => undefined, load: () => load, git: () => undefined, now: () => new Date("2026-11-21T00:00:00Z"), version: () => "9.9.9", ...extra });
const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } } });
const repoWith = (files: Record<string, string> = { "package-lock.json": lock }) => { const dir = tmp(); for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text); return dir; };
const read = (dir: string, name: string) => readFileSync(join(dir, name), "utf8");

describe("0 findings evidence", () => {
  it("writes the folder with every file, and leaves out evidence and PoC bodies by default", async () => {
    const out = join(tmp(), "evidence");
    const result = await buildEvidence(out, { repo: repoWith() }, deps(input(finding("a"), finding("b", { severity: "critical" }))));
    expect(readdirSync(out).sort()).toEqual(["README.md", "fixes.md", "findings.json", "findings.md", "findings.sarif", "manifest.json", "sbom.cdx.json"].sort());
    expect(result.findings).toBe(2);
    const json = JSON.parse(read(out, "findings.json"));
    expect(json.findings.map((f: { id: string }) => f.id)).toEqual(["b", "a"]); // critical first
    expect(json.findings[1]).toMatchObject({ triageStatus: "accepted", triageNote: "known issue", detectedAt: "2026-09-01T00:00:00.000Z", workflowUpdatedAt: "2026-09-02T00:00:00.000Z", location: "src/a.ts:3", scanModel: "model-x" });
    for (const name of readdirSync(out)) for (const secret of ["SECRET-REQUEST", "SECRET-RESPONSE", "SECRET-ANALYSIS", "SECRET-POC"]) expect(read(out, name), `${name} ${secret}`).not.toContain(secret);
    expect(JSON.parse(read(out, "findings.sarif")).version).toBe("2.1.0");
    expect(JSON.parse(read(out, "sbom.cdx.json")).bomFormat).toBe("CycloneDX");
    expect(read(out, "findings.md")).toContain("| `b` | critical |");
  });

  it("includes evidence only with --include-evidence, and warns", async () => {
    const out = join(tmp(), "e");
    const result = await buildEvidence(out, { includeEvidence: true }, deps(input(finding("a"))));
    expect(read(out, "findings.json")).toContain("SECRET-REQUEST");
    expect(read(out, "README.md")).toContain("**included**");
    expect(result.warnings.join(" ")).toContain("working exploit details");
  });

  it("README says what it shows and does not show, makes no compliance claim, and names version, date, model and commit", async () => {
    const repo = repoWith();
    const out = join(tmp(), "e");
    await buildEvidence(out, { repo }, deps(input(finding("a")), { git: (_r, args) => (args[0] === "rev-parse" ? "abc123def456\n" : args[0] === "status" ? "" : undefined) }));
    const text = read(out, "README.md");
    expect(text).toContain("`0` version 9.9.9 on 2026-11-21T00:00:00.000Z");
    expect(text).toContain("commit `abc123def456`");
    expect(text).toContain("`model-x`");
    expect(text).toContain("What it does not show");
    expect(text).toContain("not a declaration of conformity");
    expect(text).not.toMatch(/\b(is|are|be) (CRA[- ])?compliant\b/i);
    const manifest = JSON.parse(read(out, "manifest.json"));
    expect(manifest.repository.commit).toBe("abc123def456");
    expect(manifest.files.map((f: { name: string }) => f.name)).toContain("sbom.cdx.json");
    expect(text).toContain(manifest.files[0].sha256);
  });

  it("is reproducible: the same inputs give identical bytes", async () => {
    const repo = repoWith();
    const a = join(tmp(), "a"); const b = join(tmp(), "b");
    await buildEvidence(a, { repo }, deps(input(finding("a"))));
    await buildEvidence(b, { repo }, deps(input(finding("a"))));
    for (const name of readdirSync(a)) expect(read(a, name), name).toBe(read(b, name));
  });

  it("only touches the network with --check-advisories, and records the result", async () => {
    const repo = repoWith();
    const calls: string[] = [];
    const fetcher = (async (url: string | URL | Request) => { calls.push(String(url)); return new Response(JSON.stringify({ results: [{ vulns: [] }] }), { status: 200 }); }) as typeof fetch;
    await buildEvidence(join(tmp(), "none"), { repo }, deps(input(), { fetch: fetcher }));
    expect(calls).toEqual([]);
    const out = join(tmp(), "adv");
    await buildEvidence(out, { repo, checkAdvisories: true }, deps(input(), { fetch: fetcher }));
    expect(calls.length).toBeGreaterThan(0);
    expect(JSON.parse(read(out, "advisories.json"))).toMatchObject({ source: expect.stringContaining("OSV"), components: 1, advisoryCount: 0 });
    await expect(buildEvidence(join(tmp(), "x"), { checkAdvisories: true }, deps(input()))).rejects.toThrow("--check-advisories needs --repo");
  });

  it("writes nothing when the advisory lookup fails", async () => {
    const out = join(tmp(), "fail");
    const fetcher = (async () => { throw new Error("offline"); }) as unknown as typeof fetch;
    await expect(buildEvidence(out, { repo: repoWith(), checkAdvisories: true }, deps(input(), { fetch: fetcher }))).rejects.toThrow("Could not check against OSV");
    expect(existsSync(out)).toBe(false);
  });

  it("lists fix branches that exist in the repository and says pull requests are not stored", async () => {
    const records = input(finding("a"), finding("b"));
    const branch = fixBranchName("fp-a");
    const git: EvidenceDeps["git"] = (_repo, args) => args[0] === "for-each-ref" ? `${branch}\t1234567890abcdef\t2026-10-01T00:00:00+00:00\tfix: Finding a\norigin/${branch}\t1234567890abcdef\t2026-10-01T00:00:00+00:00\tfix: Finding a\n0/fix-unrelated\tff\t2026-10-01T00:00:00+00:00\tx\n` : undefined;
    const out = join(tmp(), "e");
    await buildEvidence(out, { repo: repoWith() }, deps(records, { git }));
    const text = read(out, "fixes.md");
    expect(text).toContain(`\`${branch}\``);
    expect(text).toContain(`\`origin/${branch}\``);
    expect(text).not.toContain("unrelated");
    expect(text).not.toContain(fixBranchName("fp-b"));
    expect(text).toContain("does not store pull request links");
    expect(text).toContain("does not show that the fix is correct");
  });

  it("says so when there is no repository, no lockfile or no git", async () => {
    const out = join(tmp(), "e");
    await buildEvidence(out, {}, deps(input()));
    expect(existsSync(join(out, "sbom.cdx.json"))).toBe(false);
    expect(read(out, "README.md")).toContain("No repository was given");
    expect(read(out, "fixes.md")).toContain("No repository was given");
    const bare = join(tmp(), "bare");
    const result = await buildEvidence(bare, { repo: repoWith({ "readme.md": "x" }) }, deps(input()));
    expect(result.warnings.join(" ")).toContain("no supported lockfile");
    expect(existsSync(join(bare, "sbom.cdx.json"))).toBe(false);
    expect(read(bare, "fixes.md")).toContain("not a git repository");
  });

  it("refuses folders it could harm", async () => {
    const base = tmp();
    mkdirSync(join(base, "full"));
    writeFileSync(join(base, "full", "notes.txt"), "mine");
    await expect(buildEvidence(join(base, "full"), {}, deps(input()))).rejects.toThrow("already holds other files");
    expect(readFileSync(join(base, "full", "notes.txt"), "utf8")).toBe("mine");
    writeFileSync(join(base, "file"), "x");
    await expect(buildEvidence(join(base, "file"), {}, deps(input()))).rejects.toThrow("not a folder");
    mkdirSync(join(base, "real"));
    symlinkSync(join(base, "real"), join(base, "link"));
    await expect(buildEvidence(join(base, "link"), {}, deps(input()))).rejects.toThrow("symbolic link");
    await expect(buildEvidence(join(base, "no", "such", "deep"), {}, deps(input()))).rejects.toThrow("parent");
    const repo = repoWith();
    await expect(buildEvidence(join(repo, "evidence"), { repo }, deps(input()))).rejects.toThrow("outside the repository");
    await expect(buildEvidence(join(base, "r2"), { repo: join(base, "missing") }, deps(input()))).rejects.toThrow("is not a folder");
  });

  it("does not follow a symlink planted under one of its file names", async () => {
    const base = tmp();
    const out = join(base, "e");
    mkdirSync(out);
    const victim = join(base, "victim.txt");
    writeFileSync(victim, "keep");
    symlinkSync(victim, join(out, "findings.json"));
    await expect(buildEvidence(out, {}, deps(input()))).rejects.toThrow("not a regular file");
    expect(readFileSync(victim, "utf8")).toBe("keep");
  });

  it("can overwrite its own earlier output and only ever writes its own file names", async () => {
    const out = join(tmp(), "e");
    await buildEvidence(out, {}, deps(input(finding("a"))));
    await buildEvidence(out, {}, deps(input(finding("a"), finding("b"))));
    expect(JSON.parse(read(out, "findings.json")).count).toBe(2);
    for (const name of readdirSync(out)) expect(EVIDENCE_FILES as readonly string[]).toContain(name);
  });

  it("removes a stale file of its own that this run did not produce, so the README stays true", async () => {
    const repo = repoWith();
    const out = join(tmp(), "e");
    const fetcher = (async () => new Response(JSON.stringify({ results: [{ vulns: [] }] }), { status: 200 })) as typeof fetch;
    await buildEvidence(out, { repo, checkAdvisories: true }, deps(input(), { fetch: fetcher }));
    expect(existsSync(join(out, "advisories.json"))).toBe(true);
    await buildEvidence(out, { repo }, deps(input()));
    expect(existsSync(join(out, "advisories.json"))).toBe(false);
  });

  it("records the commit of a real git repository", async () => {
    const repo = repoWith();
    execFileSync("git", ["-C", repo, "init", "-q"]);
    execFileSync("git", ["-C", repo, "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"]);
    const head = execFileSync("git", ["-C", repo, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const out = join(tmp(), "e");
    await buildEvidence(out, { repo }, deps(input(), { git: (r, args) => { try { return execFileSync("git", ["-C", r, ...args], { encoding: "utf8" }); } catch { return undefined; } } }));
    expect(JSON.parse(read(out, "manifest.json")).repository).toMatchObject({ commit: head, uncommittedChanges: true });
  });
});
