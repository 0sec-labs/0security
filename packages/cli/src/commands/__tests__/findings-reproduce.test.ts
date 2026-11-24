/**
 * Run for real: git, the SQLite store, the fixture app on loopback, the in-container script under sh.
 * FAKE: the container. HostBackedRunner copies the snapshot to a scratch folder and runs the script on the host,
 * with no isolation and no network cut. Nothing here proves the OciRunner path.
 */
import { afterEach, describe, expect, it } from "vitest";
import { execFileSync, spawn } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { osecDB } from "@0/engine/storage";
import type { ContainerRunner } from "@0/engine";
import { runReproduce, type ReproduceDeps } from "../findings-reproduce.js";
import { reproductionDetail } from "../../finding-reproduction.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "../../../../../scripts/bench/repro-fixtures/path-traversal");
const IMAGE = `node:24-bookworm-slim@sha256:${"c".repeat(64)}`;
const scratch: string[] = [];
afterEach(() => { for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const tmp = (prefix: string) => { const dir = mkdtempSync(join(tmpdir(), prefix)); scratch.push(dir); return dir; };

const hostBacked: ContainerRunner = {
  isolation: "container",
  async probe() { return { ok: true, runtime: "fake" }; },
  run(request) {
    const parent = tmp("0-repro-cli-run-");
    const work = join(parent, "work");
    cpSync(request.dir, work, { recursive: true });
    return new Promise((resolve) => {
      let output = "";
      const child = spawn("sh", ["-c", request.command], { cwd: work });
      child.stdout.on("data", (c) => { output += c; });
      child.stderr.on("data", (c) => { output += c; });
      child.on("close", (code) => resolve({ exitCode: code, output, timedOut: false, durationMs: 1 }));
    });
  },
};

function repoFrom(variant: "vulnerable" | "fixed"): { folder: string; commit: string } {
  const folder = tmp("0-repro-cli-repo-");
  cpSync(join(FIXTURES, variant), folder, { recursive: true });
  const git = (...args: string[]) => execFileSync("git", ["-C", folder, "-c", "user.name=t", "-c", "user.email=t@example.test", ...args], { encoding: "utf8" });
  git("init", "-q"); git("add", "-A"); git("commit", "-q", "-m", "fixture");
  return { folder, commit: git("rev-parse", "HEAD").trim() };
}

function dbWithFinding(): string {
  const path = join(tmp("0-repro-cli-db-"), "t.db");
  const db = new osecDB(path);
  const scanId = db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
  db.saveFinding(scanId, {
    id: "f-abc123", templateId: "t", title: "Download route reads any file", description: "d", severity: "high", category: "path-traversal", status: "discovered",
    evidence: { request: "GET /download?name=../../etc/passwd", response: "root:x" }, timestamp: Date.now(),
    pocSteps: [{ id: "e", kind: "exploit", summary: "hit", action: { type: "http", method: "GET", url: "http://victim.example/download?name=../../etc/passwd" } }],
  } as never);
  db.close();
  return path;
}

const deps = (repo: { folder: string }): ReproduceDeps => ({
  out: () => undefined, err: () => undefined, runner: () => hostBacked,
  head: async () => ({ commit: execFileSync("git", ["-C", repo.folder, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(), dirty: false }),
  snapshot: async (folder) => { const dir = tmp("0-repro-cli-snap-"); cpSync(folder, dir, { recursive: true }); return { dir, cleanup: () => undefined }; },
});
const start = () => `node server.js`;

describe("findings reproduce", () => {
  it("records reproduced for the vulnerable commit and not-reproduced for the fixed one", async () => {
    const dbPath = dbWithFinding();
    const vuln = repoFrom("vulnerable");
    const first = await runReproduce("f-abc123", { image: IMAGE, folder: vuln.folder, dbPath, start: start() }, deps(vuln));
    expect(first).toMatchObject({ stored: true, result: { status: "reproduced", commit: vuln.commit } });
    expect(first.line).toMatch(/^Reproduced on commit/);

    const fixed = repoFrom("fixed");
    const second = await runReproduce("f-abc123", { image: IMAGE, folder: fixed.folder, dbPath, start: start() }, deps(fixed));
    expect(second.result.status).toBe("not-reproduced");
    expect(second.line).toMatch(/does not mean the issue is absent/);

    const db = new osecDB(dbPath);
    try {
      const stored = db.getFindingReproduction("f-abc123");
      expect(stored?.result?.commit).toBe(fixed.commit);
      expect(stored?.proof?.label).toBe("proposed");
      expect(reproductionDetail(db.getFinding("f-abc123") as never)?.line).toMatch(/^Not reproduced by this recipe/);
      expect(db.getFinding("f-abc123")).toMatchObject({ severity: "high", status: "discovered", triageStatus: "new" });
    } finally { db.close(); }
  }, 120_000);

  it("does not store an error over an earlier result", async () => {
    const dbPath = dbWithFinding();
    const vuln = repoFrom("vulnerable");
    await runReproduce("f-abc123", { image: IMAGE, folder: vuln.folder, dbPath, start: start() }, deps(vuln));
    const broken: ReproduceDeps = { ...deps(vuln), runner: () => ({ isolation: "container", probe: async () => ({ ok: false, reason: "no daemon" }), run: async () => { throw new Error("unreachable"); } }) };
    const outcome = await runReproduce("f-abc123", { image: IMAGE, folder: vuln.folder, dbPath }, broken);
    expect(outcome).toMatchObject({ stored: false, result: { status: "error", reason: "no-container-runtime" } });
    const db = new osecDB(dbPath);
    try { expect(db.getFindingReproduction("f-abc123")?.result?.status).toBe("reproduced"); } finally { db.close(); }
  }, 120_000);

  it("refuses a tag, an unknown finding and a folder that is not a Git repository", async () => {
    const dbPath = dbWithFinding();
    const vuln = repoFrom("vulnerable");
    await expect(runReproduce("f-abc123", { image: "node:24", folder: vuln.folder, dbPath }, deps(vuln))).rejects.toThrow(/pinned by digest/);
    await expect(runReproduce("nope", { image: IMAGE, folder: vuln.folder, dbPath }, deps(vuln))).rejects.toThrow(/not found/);
    await expect(runReproduce("f-abc123", { image: IMAGE, folder: vuln.folder, dbPath }, { ...deps(vuln), head: async () => undefined })).rejects.toThrow(/not a Git repository/);
  });
});
