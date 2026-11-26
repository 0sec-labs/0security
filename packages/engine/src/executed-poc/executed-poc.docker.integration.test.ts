/**
 * Executed PoC through the REAL container adapter (`OciRunner`), no fake `ContainerRunner`.
 *
 * Gated: skipped unless `docker info` or `podman info` answers. It never needs a model or an API key. The first run
 * pulls the pinned image. Run it alone:
 *
 *   pnpm --filter @0/engine exec vitest run src/executed-poc/executed-poc.docker.integration.test.ts
 *
 * Image: alpine 3.20, pinned by the digest `docker pull alpine:3.20` resolved on 2026-11-26 (multi-arch index digest).
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { OciRunner } from "../verifier/docker-runner.js";
import type { PocStep } from "../shared/types.js";
import { createExecutedPoc, executePocForFinding } from "./run.js";

const hasContainerRuntime = ["docker", "podman"].some((bin) => spawnSync(bin, ["info"], { stdio: "ignore", timeout: 15_000 }).status === 0);
const ALPINE_DIGEST = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";
const IMAGE = `alpine@${ALPINE_DIGEST}`;
const SECRET = "TOP-SECRET-7f3a91";

const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

/** A tiny shell app (alpine has no node): one path traversal (`read`) and a guarded twin (`safe-read`). */
function fixtureApp(): string {
  const dir = mkdtempSync(join(tmpdir(), "0-poc-real-"));
  dirs.push(dir);
  mkdirSync(join(dir, "public"));
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "public", "index.txt"), "welcome\n");
  writeFileSync(join(dir, "data", "secret.txt"), `${SECRET}\n`);
  writeFileSync(join(dir, "app.sh"), [
    "#!/bin/sh",
    'case "$1" in',
    '  read) cat "public/$2" ;;',
    '  safe-read) case "$2" in *..*) echo denied ;; *) cat "public/$2" ;; esac ;;',
    "  *) exit 2 ;;",
    "esac",
    "",
  ].join("\n"));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q"); git("add", "-A");
  git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "fixture");
  return dir;
}

const shell = (id: string, cmd: string, text: string): PocStep => ({ id, kind: "exploit", summary: id, action: { type: "shell", cmd }, expect: { type: "body-contains", text } });

describe.skipIf(!hasContainerRuntime)("executed PoC with the real OciRunner (needs Docker or podman)", () => {
  const folder = hasContainerRuntime ? fixtureApp() : "";
  const runtime = () => createExecutedPoc({ image: IMAGE, maxRuns: 5 }, new OciRunner());

  it("runs a real path traversal script inside a container with the network off (script-matched, not a reproduction)", async () => {
    const record = await executePocForFinding({ finding: { severity: "high", pocSteps: [shell("p1", "sh app.sh read ../data/secret.txt", SECRET)] }, folder, runtime: runtime() });
    expect(record).toMatchObject({ outcome: "script-matched", reason: "expectation-met", stepIds: ["p1"], run: { status: "pass", isolation: "container", imageDigest: ALPINE_DIGEST } });
    expect(record!.run!.logTail).toContain(SECRET);
  }, 180_000);

  it("reports script-unmatched for the guarded twin, and proves the network is off from inside", async () => {
    const failed = await executePocForFinding({ finding: { severity: "critical", pocSteps: [shell("f1", "sh app.sh safe-read ../data/secret.txt", SECRET)] }, folder, runtime: runtime() });
    expect(failed).toMatchObject({ outcome: "script-unmatched", reason: "expectation-not-met", run: { status: "fail", isolation: "container" } });
    expect(failed!.run!.logTail).toContain("denied");

    // The expected text is assembled at run time, so it is not "written into the command". It only appears if the fetch failed.
    const offline = await executePocForFinding({
      finding: { severity: "high", pocSteps: [shell("n1", "wget -T 3 -q -O- http://1.1.1.1/ || printf '%s-%s' OFFLINE CONFIRMED", "OFFLINE-CONFIRMED")] }, folder, runtime: runtime(),
    });
    expect(offline).toMatchObject({ outcome: "script-matched", run: { isolation: "container" } });
  }, 180_000);

  it("does not change the host folder", () => {
    // Container leaks are covered by docker-runner.integration.test.ts; a global `ps` here would race with the other Docker tests running in parallel.
    expect(execFileSync("git", ["status", "--porcelain"], { cwd: folder, encoding: "utf8" })).toBe("");
  });
});
