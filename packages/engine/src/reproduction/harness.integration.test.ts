/**
 * Real container runs of the reproduction harness. Skipped unless a container runtime answers; needs no model and no
 * API key. It may pull the small pinned node image the first time. The fixture apps run inside a container with a
 * read-only root file system, no network and the production limits.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { proposeProof } from "../shared/reproduction.js";
import { OciRunner } from "../verifier/docker-runner.js";
import { REPRODUCTION_LIMITS, reproduceFinding } from "./harness.js";

const hasDocker = ["docker", "podman"].some((bin) => spawnSync(bin, ["info"], { stdio: "ignore", timeout: 10_000 }).status === 0);
const NODE = "node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a"; // node:22-alpine
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "../../../../scripts/bench/repro-fixtures/path-traversal");
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const ACK = "REPRO_FIXTURE_ACK=intentionally-vulnerable node server.js";
const proof = proposeProof({ pocSteps: [{ id: "e", kind: "exploit", summary: "x", action: { type: "http", method: "GET", url: "http://victim.example/download?name=../../etc/passwd" } }] })!;
const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
// The label is shared by every container 0 starts on this daemon, so a leftover is only one that was not there when
// the test began. Containers from other test files or earlier runs are not this test's to judge.
const labelled = () => new Set(spawnSync("docker", ["ps", "-aq", "--no-trunc", "--filter", "label=0.verify=1"], { encoding: "utf8" }).stdout.split(/\s+/).filter(Boolean));
let before = new Set<string>();
beforeEach(() => { before = labelled(); });
const left = () => [...labelled()].filter((id) => !before.has(id)).join("\n");

describe.skipIf(!hasDocker)("reproduction in a real container with a read-only root", () => {
  const runner = new OciRunner();
  const reproduce = (variant: string, start = ACK) => reproduceFinding({ proof, snapshotDir: join(FIXTURES, variant), commit: COMMIT, runner, image: NODE, start });

  it("reproduces the planted flaw in the vulnerable fixture", async () => {
    const result = await reproduce("vulnerable");
    expect(result).toMatchObject({ status: "reproduced", reason: "canary-observed", isolation: "container", network: "loopback", canary: { observed: true } });
    expect(result.storageUnbounded).toBeUndefined();
    expect(left()).toBe("");
  }, 180_000);

  it("does not reproduce anything in the fixed fixture", async () => {
    const result = await reproduce("fixed", "node server.js");
    expect(result).toMatchObject({ status: "not-reproduced", reason: "canary-absent", isolation: "container", canary: { observed: false } });
    expect(left()).toBe("");
  }, 180_000);

  it("runs with a read-only root, a capped writable folder, no network and no exec on the writable folders", async () => {
    const dir = mkdtempSync(join(tmpdir(), "repro-it-"));
    dirs.push(dir);
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "sub", "run.sh"), "#!/bin/sh\necho ran\n");
    chmodSync(join(dir, "sub", "run.sh"), 0o755);
    symlinkSync("sub/run.sh", join(dir, "link"));
    const script = [
      "pwd", "cat /proc/self/status | grep -c NoNewPrivs", "touch /x 2>&1 | grep -c 'Read-only'", "touch /sandbox/beside && echo parent-writable",
      "sh sub/run.sh", "./sub/run.sh 2>&1 | grep -c 'Permission denied'", "readlink link", "cp sub/run.sh /tmp/r.sh && (/tmp/r.sh 2>&1 | grep -c 'Permission denied')",
      "(wget -T 2 -q -O- http://1.1.1.1/ >/dev/null 2>&1 && echo network-up) || echo network-down",
      "dd if=/dev/zero of=/sandbox/big bs=1M count=64 2>&1 | grep -c 'No space left'", "df -m /sandbox | tail -1 | tr -s ' ' | cut -d' ' -f2",
    ].join("\n");
    const outcome = await runner.run({ image: NODE, dir, command: script, network: "none", timeoutMs: 60_000, limits: { ...REPRODUCTION_LIMITS, storageSize: "16m" } });
    expect(outcome.infraError).toBeUndefined();
    expect(outcome.output.trim().split("\n")).toEqual(["/sandbox/app", "1", "1", "parent-writable", "ran", "1", "sub/run.sh", "1", "network-down", "1", "16"]);
    expect(left()).toBe("");
  }, 120_000);

  it("refuses to run when the writable folder cannot be capped", async () => {
    const dir = mkdtempSync(join(tmpdir(), "repro-it-"));
    dirs.push(dir);
    const outcome = await runner.run({ image: NODE, dir, command: "echo should-not-run", network: "none", timeoutMs: 60_000, limits: { ...REPRODUCTION_LIMITS, storageSize: "lots" } });
    expect(outcome.infraError).toMatch(/could not start container/);
    expect(outcome.output).not.toContain("should-not-run");
    expect(left()).toBe("");
  }, 120_000);
});
