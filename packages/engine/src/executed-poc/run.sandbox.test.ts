import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildCreateArgs, OciRunner } from "../verifier/docker-runner.js";
import { HostRunner } from "../verifier/host-runner.js";
import type { ContainerRunner, StepRequest } from "../verifier/port.js";
import { looksSecret, snapshotWorktree } from "../verifier/snapshot.js";
import { claimsReproduced } from "../shared/reproduction.js";
import { executedPocLine, parseExecutedPoc } from "../shared/executed-poc.js";
import { createExecutedPoc, executePocForFinding } from "./run.js";

const IMAGE = `node:24-bookworm-slim@sha256:${"a".repeat(64)}`;
const cleanups: Array<() => void> = [];
afterEach(() => { for (const c of cleanups.splice(0)) c(); });

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "0-poc-sbx-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q"); git("add", "-A");
  git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x");
  return dir;
}

const finding = (cmd: string, text: string) => ({ severity: "high" as const, pocSteps: [{ id: "s", kind: "exploit" as const, summary: "s", action: { type: "shell" as const, cmd }, expect: { type: "body-contains" as const, text } }] });

function recording(): ContainerRunner & { requests: StepRequest[] } {
  const host = new HostRunner();
  const requests: StepRequest[] = [];
  return { isolation: "container", requests, probe: () => host.probe(), run: (r) => { requests.push(r); return host.run(r); } };
}

describe("executed PoC sandbox rules", () => {
  it("a script that prints the expected text without touching the code is never called a reproduction", async () => {
    const dir = repo({ "app.js": "// nothing vulnerable here\n" });
    const runtime = createExecutedPoc({ image: IMAGE }, recording());
    const record = await executePocForFinding({ finding: finding(`printf "PWN-%s" 1234`, "PWN-1234"), folder: dir, runtime });
    expect(record?.outcome).toBe("script-matched");
    const line = executedPocLine(record);
    expect(line).toMatch(/not a reproduction/);
    expect(line).not.toMatch(/proven|reproduced/i);
    expect(claimsReproduced("The PoC is executed-proven")).toBe(true);
  });

  it("leaves credential-looking files out of the snapshot the commands see", async () => {
    const dir = repo({ "app.js": "x", ".env": "TOKEN=abc", "config/.env.production": "A=1", "keys/server.pem": "k", ".ssh/id_rsa": "k", ".env.example": "A=", "src/secrets.ts": "export {}", "secrets.json": "{}" });
    const runner = recording();
    const runtime = createExecutedPoc({ image: IMAGE }, runner);
    const record = await executePocForFinding({ finding: finding("ls -A; find . -type f | sort", "app.js"), folder: dir, runtime });
    expect(record?.outcome).toBe("script-matched");
    const log = record!.run!.logTail;
    expect(log).toContain("app.js");
    expect(log).toContain(".env.example");
    expect(log).toContain("secrets.ts");
    expect(log).not.toMatch(/secrets\.json|\.env\.production|server\.pem|id_rsa|\n\.\/\.env\n/);
    expect(looksSecret(".env")).toBe(true);
    expect(looksSecret(".env.example")).toBe(false);
  });

  it("redacts secrets in the stored command and log", async () => {
    const dir = repo({ "app.js": "x" });
    const runtime = createExecutedPoc({ image: IMAGE }, recording());
    const fake = ["gh", "p_", "a".repeat(30)].join("");
    const record = await executePocForFinding({ finding: finding(`printf "%s %s-%s" token=${fake} ready marker`, "ready-marker"), folder: dir, runtime });
    expect(record!.run!.command).not.toContain(fake);
    expect(record!.run!.logTail).not.toContain(fake);
  });

  it("asks the runtime never to pull and passes the abort signal to the container port", async () => {
    const dir = repo({ "app.js": "x" });
    const runner = recording();
    const controller = new AbortController();
    await executePocForFinding({ finding: finding(`printf "%s-%s" ready marker`, "ready-marker"), folder: dir, runtime: createExecutedPoc({ image: IMAGE }, runner), signal: controller.signal });
    expect(runner.requests[0]!.limits).toMatchObject({ pullNever: true, readOnlyRoot: true });
    expect(runner.requests[0]!.signal).toBe(controller.signal);
    const args = buildCreateArgs("n", runner.requests[0]!);
    expect(args).toContain("--pull=never");
    expect(args).toContain("--read-only");
    expect(args.join(" ")).toMatch(/--tmpfs \/sandbox:rw,size=\w+,noexec/);
    expect(args.join(" ")).toMatch(/--tmpfs \/tmp:rw,size=64m,noexec/);
    expect(buildCreateArgs("n", { image: IMAGE, dir: "/x", command: "c", network: "none", timeoutMs: 1 })).not.toContain("--pull=never");
  });

  it("reads records stored under the first outcome names", () => {
    const base = { schemaVersion: 1, harness: "0security-executed-poc/1", reason: "x", stepIds: [], startedAt: "2026-01-01T00:00:00.000Z", finishedAt: "2026-01-01T00:00:01.000Z" };
    const run = { status: "pass", reason: "criteria-met", command: "c", isolation: "container", durationMs: 1, logTail: "", imageDigest: `sha256:${"a".repeat(64)}` };
    expect(parseExecutedPoc({ ...base, outcome: "executed-proven", run })?.outcome).toBe("script-matched");
    expect(parseExecutedPoc({ ...base, outcome: "executed-proven" })).toBeUndefined();
  });

  it("snapshot exclusion keeps everything else", async () => {
    const dir = repo({ "a.txt": "a", ".env": "S=1" });
    const snap = await snapshotWorktree(dir, { exclude: looksSecret });
    cleanups.push(snap.cleanup);
    expect(existsSync(join(snap.dir, "a.txt"))).toBe(true);
    expect(existsSync(join(snap.dir, ".env"))).toBe(false);
  });
});

const hasDocker = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 10_000 }).status === 0;
/** Set ZERO_POC_TEST_IMAGE to a digest-pinned image that is already local; the test never pulls. */
const localImage = process.env.ZERO_POC_TEST_IMAGE;
const present = (image: string) => spawnSync("docker", ["image", "inspect", image], { stdio: "ignore" }).status === 0;

describe.skipIf(!hasDocker)("executed PoC against the real Docker daemon", () => {
  it("does not pull a missing image: the PoC is static-only and no registry is contacted", async () => {
    const dir = repo({ "app.js": "x" });
    const missing = `0-poc-no-such-image@sha256:${"0".repeat(64)}`;
    const record = await executePocForFinding({ finding: finding(`printf "%s-%s" ready marker`, "ready-marker"), folder: dir, runtime: createExecutedPoc({ image: missing }, new OciRunner()) });
    expect(record).toMatchObject({ outcome: "static-only", reason: "image-not-present-locally" });
  }, 60_000);

  it.skipIf(!localImage || !present(localImage))("runs on the read-only layout with a noexec tmpfs", async () => {
    const dir = repo({ "app.js": "console.log('from-app')\n", "run.sh": "#!/bin/sh\necho scripted\n" });
    const runtime = createExecutedPoc({ image: localImage! }, new OciRunner());
    const ok = await executePocForFinding({ finding: finding("node app.js; pwd", "from-app"), folder: dir, runtime });
    expect(ok).toMatchObject({ outcome: "script-matched", run: { isolation: "container" } });
    expect(ok!.run!.logTail).toContain("/sandbox/app");
    const write = await executePocForFinding({ finding: finding("touch /etc/x 2>&1 || echo root-readonly; touch /sandbox/ok && echo sandbox-writable", "root-readonly"), folder: dir, runtime });
    expect(write!.run!.logTail).toMatch(/sandbox-writable/);
    const exec = await executePocForFinding({ finding: finding("chmod +x run.sh; ./run.sh 2>&1 || echo exec-denied", "exec-denied"), folder: dir, runtime });
    expect(exec).toMatchObject({ outcome: "script-matched" });
    const net = await executePocForFinding({ finding: finding(`node -e "require('net').connect(80,'1.1.1.1').on('error',()=>console.log('no-network'))"`, "no-network"), folder: dir, runtime });
    expect(net).toMatchObject({ outcome: "script-matched" });
  }, 180_000);
});
