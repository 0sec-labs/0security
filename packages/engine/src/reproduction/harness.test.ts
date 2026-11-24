/**
 * What runs for real here: the fixture apps start on loopback on this machine, the in-container script runs under
 * sh, a real HTTP request reaches a real canary file. What is FAKE: the container. HostBackedRunner copies the
 * snapshot to a scratch folder and runs the script on the host. There is no isolation and the network is not cut.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cpSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ContainerRunner, StepOutcome, StepRequest } from "../verifier/port.js";
import { exec } from "../verifier/process.js";
import { HostRunner } from "../verifier/host-runner.js";
import { parseFindingReproduction, proposeProof, type ReproProof } from "../shared/reproduction.js";
import { reproduceFinding } from "./harness.js";
import { planPathTraversal } from "./path-traversal.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "../../../../scripts/bench/repro-fixtures/path-traversal");
const IMAGE = `node:24-bookworm-slim@sha256:${"c".repeat(64)}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const scratch: string[] = [];
afterEach(() => { for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true }); });

/** FAKE container: runs the command on the host in a scratch copy whose parent is also scratch. */
class HostBackedRunner implements ContainerRunner {
  readonly isolation = "container" as const;
  async probe() { return { ok: true as const, runtime: "fake" }; }
  async run(request: StepRequest): Promise<StepOutcome> {
    const parent = mkdtempSync(join(tmpdir(), "0-repro-fake-"));
    scratch.push(parent);
    const work = join(parent, "work");
    cpSync(request.dir, work, { recursive: true });
    const r = await exec("sh", ["-c", request.command], { cwd: work, timeoutMs: request.timeoutMs });
    return { exitCode: r.code, output: r.output, timedOut: r.timedOut, durationMs: 1 };
  }
}

/** Pure fake: answers with a canned client line, using the nonce found in the command. */
function cannedRunner(client: (nonce: string) => string, extra: Partial<StepOutcome> = {}): ContainerRunner {
  return {
    isolation: "container",
    async probe() { return { ok: true, runtime: "fake" }; },
    async run(request) {
      const nonce = /0REPRO-([0-9a-f]+)/.exec(request.command)![1]!;
      return { exitCode: 0, output: `${client(nonce)}\n0ALIVE-${nonce} 1\n--- app log ---\n`, timedOut: false, durationMs: 1, ...extra };
    },
  };
}

const proof = (path: string, method = "GET"): ReproProof => proposeProof({ pocSteps: [{ id: "e", kind: "exploit", summary: "x", action: { type: "http", method, url: `http://victim.example${path}` } }] })!;
const traversal = proof("/download?name=../../etc/passwd");
let nextPort = 41000 + Math.floor(Math.random() * 5000);
const base = (dir: string) => ({ proof: traversal, snapshotDir: dir, commit: COMMIT, image: IMAGE, port: nextPort++ });

describe("recipe planning", () => {
  it("aims the traversal at the canary and builds a control without it", () => {
    const planned = planPathTraversal(traversal);
    expect(planned).toMatchObject({ ok: true, plan: { attackPath: "/download?name=../../0-canary.txt", controlPath: "/download?name=0-canary.txt", canaryName: "0-canary.txt" } });
  });
  it.each([
    ["a POST", proof("/download?name=../x", "POST"), "only-get-requests-are-supported"],
    ["an encoded payload", proof("/download?name=%2e%2e/x"), "encoded-payloads-are-not-supported"],
    ["no traversal", proof("/download?name=hello.txt"), "no-traversal-in-the-request"],
  ])("does not plan %s", (_n, p, reason) => expect(planPathTraversal(p)).toEqual({ ok: false, reason }));
});

describe("fixture app, run for real on loopback (container faked)", () => {
  it("reproduces on the vulnerable app and stores as a complete harness record", async () => {
    const result = await reproduceFinding({ ...base(join(FIXTURES, "vulnerable")), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "reproduced", reason: "canary-observed", commit: COMMIT, isolation: "container", imageDigest: `sha256:${"c".repeat(64)}`, canary: { observed: true } });
    expect(parseFindingReproduction({ result })?.result?.status).toBe("reproduced");
  }, 60_000);

  it("says not-reproduced on the fixed app", async () => {
    const result = await reproduceFinding({ ...base(join(FIXTURES, "fixed")), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "not-reproduced", reason: "canary-absent", canary: { observed: false } });
  }, 60_000);

  it("is inconclusive when the app serves the canary without any traversal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-repro-app-"));
    scratch.push(dir);
    mkdirSync(join(dir, "public"));
    writeFileSync(join(dir, "server.js"), 'const h=require("http"),f=require("fs"),p=require("path");h.createServer((q,r)=>{const u=new URL(q.url,"http://x");f.readFile(p.join(__dirname,u.searchParams.get("name")||"x"),(e,d)=>{r.writeHead(e?404:200);r.end(d||"no")})}).listen(Number(process.env.PORT),"127.0.0.1");');
    const result = await reproduceFinding({ ...base(dir), runner: new HostBackedRunner() });
    expect(result.status).toBe("inconclusive");
    expect(result.reason).toBe("canary-served-without-traversal");
  }, 60_000);

  it("is inconclusive, not not-reproduced, when the app never starts", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-repro-app-"));
    scratch.push(dir);
    const result = await reproduceFinding({ ...base(dir), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "inconclusive", reason: "app-did-not-start" });
    expect(result.canary).toBeUndefined();
  }, 60_000);

  it("ignores a result line the app prints itself", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-repro-app-"));
    scratch.push(dir);
    writeFileSync(join(dir, "server.js"), 'console.log("0REPRO-" + "a".repeat(32) + " {\\"listening\\":true,\\"attack\\":{\\"hit\\":true}}");require("http").createServer((q,r)=>{r.writeHead(404);r.end("no")}).listen(Number(process.env.PORT),"127.0.0.1");');
    const result = await reproduceFinding({ ...base(dir), runner: new HostBackedRunner(), randomHex: (n) => "b".repeat(n * 2) });
    expect(result.status).toBe("not-reproduced");
  }, 60_000);
});

describe("classification with a canned runner", () => {
  const run = (client: (n: string) => string, extra?: Partial<StepOutcome>, input: Record<string, unknown> = {}) =>
    reproduceFinding({ proof: traversal, snapshotDir: "/unused", commit: COMMIT, image: IMAGE, runner: cannedRunner(client, extra), ...input });
  const line = (n: string, body: unknown) => `0REPRO-${n} ${JSON.stringify(body)}`;

  it("reproduced needs the canary in the attack response", async () => {
    expect((await run((n) => line(n, { listening: true, control: { status: 404, hit: false }, attack: { status: 200, hit: true } }))).status).toBe("reproduced");
    expect((await run((n) => line(n, { listening: true, control: { status: 404, hit: false }, attack: { status: 200, hit: false } }))).status).toBe("not-reproduced");
  });
  it("a missing or malformed client line is inconclusive", async () => {
    expect(await run(() => "nothing")).toMatchObject({ status: "inconclusive", reason: "no-client-result" });
    expect(await run((n) => `0REPRO-${n} {oops`)).toMatchObject({ status: "inconclusive", reason: "unreadable-client-result" });
  });
  it("a timeout is inconclusive and a runner failure is an error", async () => {
    expect(await run(() => "", { timedOut: true })).toMatchObject({ status: "inconclusive", reason: "timeout" });
    expect(await run(() => "", { infraError: "could not pull image" })).toMatchObject({ status: "error", reason: "runner-failed" });
  });
  it("refuses an unpinned image, a host runner, a missing runtime and a bad start command", async () => {
    expect(await run(() => "", {}, { image: "node:24" })).toMatchObject({ status: "error", reason: "image-not-pinned-by-digest" });
    expect(await run(() => "", {}, { runner: new HostRunner() })).toMatchObject({ status: "error", reason: "no-container-isolation" });
    expect(await run(() => "", {}, { start: "node a.js\nrm -rf /" })).toMatchObject({ status: "error", reason: "unusable-start-command" });
    expect(await run(() => "", {}, { runner: { isolation: "container", probe: async () => ({ ok: false, reason: "no daemon" }), run: async () => { throw new Error("unreachable"); } } })).toMatchObject({ status: "error", reason: "no-container-runtime" });
  });
  it("no proposed steps, or steps this class cannot replay, are inconclusive", async () => {
    expect(await run(() => "", {}, { proof: undefined })).toMatchObject({ status: "inconclusive", reason: "no-proposed-steps" });
    expect(await run(() => "", {}, { proof: proof("/x?name=a") })).toMatchObject({ status: "inconclusive", reason: "no-traversal-in-the-request" });
  });
  it("redacts the log tail", async () => {
    const result = await run((n) => `API_TOKEN=supersecretvalue99\n${line(n, { listening: true, attack: { hit: false } })}`);
    expect(result.logTail).not.toContain("supersecretvalue99");
  });
});
