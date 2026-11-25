/**
 * What runs for real here: the fixture apps start on loopback on this machine, the in-container script runs under
 * sh, a real HTTP request reaches a real canary file. What is FAKE: the container. HostBackedRunner copies the
 * snapshot to a scratch folder and runs the script on the host. There is no isolation and the network is not cut, so
 * it says so (isolation "host"), and its results are unisolated: never reproduced, never not-reproduced.
 * The reproduced and not-reproduced classification is tested separately with a canned runner that stands in for a
 * container. No real container ran in these tests.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { ContainerRunner, StepOutcome, StepRequest } from "../verifier/port.js";
import { exec } from "../verifier/process.js";
import { HostRunner } from "../verifier/host-runner.js";
import { parseFindingReproduction, proposeProof, type ReproProof } from "../shared/reproduction.js";
import { REPRODUCTION_LIMITS, REPRODUCTION_TIMEOUT_MS, hashAppFiles, reproduceFinding } from "./harness.js";
import { planPathTraversal } from "./path-traversal.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "../../../../scripts/bench/repro-fixtures/path-traversal");
const IMAGE = `node:24-bookworm-slim@sha256:${"c".repeat(64)}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const scratch: string[] = [];
afterEach(() => { for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true }); });

/** NOT a container: runs the command on the host in a scratch copy whose parent is also scratch. */
class HostBackedRunner implements ContainerRunner {
  readonly isolation = "host" as const;
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
const ACK = "REPRO_FIXTURE_ACK=intentionally-vulnerable node server.js";
const base = (dir: string, start = ACK) => ({ proof: traversal, snapshotDir: dir, commit: COMMIT, image: IMAGE, port: nextPort++, start, allowUnisolated: true });
const appDir = (source: string): string => { const dir = mkdtempSync(join(tmpdir(), "0-repro-app-")); scratch.push(dir); writeFileSync(join(dir, "server.js"), source); return dir; };

describe("recipe planning", () => {
  it("aims the traversal at the canary and builds a control without it", () => {
    const planned = planPathTraversal(traversal);
    expect(planned).toEqual({ ok: true, plan: { attackPath: "/download?name=../../@@CANARY@@", controlPath: "/download?name=@@CANARY@@", canaryExt: ".txt" } });
  });
  it.each([
    ["a POST", proof("/download?name=../x", "POST"), "only-get-requests-are-supported"],
    ["an encoded payload", proof("/download?name=%2e%2e/x"), "encoded-payloads-are-not-supported"],
    ["no traversal", proof("/download?name=hello.txt"), "no-traversal-in-the-request"],
  ])("does not plan %s", (_n, p, reason) => expect(planPathTraversal(p)).toEqual({ ok: false, reason }));
});

describe("fixture app, run for real on loopback (not a container, so unisolated)", () => {
  it("returns the canary on the vulnerable app, but an unisolated run is never reproduced", async () => {
    const result = await reproduceFinding({ ...base(join(FIXTURES, "vulnerable")), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "inconclusive", reason: "unisolated-run-canary-observed", isolation: "unisolated", commit: COMMIT, canary: { observed: true } });
    expect(result.appSha256).toBe(hashAppFiles(join(FIXTURES, "vulnerable")));
    expect(parseFindingReproduction({ result })?.result?.status).toBe("inconclusive");
  }, 60_000);

  it("does not return the canary on the fixed app", async () => {
    const result = await reproduceFinding({ ...base(join(FIXTURES, "fixed")), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "inconclusive", reason: "unisolated-run-canary-absent", isolation: "unisolated", canary: { observed: false } });
  }, 60_000);

  it("refuses to run the vulnerable fixture without its acknowledgement", async () => {
    const result = await reproduceFinding({ ...base(join(FIXTURES, "vulnerable"), "node server.js"), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "inconclusive", reason: "app-did-not-start" });
  }, 60_000);

  it("refuses a runner that is not a container unless a test allows it", async () => {
    const result = await reproduceFinding({ ...base(join(FIXTURES, "vulnerable")), allowUnisolated: false, runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "error", reason: "no-container-isolation" });
  });

  it("is inconclusive when the app serves the canary without any traversal", async () => {
    const dir = appDir('const h=require("http"),f=require("fs"),p=require("path");h.createServer((q,r)=>{const u=new URL(q.url,"http://x");f.readFile(p.join(__dirname,u.searchParams.get("name")||"x"),(e,d)=>{r.writeHead(e?404:200);r.end(d||"no")})}).listen(Number(process.env.PORT),"127.0.0.1");');
    const result = await reproduceFinding({ ...base(dir, "node server.js"), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "inconclusive", reason: "canary-served-without-traversal" });
  }, 60_000);

  it("is inconclusive, not not-reproduced, when the app never starts", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-repro-app-"));
    scratch.push(dir);
    const result = await reproduceFinding({ ...base(dir, "node server.js"), runner: new HostBackedRunner() });
    expect(result).toMatchObject({ status: "inconclusive", reason: "app-did-not-start" });
    expect(result.canary).toBeUndefined();
  }, 60_000);
});

describe("an untrusted app cannot get a hit without a request that reaches the canary", () => {
  // The canary does not exist until the app is up and answering, and nothing about it is in the app's environment.
  const listen = 'require("http").createServer(handler).listen(Number(process.env.PORT),"127.0.0.1");';
  const run = (source: string) => reproduceFinding({ ...base(appDir(source), "node server.js"), runner: new HostBackedRunner() });

  it("an app that dumps its environment and every file it can read at startup, then replays that, gets no hit", async () => {
    const result = await run(
      'const fs=require("fs"),path=require("path");' +
      'const grab=()=>{let t=JSON.stringify(process.env);for(const d of [__dirname,path.dirname(__dirname)]){try{for(const f of fs.readdirSync(d)){try{t+=fs.readFileSync(path.join(d,f),"utf8")}catch(e){}}}catch(e){}}return t};' +
      'const early=grab();console.log(early);' +
      'const handler=(q,r)=>{r.writeHead(200);r.end(early)};' + listen,
    );
    expect(result).toMatchObject({ status: "inconclusive", reason: "unisolated-run-canary-absent", canary: { observed: false } });
  }, 60_000);

  it("an app that reads the whole folder and its parent on every request is caught by the control request", async () => {
    const result = await run(
      'const fs=require("fs"),path=require("path");' +
      'const handler=(q,r)=>{let t="";for(const d of [__dirname,path.dirname(__dirname)]){try{for(const f of fs.readdirSync(d)){try{t+=fs.readFileSync(path.join(d,f),"utf8")}catch(e){}}}catch(e){}}r.writeHead(200);r.end(t)};' + listen,
    );
    expect(result).toMatchObject({ status: "inconclusive", reason: "canary-served-without-traversal" });
  }, 60_000);

  it("ignores a result line the app prints itself", async () => {
    const result = await reproduceFinding({
      ...base(appDir('console.log("0REPRO-" + "b".repeat(32) + " {\\"listening\\":true,\\"token\\":\\"" + "e".repeat(32) + "\\",\\"attack\\":{\\"hit\\":true}}");const handler=(q,r)=>{r.writeHead(404);r.end("no")};' + listen), "node server.js"),
      runner: new HostBackedRunner(), randomHex: (n) => "b".repeat(n * 2),
    });
    expect(result.reason).toBe("unisolated-run-canary-absent");
  }, 60_000);

  it("KNOWN LIMIT: an app built to lie, that finds the planted file when it sees ../ in a request, can still fake a hit", async () => {
    const result = await run(
      'const fs=require("fs"),path=require("path");' +
      'const handler=(q,r)=>{if(!q.url.includes("..")){r.writeHead(404);return r.end("no")}let t="";for(const d of [__dirname,path.dirname(__dirname)]){try{for(const f of fs.readdirSync(d)){if(f.startsWith("0-canary-"))t+=fs.readFileSync(path.join(d,f),"utf8")}}catch(e){}}r.writeHead(200);r.end(t)};' + listen,
    );
    // Only the observation "the app as run returned the canary" holds. It says nothing about the app's code.
    expect(result.canary?.observed).toBe(true);
  }, 60_000);

  it("keeps the canary token and file name out of the command text", async () => {
    let command = "";
    const spy: ContainerRunner = { isolation: "container", async probe() { return { ok: true, runtime: "fake" }; }, async run(request) { command = request.command; return { exitCode: 0, output: "", timedOut: false, durationMs: 1 }; } };
    await reproduceFinding({ proof: traversal, snapshotDir: join(FIXTURES, "fixed"), commit: COMMIT, image: IMAGE, runner: spy });
    expect(command).not.toMatch(/0-canary-[0-9a-f]/);
    expect(command).not.toMatch(/\bTOKEN=|canary [^"]*[0-9a-f]{32}/);
  });
});

describe("container limits", () => {
  it("asks the runner for process, memory, CPU, tmpfs and storage caps and a wall-clock timeout", async () => {
    let seen: StepRequest | undefined;
    const spy: ContainerRunner = { isolation: "container", async probe() { return { ok: true, runtime: "fake" }; }, async run(request) { seen = request; return { exitCode: 0, output: "", timedOut: false, durationMs: 1, limitsNotApplied: ["storage-size"] }; } };
    const result = await reproduceFinding({ proof: traversal, snapshotDir: join(FIXTURES, "fixed"), commit: COMMIT, image: IMAGE, runner: spy });
    expect(seen?.limits).toEqual(REPRODUCTION_LIMITS);
    expect(REPRODUCTION_LIMITS).toMatchObject({ pidsLimit: 128, memory: "512m", cpus: "1", storageSize: "256m", tmpfs: ["/tmp:rw,size=64m,noexec,nosuid"] });
    expect(seen?.timeoutMs).toBe(REPRODUCTION_TIMEOUT_MS);
    expect(seen?.network).toBe("none");
    expect(result.logTail).toContain("limits not applied: storage-size");
  });
});

describe("storage cap fails closed", () => {
  const refusing: ContainerRunner = { isolation: "container", async probe() { return { ok: true, runtime: "fake" }; }, async run() { return { exitCode: null, output: "", timedOut: false, durationMs: 1, infraError: "storage limit unavailable: reproduction refused" }; } };
  const optedOut: ContainerRunner = { isolation: "container", async probe() { return { ok: true, runtime: "fake" }; }, async run(request) {
    const nonce = /0REPRO-([0-9a-f]+)/.exec(request.command)![1]!;
    return { exitCode: 0, output: `0REPRO-${nonce} ${JSON.stringify({ listening: true, token: "a1".repeat(16), control: { hit: false }, attack: { hit: true } })}\n0ALIVE-${nonce} 1\n`, timedOut: false, durationMs: 1, limitsNotApplied: request.limits?.allowUnboundedStorage ? ["storage-size"] : [] };
  } };
  const input = { proof: traversal, snapshotDir: join(FIXTURES, "fixed"), commit: COMMIT, image: IMAGE };

  it("returns error, not a result, when the cap cannot be applied", async () => {
    const result = await reproduceFinding({ ...input, runner: refusing });
    expect(result).toMatchObject({ status: "error", reason: "storage-limit-unavailable", logTail: "storage limit unavailable: reproduction refused" });
    expect(result.canary).toBeUndefined();
  });

  it("passes the operator's opt-out to the runner only when set, and records it in the result", async () => {
    let seen: StepRequest | undefined;
    const spy: ContainerRunner = { ...optedOut, run: (request) => { seen = request; return optedOut.run(request); } };
    await reproduceFinding({ ...input, runner: spy });
    expect(seen?.limits?.allowUnboundedStorage).toBeUndefined();
    const result = await reproduceFinding({ ...input, runner: spy, allowUnboundedStorage: true });
    expect(seen?.limits?.allowUnboundedStorage).toBe(true);
    expect(result).toMatchObject({ status: "reproduced", storageUnbounded: true });
    expect(result.logTail).toContain("limits not applied: storage-size");
    expect(parseFindingReproduction({ result })?.result?.storageUnbounded).toBe(true);
  });

  it("does not mark a run unbounded when the cap applied", async () => {
    const result = await reproduceFinding({ ...input, runner: optedOut });
    expect(result.storageUnbounded).toBeUndefined();
  });
});

describe("hashing the app files", () => {
  it("is stable, and changes when a file changes", () => {
    const dir = appDir("a");
    const first = hashAppFiles(dir);
    expect(hashAppFiles(dir)).toBe(first);
    writeFileSync(join(dir, "server.js"), "b");
    expect(hashAppFiles(dir)).not.toBe(first);
    expect(hashAppFiles(join(FIXTURES, "vulnerable"))).not.toBe(hashAppFiles(join(FIXTURES, "fixed")));
  });
});

describe("classification with a canned runner", () => {
  const run = (client: (n: string) => string, extra?: Partial<StepOutcome>, input: Record<string, unknown> = {}) =>
    reproduceFinding({ proof: traversal, snapshotDir: join(FIXTURES, "fixed"), commit: COMMIT, image: IMAGE, runner: cannedRunner(client, extra), ...input });
  const TOKEN = "a1".repeat(16);
  const line = (n: string, body: unknown) => `0REPRO-${n} ${JSON.stringify(body)}`;

  it("reproduced needs the canary in the attack response", async () => {
    const hit = await run((n) => line(n, { listening: true, token: TOKEN, control: { status: 404, hit: false }, attack: { status: 200, hit: true } }), undefined, { snapshotDir: join(FIXTURES, "fixed") });
    expect(hit).toMatchObject({ status: "reproduced", isolation: "container", canary: { token: TOKEN, observed: true }, appSha256: hashAppFiles(join(FIXTURES, "fixed")) });
    expect(parseFindingReproduction({ result: hit })?.result?.status).toBe("reproduced");
    expect((await run((n) => line(n, { listening: true, token: TOKEN, control: { status: 404, hit: false }, attack: { status: 200, hit: false } }))).status).toBe("not-reproduced");
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
    const result = await run((n) => `API_TOKEN=supersecretvalue99\n${line(n, { listening: true, token: TOKEN, attack: { hit: false } })}`);
    expect(result.logTail).not.toContain("supersecretvalue99");
  });
});

describe("the intentionally vulnerable fixture", () => {
  const source = readFileSync(join(FIXTURES, "vulnerable/server.js"), "utf8");
  it("is labelled, binds to loopback only, and refuses to start without its acknowledgement", () => {
    expect(source).toMatch(/^\/\/ INTENTIONALLY VULNERABLE TEST FIXTURE/);
    expect(source).toMatch(/REPRO_FIXTURE_ACK !== "intentionally-vulnerable"/);
    const listens = source.split("\n").filter((l) => l.includes(".listen("));
    expect(listens.length).toBeGreaterThan(0);
    expect(listens.every((l) => l.includes('"127.0.0.1"'))).toBe(true);
  });
  it("serves nothing above the folder that holds its copy, and only to loopback peers", async () => {
    expect(source).toMatch(/LOOPBACK\.has\(req\.socket\.remoteAddress\)/);
    const parent = mkdtempSync(join(tmpdir(), "0-repro-fx-"));
    scratch.push(parent);
    const work = join(parent, "work");
    cpSync(join(FIXTURES, "vulnerable"), work, { recursive: true });
    writeFileSync(join(parent, "inside.txt"), "inside-the-limit");
    const port = nextPort++;
    const child = spawn("node", ["server.js"], { cwd: work, env: { ...process.env, PORT: String(port), REPRO_FIXTURE_ACK: "intentionally-vulnerable" }, stdio: "ignore" });
    try {
      let reached = false;
      for (let i = 0; i < 40 && !reached; i++) { try { await fetch(`http://127.0.0.1:${port}/`); reached = true; } catch { await new Promise((r) => setTimeout(r, 100)); } }
      expect(reached).toBe(true);
      const get = async (name: string) => { const r = await fetch(`http://127.0.0.1:${port}/download?name=${name}`); return { status: r.status, text: await r.text() }; };
      expect(await get("hello.txt")).toMatchObject({ status: 200 });
      expect(await get("../../inside.txt")).toEqual({ status: 200, text: "inside-the-limit" }); // the planted flaw: leaves public/
      expect(await get("../../../../../../../../etc/hosts")).toMatchObject({ status: 403 }); // but never leaves the temp folder
    } finally { child.kill("SIGKILL"); }
  }, 30_000);
  it("has no package.json, no start script and no workflow that runs it", () => {
    for (const variant of ["vulnerable", "fixed"]) expect(existsSync(join(FIXTURES, variant, "package.json"))).toBe(false);
    const root = join(FIXTURES, "../../../..");
    const workflows = join(root, ".github/workflows");
    for (const file of readdirSync(workflows)) expect(readFileSync(join(workflows, file), "utf8")).not.toContain("repro-fixtures");
    expect(readFileSync(join(root, "package.json"), "utf8")).not.toContain("repro-fixtures");
  });
});
