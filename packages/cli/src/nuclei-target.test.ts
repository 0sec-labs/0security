import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findNuclei, nucleiArguments, pinnedUrl, runNucleiTarget } from "./nuclei-target.js";

const directories: string[] = [];
const scratch = () => { const dir = mkdtempSync(join(tmpdir(), "0-nuclei-test-")); directories.push(dir); return dir; };
afterEach(() => directories.splice(0).forEach(path => rmSync(path, { recursive: true, force: true })));

const jsonl = readFileSync(new URL("../../engine/src/shared/__fixtures__/nuclei.jsonl", import.meta.url), "utf8");
/** A stand-in for nuclei: records its arguments and writes the fixture where -jle says. Real Nuclei is not used here. */
function fakeNuclei(dir: string, body = `cp "${join(dir, "fixture.jsonl")}" "$out"`): string {
  writeFileSync(join(dir, "fixture.jsonl"), jsonl);
  const path = join(dir, "nuclei");
  writeFileSync(path, `#!/bin/sh\nif [ "$1" = "-version" ]; then echo "[INF] Nuclei Engine Version: v3.9.9" >&2; exit 0; fi\nprintf '%s\\n' "$@" > "${join(dir, "args.txt")}"\nout=""; prev=""; for a in "$@"; do if [ "$prev" = "-jle" ]; then out="$a"; fi; prev="$a"; done\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
}
const loopback = { env: {} as NodeJS.ProcessEnv };

describe("findNuclei", () => {
  it("uses ZERO_NUCLEI_PATH, then PATH, and reports nothing when there is none", () => {
    const dir = scratch();
    const path = fakeNuclei(dir);
    expect(findNuclei({ ZERO_NUCLEI_PATH: path })).toBe(path);
    expect(findNuclei({ PATH: dir })).toBe(path);
    expect(findNuclei({ PATH: join(dir, "missing") })).toBeUndefined();
    expect(findNuclei({ ZERO_NUCLEI_PATH: join(dir, "missing") })).toBeUndefined();
  });
});

describe("nucleiArguments", () => {
  it("excludes intrusive, dos and fuzz templates, turns off out-of-band callbacks and update checks, and sets the limits", () => {
    const args = nucleiArguments({ url: "http://127.0.0.1:1", out: "/o.jsonl", rateLimit: 10, concurrency: 5 });
    expect(args.slice(args.indexOf("-etags"), args.indexOf("-etags") + 2)).toEqual(["-etags", "intrusive,dos,fuzz"]);
    expect(args).toEqual(expect.arrayContaining(["-ni", "-duc", "-rl", "10", "-c", "5"]));
    expect(args).not.toContain("-t");
  });
});

describe("pinnedUrl", () => {
  const target = (hostname: string, host: string, addresses: string[]) => ({ url: `http://${host}/x`, host, hostname, addresses, network: "loopback" as const, authorisedBy: ["acknowledged" as const] });
  it("gives Nuclei the checked address and keeps the name in the Host header and TLS server name", () => {
    const pinned = pinnedUrl(target("staging.test", "staging.test:8080", ["10.0.0.7", "10.0.0.8"]));
    expect(pinned).toEqual({ url: "http://10.0.0.7:8080/x", pin: { host: "staging.test:8080", hostname: "staging.test" } });
    const args = nucleiArguments({ ...pinned, out: "/o", rateLimit: 1, concurrency: 1 });
    expect(args).toEqual(expect.arrayContaining(["-H", "Host: staging.test:8080", "-sni", "staging.test"]));
    expect(pinnedUrl(target("fd00::1", "[fd00::1]:80", ["fd00::1"])).pin).toBeUndefined();
    expect(pinnedUrl(target("127.0.0.1", "127.0.0.1:80", ["127.0.0.1"])).pin).toBeUndefined();
    expect(pinnedUrl(target("v6.test", "v6.test", ["fd00::5"])).url).toBe("http://[fd00::5]/x");
  });
});

describe("runNucleiTarget", () => {
  it("runs the binary on the named target with conservative limits and reads its findings", async () => {
    const dir = scratch();
    const run = await runNucleiTarget({ targetUrl: "http://127.0.0.1:18089", acknowledgeHost: "127.0.0.1:18089" }, { env: { ZERO_NUCLEI_PATH: fakeNuclei(dir) } });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]).toMatchObject({ ruleId: "local-admin-panel-exposed", endpoint: "http://127.0.0.1:18089/admin", method: "GET", cwe: ["CWE-306"] });
    expect(run.rateLimit).toBe(10);
    expect(run.concurrency).toBe(5);
    expect(run.version).toBe("3.9.9");
    expect(run.scope).toContain("authorised by the typed host 127.0.0.1:18089");
    const args = readFileSync(join(dir, "args.txt"), "utf8").trim().split("\n");
    expect(args.slice(0, 2)).toEqual(["-u", "http://127.0.0.1:18089/"]);
    expect(args).toEqual(expect.arrayContaining(["-rl", "10", "-c", "5", "-etags", "intrusive,dos,fuzz", "-ni", "-duc"]));
  });
  it("starts Nuclei on the address it checked when the target is a name", async () => {
    const dir = scratch();
    await runNucleiTarget({ targetUrl: "http://localhost:18089", acknowledgeHost: "localhost" }, { env: { ZERO_NUCLEI_PATH: fakeNuclei(dir) }, resolve: async () => ["127.0.0.1"] });
    const args = readFileSync(join(dir, "args.txt"), "utf8").trim().split("\n");
    expect(args.slice(0, 2)).toEqual(["-u", "http://127.0.0.1:18089/"]);
    expect(args).toEqual(expect.arrayContaining(["-H", "Host: localhost:18089"]));
  });
  it("reads the scope file, and passes the rate limit and templates it was given", async () => {
    const dir = scratch();
    const scope = join(dir, "scope.txt");
    writeFileSync(scope, "# test app\n127.0.0.1:18089\n");
    await runNucleiTarget({ targetUrl: "http://127.0.0.1:18089", scopeFile: scope, rateLimit: 3, concurrency: 2, templates: "/t/one.yaml" }, { env: { ZERO_NUCLEI_PATH: fakeNuclei(dir) } });
    const args = readFileSync(join(dir, "args.txt"), "utf8").trim().split("\n");
    expect(args).toEqual(expect.arrayContaining(["-rl", "3", "-c", "2", "-t", "/t/one.yaml"]));
  });
  it("refuses before it starts Nuclei: public host without the typed host, metadata address, host not in scope file", async () => {
    const dir = scratch();
    const env = { ZERO_NUCLEI_PATH: fakeNuclei(dir) };
    const scope = join(dir, "scope.txt");
    writeFileSync(scope, "other.test\n");
    await expect(runNucleiTarget({ targetUrl: "https://app.example.com", scopeFile: scope }, { env, resolve: async () => ["203.0.113.9"] })).rejects.toThrow("not listed");
    await expect(runNucleiTarget({ targetUrl: "https://app.example.com", acknowledgeHost: "x.test" }, { env, resolve: async () => ["203.0.113.9"] })).rejects.toThrow("exactly");
    await expect(runNucleiTarget({ targetUrl: "https://app.example.com", scopeFile: scope.replace("scope", "nope") }, { env })).rejects.toThrow();
    await expect(runNucleiTarget({ targetUrl: "http://169.254.169.254/", acknowledgeHost: "169.254.169.254" }, { env })).rejects.toThrow("never tested");
    await expect(runNucleiTarget({ targetUrl: "http://127.0.0.1:1" }, { env })).rejects.toThrow("--scope-file");
    expect(() => readFileSync(join(dir, "args.txt"))).toThrow();
  });
  it("under ZERO_ENTERPRISE refuses a private target and still runs a loopback one", async () => {
    const dir = scratch();
    const env = { ZERO_NUCLEI_PATH: fakeNuclei(dir), ZERO_ENTERPRISE: "1" };
    await expect(runNucleiTarget({ targetUrl: "http://192.168.1.5", acknowledgeHost: "192.168.1.5" }, { env })).rejects.toThrow("ZERO_ENTERPRISE");
    expect((await runNucleiTarget({ targetUrl: "http://127.0.0.1:18089", acknowledgeHost: "127.0.0.1:18089" }, { env })).findings).toHaveLength(1);
  });
  it("says plainly when Nuclei is not installed, and never downloads it", async () => {
    await expect(runNucleiTarget({ targetUrl: "http://127.0.0.1:1", acknowledgeHost: "127.0.0.1:1" }, { env: { PATH: "/nonexistent" } })).rejects.toThrow(/Nuclei is not installed.*never downloads/);
  });
  it("rejects limits outside the allowed range", async () => {
    const env = { ZERO_NUCLEI_PATH: fakeNuclei(scratch()) };
    await expect(runNucleiTarget({ targetUrl: "http://127.0.0.1:1", acknowledgeHost: "127.0.0.1:1", rateLimit: 1000 }, { env })).rejects.toThrow("--rate-limit");
    await expect(runNucleiTarget({ targetUrl: "http://127.0.0.1:1", acknowledgeHost: "127.0.0.1:1", concurrency: 0 }, { env })).rejects.toThrow("--concurrency");
  });
  it("reports the missing-templates failure with the way forward, and a run with no findings as empty", async () => {
    const noTemplates = fakeNuclei(scratch(), `echo "[FTL] Could not run nuclei: no templates provided for scan" >&2; exit 1`);
    await expect(runNucleiTarget({ targetUrl: "http://127.0.0.1:1", acknowledgeHost: "127.0.0.1:1" }, { env: { ZERO_NUCLEI_PATH: noTemplates } })).rejects.toThrow("nuclei -update-templates");
    const none = fakeNuclei(scratch(), "true");
    expect((await runNucleiTarget({ targetUrl: "http://127.0.0.1:1", acknowledgeHost: "127.0.0.1:1" }, { env: { ZERO_NUCLEI_PATH: none } })).findings).toEqual([]);
  });
});
