import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { dockerRunArgs, isPinnedImage, makeSandboxCache, NETWORK_CANARY, networkCanary, runInSandbox, sandboxLabel, validateSandboxImage } from "../fix-sandbox.js";
import { pullRequestBody, runFix, sandboxSpec, sandboxVerifiedLine, type CheckResult, type FindingToFix, type FixOptions } from "../fix.js";

const finding: FindingToFix = { id: "f-1234567890ab", fingerprint: "x", title: "Vulnerable dependency", severity: "high", category: "dependency", tool: "0", description: "d", path: "pom.xml", startLine: 3 };
const spec = { image: "maven:3-eclipse-temurin-21", network: false };

/** A fake docker that records its arguments and exits with a chosen code. Nothing real runs. */
function fakeDocker(script: string): { env: NodeJS.ProcessEnv; log: string } {
  const root = mkdtempSync(join(tmpdir(), "0-fakedocker-"));
  const bin = join(root, "bin"); mkdirSync(bin);
  const log = join(root, "args.log");
  writeFileSync(join(bin, "docker"), `#!/bin/sh\nprintf '%s\\n' "$@" >> "${log}"\n${script}\n`);
  chmodSync(join(bin, "docker"), 0o755);
  return { env: { PATH: `${bin}:/usr/bin:/bin`, OPENAI_API_KEY: "must-not-reach-docker" }, log };
}
const tree = (): string => { const dir = mkdtempSync(join(tmpdir(), "0-sbx-tree-")); mkdirSync(join(dir, ".git")); writeFileSync(join(dir, ".git", "config"), "secret"); writeFileSync(join(dir, "pom.xml"), "<project/>"); return dir; };

describe("docker run arguments", () => {
  it("has no network, limits, no capabilities and no host environment by default", () => {
    const args = dockerRunArgs(spec, "n", "/copy", "mvn -q test", { uid: 501, gid: 20 });
    expect(args.slice(0, 3)).toEqual(["run", "--rm", "--name"]);
    expect(args).toContain("--network"); expect(args[args.indexOf("--network") + 1]).toBe("none");
    expect(args).toEqual(expect.arrayContaining(["--memory", "--cpus", "--pids-limit", "--cap-drop", "ALL", "no-new-privileges"]));
    expect(args).toEqual(expect.arrayContaining(["-v", "/copy:/work", "--user", "501:20"]));
    expect(args.slice(-5, -1)).toEqual(["--entrypoint", "/bin/sh", "maven:3-eclipse-temurin-21", "-c"]);
    expect(args.at(-1)).toMatch(/not visible inside the container[\s\S]*\nmvn -q test$/);
    expect(args.filter(arg => arg === "-e")).toHaveLength(2); // HOME and CI only
  });
  it("leaves the network on only when asked", () => {
    expect(dockerRunArgs({ ...spec, network: true }, "n", "/c", "x")).not.toContain("--network");
    expect(sandboxLabel(spec)).toBe("maven:3-eclipse-temurin-21, network off");
    expect(sandboxLabel({ ...spec, network: true })).toBe("maven:3-eclipse-temurin-21, network on");
  });
  it("rejects an image that could be read as an option or has spaces", () => {
    expect(() => validateSandboxImage("--privileged")).toThrow();
    expect(() => validateSandboxImage("a b")).toThrow();
    expect(() => validateSandboxImage("")).toThrow();
    expect(validateSandboxImage("ghcr.io/org/app@sha256:" + "a".repeat(64))).toContain("ghcr.io");
  });
});

describe("runInSandbox with a fake docker", () => {
  it("passes the command and a copy without .git, and reports the exit code and output", async () => {
    const fake = fakeDocker("echo built; exit 0");
    const dir = tree();
    const result = await runInSandbox(dir, "mvn -q test", spec, { env: fake.env });
    expect(result).toMatchObject({ code: 0, sandbox: "maven:3-eclipse-temurin-21, network off" });
    expect(result.output).toContain("built");
    const args = readFileSync(fake.log, "utf8").split("\n");
    expect(args.join("\n")).toContain("\nmvn -q test");
    const mount = args[args.indexOf("-v") + 1]!.split(":/work")[0]!;
    expect(mount).not.toBe(dir); // the mounted folder is a copy, and it is gone afterwards
    expect(existsSync(mount)).toBe(false);
    expect(existsSync(join(dir, ".git", "config"))).toBe(true);
  });
  it("does not copy .git into the sandbox", async () => {
    const fake = fakeDocker('for a in "$@"; do case "$a" in *:/work) d="${a%:/work}"; ls -A "$d";; esac; done');
    const result = await runInSandbox(tree(), "x", spec, { env: fake.env });
    expect(result.output).toContain("pom.xml");
    expect(result.output).not.toContain(".git");
  });
  it("does not give the docker process the host's other environment", async () => {
    const fake = fakeDocker('echo "key=[$OPENAI_API_KEY]"');
    expect((await runInSandbox(tree(), "x", spec, { env: fake.env })).output).toContain("key=[]");
  });
  it("reports a failing command as a failed check", async () => {
    expect(await runInSandbox(tree(), "x", spec, { env: fakeDocker("echo FAIL >&2; exit 1").env })).toMatchObject({ code: 1 });
  });
  it("treats a Docker failure as a failed check with the reason, never a pass", async () => {
    const result = await runInSandbox(tree(), "x", spec, { env: fakeDocker("echo 'Unable to find image' >&2; exit 125").env });
    expect(result.code).toBe(125);
    expect(result.output).toContain("docker could not start the container");
  });
  it("says so when docker is missing", async () => {
    const result = await runInSandbox(tree(), "x", spec, { env: { PATH: "/nonexistent" } });
    expect(result).toMatchObject({ code: 127 });
    expect(result.output).toContain("docker is not installed");
  });
  it("stops a command that runs too long and asks Docker to kill the container", async () => {
    const fake = fakeDocker('case "$1" in kill) exit 0;; esac\nexec sleep 30');
    const result = await runInSandbox(tree(), "x", spec, { env: fake.env, timeoutMs: 300 });
    expect(result.code).toBe(124);
    expect(readFileSync(fake.log, "utf8")).toContain("kill");
  });
  it("stops output that is too large", async () => {
    const result = await runInSandbox(tree(), "x", spec, { env: fakeDocker("head -c 6000000 /dev/zero | tr '\\0' a").env });
    expect(result.output).toContain("printed more than");
    expect(result.code).toBe(1);
  });
  it("never follows or fails on a pre-existing symlink or directory at .0-sandbox-probe", async () => {
    const dirWithDirProbe = tree();
    mkdirSync(join(dirWithDirProbe, ".0-sandbox-probe"));
    const dirProbeRes = await runInSandbox(dirWithDirProbe, "x", spec, { env: { PATH: "/nonexistent" } });
    expect(dirProbeRes.code).toBe(127);

    const outside = mkdtempSync(join(tmpdir(), "0-sbx-outside-"));
    const targetFile = join(outside, "host-secret.txt");
    writeFileSync(targetFile, "host-data");
    const dirWithLinkProbe = tree();
    try {
      let linked = false;
      try {
        symlinkSync(targetFile, join(dirWithLinkProbe, ".0-sandbox-probe"));
        linked = true;
      } catch (err) {
        if (process.platform !== "win32" || (err as NodeJS.ErrnoException).code !== "EPERM") throw err;
      }
      if (linked) {
        const linkRes = await runInSandbox(dirWithLinkProbe, "x", spec, { env: { PATH: "/nonexistent" } });
        expect(linkRes.code).toBe(127);
        expect(readFileSync(targetFile, "utf8")).toBe("host-data");
      }
    } finally {
      rmSync(outside, { recursive: true, force: true });
      rmSync(dirWithDirProbe, { recursive: true, force: true });
      rmSync(dirWithLinkProbe, { recursive: true, force: true });
    }
  });
});

describe("sandbox options", () => {
  const base: FixOptions = { budget: "3", timeout: "60", pr: true };
  it("needs an image and a test command, and rejects other modes", () => {
    expect(() => sandboxSpec({ ...base, sandbox: "docker", test: ["t"] })).toThrow(/--sandbox-image/);
    expect(() => sandboxSpec({ ...base, sandbox: "docker", sandboxImage: "a:1" })).toThrow(/--test/);
    expect(() => sandboxSpec({ ...base, sandbox: "vm", sandboxImage: "a:1", test: ["t"] })).toThrow(/must be docker/);
    expect(() => sandboxSpec({ ...base, sandboxImage: "a:1" })).toThrow(/need --sandbox docker/);
    expect(sandboxSpec({ ...base })).toBeUndefined();
  });
  it("is off for the network by default, and refuses the network under ZERO_ENTERPRISE", () => {
    expect(sandboxSpec({ ...base, sandbox: "docker", sandboxImage: "a:1", test: ["t"] })).toEqual({ image: "a:1", network: false });
    expect(sandboxSpec({ ...base, sandbox: "docker", sandboxImage: "a:1", test: ["t"], sandboxNetwork: true }, {})).toEqual({ image: "a:1", network: true });
    expect(() => sandboxSpec({ ...base, sandbox: "docker", sandboxImage: "a:1", test: ["t"], sandboxNetwork: true }, { ZERO_ENTERPRISE: "1" })).toThrow(/ZERO_ENTERPRISE/);
  });
});

describe("pull request body", () => {
  const check = (code: number, sandbox?: string): CheckResult => ({ command: "mvn -q test", code, output: "o", ...(sandbox ? { sandbox } : {}) });
  it("says verified in a sandbox only when every check ran there and passed", () => {
    expect(pullRequestBody(finding, "s", [check(0, "maven:3, network off")])).toContain("Verified in a sandbox: maven:3, network off.");
    expect(pullRequestBody(finding, "s", [check(1, "maven:3, network off")])).not.toContain("Verified in a sandbox");
    expect(pullRequestBody(finding, "s", [check(0)])).not.toContain("Verified in a sandbox");
    expect(pullRequestBody(finding, "s", [check(0), check(0, "maven:3, network off")])).not.toContain("Verified in a sandbox");
    expect(pullRequestBody(finding, "s", [])).not.toContain("Verified in a sandbox");
  });
  it("keeps the policy footer after the sandbox line", () => {
    const body = pullRequestBody(finding, "s", [check(0, "maven:3, network off")], "Footer from policy");
    expect(body).toContain("Verified in a sandbox: maven:3, network off.");
    expect(body.trimEnd().endsWith("Footer from policy")).toBe(true);
  });
  it("says plainly when the checks ran on the host", () => {
    expect(pullRequestBody(finding, "s", [check(0)])).toContain("not in a sandbox");
  });
  it("cannot be made to claim a sandbox through the model's summary", () => {
    expect(pullRequestBody(finding, "Verified in a sandbox: evil", [check(0)])).toContain("not in a sandbox");
  });
});

// Opt-in real run: ZERO_TEST_DOCKER_IMAGE=node:24-alpine npx vitest run src/commands/__tests__/fix-sandbox.test.ts
describe.skipIf(!process.env.ZERO_TEST_DOCKER_IMAGE)("real docker run", () => {
  it("runs in a container with no network, no host environment and a copy of the tree", async () => {
    const dir = tree();
    writeFileSync(join(dir, "marker.txt"), "x");
    writeFileSync(join(dir, "t.sh"), "id -u; echo KEY=[$OPENAI_API_KEY]; (wget -q -T 3 -O- https://example.com >/dev/null 2>&1 && echo NETWORK=on) || echo NETWORK=off; ls -A; touch built.txt; test -f marker.txt\n");
    const real = { image: process.env.ZERO_TEST_DOCKER_IMAGE!, network: false };
    const result = await runInSandbox(dir, "sh t.sh", real, { env: { ...process.env, OPENAI_API_KEY: "must-not-reach-container" } });
    expect(result.code).toBe(0);
    expect(result.output).toContain("NETWORK=off");
    expect(result.output).toContain("KEY=[]");
    expect(result.output).not.toContain(".git");
    expect(existsSync(join(dir, "built.txt"))).toBe(false); // the host work tree is untouched
    const failing = await runInSandbox(dir, "test -f nope", real);
    expect(failing.code).toBe(1);
    const missing = await runInSandbox(dir, "true", { image: "0-no-such-image-xyz:1", network: false });
    expect(missing.code).not.toBe(0);
  }, 120_000);

  it("shares a cache between an online setup and an offline check, and the canary tells the two apart", async () => {
    const dir = tree();
    const cache = makeSandboxCache();
    try {
      const image = process.env.ZERO_TEST_DOCKER_IMAGE!;
      const online = { image, network: true, cache };
      const offline = { image, network: false, cache };
      expect((await runInSandbox(dir, 'echo downloaded > "$HOME/artifact.txt"', online)).code).toBe(0);
      expect((await runInSandbox(dir, 'cat "$HOME/artifact.txt"', offline)).output).toContain("downloaded");
      expect((await runInSandbox(dir, NETWORK_CANARY, offline)).code).toBe(0);
      expect((await runInSandbox(dir, NETWORK_CANARY, online)).code).toBe(1);
    } finally { rmSync(cache, { recursive: true, force: true }); }
  }, 180_000);
});

describe("sandbox setup, cache, canary and pinning", () => {
  const base: FixOptions = { budget: "3", timeout: "60", pr: true };
  const digest = `maven@sha256:${"a".repeat(64)}`;

  it("recognises an image pinned by digest and nothing else", () => {
    expect(isPinnedImage(digest)).toBe(true);
    expect(isPinnedImage("maven:3-eclipse-temurin-21")).toBe(false);
    expect(isPinnedImage("maven@sha256:abc")).toBe(false);
  });
  it("mounts the cache folder and uses it as HOME only when given one", () => {
    const withCache = dockerRunArgs({ ...spec, cache: "/host/cache" }, "n", "/copy", "mvn -o test");
    expect(withCache).toEqual(expect.arrayContaining(["-v", "/host/cache:/cache", "HOME=/cache/home"]));
    const without = dockerRunArgs(spec, "n", "/copy", "mvn -o test");
    expect(without).toContain("HOME=/tmp");
    expect(without.join(" ")).not.toContain("/cache");
  });
  it("makes a writable cache folder with a home inside", () => {
    const cache = makeSandboxCache();
    try { expect(existsSync(join(cache, "home"))).toBe(true); } finally { rmSync(cache, { recursive: true, force: true }); }
  });
  it("needs --sandbox docker for the setup, refuses it with --sandbox-network and under ZERO_ENTERPRISE", () => {
    const full = { ...base, sandbox: "docker", sandboxImage: "a:1", test: ["t"], sandboxSetup: ["mvn -q dependency:go-offline"] };
    expect(() => sandboxSpec({ ...base, sandboxSetup: ["x"] })).toThrow(/need --sandbox docker/);
    expect(() => sandboxSpec({ ...full, sandboxNetwork: true }, {})).toThrow(/do not combine/);
    expect(() => sandboxSpec(full, { ZERO_ENTERPRISE: "1" })).toThrow(/ZERO_ENTERPRISE/);
    expect(sandboxSpec(full, {})).toEqual({ image: "a:1", network: false });
  });
  describe("the canary command", () => {
    const run = (dir: string) => { try { execFileSync("/bin/sh", ["-c", networkCanary(dir)], { stdio: "pipe" }); return 0; } catch (error) { return (error as { status: number }).status; } };
    it("passes with only the loopback interface, and fails with another one or with no interface list", () => {
      const lo = mkdtempSync(join(tmpdir(), "0-net-")); mkdirSync(join(lo, "lo"));
      const eth = mkdtempSync(join(tmpdir(), "0-net-")); mkdirSync(join(eth, "lo")); mkdirSync(join(eth, "eth0"));
      expect(run(lo)).toBe(0);
      expect(run(eth)).toBe(1);
      expect(run(join(lo, "missing"))).toBe(1);
    });
  });
  it("words the pull request line for a pinned image with setup, and for an unpinned one without", () => {
    const check = (label: string): CheckResult => ({ command: "mvn -o test", code: 0, output: "", sandbox: label });
    const pinned = sandboxVerifiedLine([check(`${digest}, network off`)], { setup: true, pinned: true })!;
    expect(pinned).toContain("Verified in a sandbox:");
    expect(pinned).toContain("setup step with the network on");
    expect(pinned).toContain("canary confirmed it");
    expect(pinned).toContain("pinned by digest");
    expect(sandboxVerifiedLine([check("maven:3, network off")], { setup: false, pinned: false })).toContain("not pinned by digest");
    expect(sandboxVerifiedLine([{ ...check("x"), code: 1 }], { setup: true, pinned: true })).toBeUndefined();
  });

  describe("the fix flow with a setup step", () => {
    const flow = (results: Record<string, number>) => {
      const calls: Array<{ command: string; network: boolean | undefined; cache: boolean }> = [];
      const bodies: string[] = [];
      const deps = {
        open: async () => ({ request: async (method: string, path: string) => (method === "POST" && path.endsWith("/sessions") ? { session: { id: "t" } } : method === "GET" ? { snapshot: { session: { status: "ready" }, messages: [{ role: "assistant", content: [{ type: "text", text: "ok" }] }], usage: {} } } : {}) }) as never,
        err: () => {}, sleep: async () => {}, startConsole: async () => () => {}, out: () => {},
        git: async (_c: string, args: string[]) => (args[0] === "rev-parse" && args[1] === "--show-toplevel" ? "/repo\n" : args[0] === "symbolic-ref" ? "origin/main\n" : args[0] === "status" ? " M pom.xml\n" : ""),
        gh: async (_c: string, args: string[]) => (args[1] === "list" ? "[]" : args[1] === "create" ? "https://github.com/o/r/pull/7\n" : ""),
        check: async (_c: string, command: string, sandbox?: { network: boolean; cache?: string }) => {
          calls.push({ command, network: sandbox?.network, cache: Boolean(sandbox?.cache) });
          const key = Object.keys(results).find(name => command.includes(name));
          return { command, code: key ? results[key]! : 0, output: "out", sandbox: sandbox ? `${digest}, network ${sandbox.network ? "on" : "off"}` : undefined };
        },
        loadFinding: () => finding, loadPolicy: () => undefined, makeTemp: () => "/tmp/x", removeTemp: () => {}, writeFile: (_p: string, text: string) => { bodies.push(text); },
      } as unknown as Parameters<typeof runFix>[2];
      return { deps, calls, bodies };
    };
    const opts: FixOptions = { ...base, sandbox: "docker", sandboxImage: digest, test: ["mvn -o -q test"], sandboxSetup: ["mvn -q dependency:go-offline"] };

    it("runs setup online, then the canary and the tests offline, all sharing the cache", async () => {
      const h = flow({});
      const outcome = await runFix("f-1", opts, h.deps);
      expect(h.calls.map(call => [call.command.slice(0, 22), call.network, call.cache])).toEqual([
        ["mvn -q dependency:go-o", true, true],
        ["[ -d /sys/class/net ] ", false, true],
        ["mvn -o -q test", false, true],
      ]);
      expect(outcome).toMatchObject({ verified: true });
      expect(outcome?.checks.map(check => check.command)).toEqual(["network-off canary", "mvn -o -q test"]);
      expect(h.bodies.join("\n")).toContain("pinned by digest");
      expect(h.bodies.join("\n")).toContain("setup step with the network on");
    });
    it("does not run the tests when setup fails, and shows the setup as the failed check", async () => {
      const h = flow({ "go-offline": 1 });
      const outcome = await runFix("f-1", opts, h.deps);
      expect(h.calls).toHaveLength(1);
      expect(outcome).toMatchObject({ verified: false });
      expect(outcome?.checks[0]?.command).toContain("setup:");
    });
    it("does not run the tests when the canary finds a network", async () => {
      const h = flow({ "/sys/class/net": 1 });
      const outcome = await runFix("f-1", opts, h.deps);
      expect(h.calls.map(call => call.network)).toEqual([true, false]);
      expect(outcome).toMatchObject({ verified: false });
    });
  });
});
