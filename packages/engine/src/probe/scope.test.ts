import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { PUBLIC_MIN_DELAY_MS, assessTarget, classifyAddress, createScopedFetch, probeFindings, runProbes, selectProbes, ProbeScopeError } from "./index.js";
import { enterpriseMode } from "../policy/enterprise.js";

const dns = (...addresses: string[]) => async () => addresses;
const never = () => { throw new Error("DNS must not be asked for an IP literal"); };
const servers: Server[] = [];
afterEach(() => { for (const server of servers.splice(0)) server.close(); });
const listen = (handler: Parameters<typeof createServer>[1]) => new Promise<number>(resolve => { const server = createServer(handler); servers.push(server); server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)); });

describe("classifyAddress", () => {
  it("separates loopback, private, public and never-allowed addresses", () => {
    expect(["127.0.0.1", "::1", "::ffff:127.0.0.1"].map(classifyAddress)).toEqual(["loopback", "loopback", "loopback"]);
    expect(["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd12::1", "::ffff:10.0.0.1"].map(classifyAddress)).toEqual(Array(7).fill("private"));
    expect(["8.8.8.8", "172.32.0.1", "2606:4700::1", "203.0.113.9"].map(classifyAddress)).toEqual(Array(4).fill("public"));
    expect(["169.254.169.254", "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "fe80::1", "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "192.0.0.192", "garbage"].map(classifyAddress)).toEqual(Array(12).fill("blocked"));
  });
});

describe("assessTarget", () => {
  it("allows loopback and private hosts without a flag, and does not ask DNS about a literal", async () => {
    expect(await assessTarget(new URL("http://127.0.0.1:8080/v1"), { resolve: never })).toMatchObject({ network: "loopback", host: "127.0.0.1:8080" });
    expect(await assessTarget(new URL("http://[::1]:8080/"), { resolve: never })).toMatchObject({ network: "loopback" });
    expect(await assessTarget(new URL("http://localhost:8080/"), { resolve: dns("127.0.0.1", "::1") })).toMatchObject({ network: "loopback", addresses: ["127.0.0.1", "::1"] });
    expect(await assessTarget(new URL("http://192.168.1.20/"), { resolve: never })).toMatchObject({ network: "private" });
  });
  it("refuses a public host without the flag, and with the wrong host", async () => {
    await expect(assessTarget(new URL("https://chat.example.com/x"), { resolve: dns("203.0.113.9") })).rejects.toThrow("--i-own-this chat.example.com");
    await expect(assessTarget(new URL("https://chat.example.com/x"), { acknowledge: "example.com", resolve: dns("203.0.113.9") })).rejects.toThrow("exact host");
    await expect(assessTarget(new URL("https://chat.example.com/x"), { acknowledge: "other.com", resolve: dns("203.0.113.9") })).rejects.toBeInstanceOf(ProbeScopeError);
  });
  it("accepts a public host with the exact host and records the acknowledgement", async () => {
    const scope = await assessTarget(new URL("https://Chat.Example.com:8443/x"), { acknowledge: "chat.example.com", resolve: dns("203.0.113.9") });
    expect(scope).toMatchObject({ network: "public", host: "chat.example.com:8443", addresses: ["203.0.113.9"], acknowledgedHost: "chat.example.com" });
  });
  it("a wrong flag is refused even for a local target", async () => {
    await expect(assessTarget(new URL("http://127.0.0.1/"), { acknowledge: "10.0.0.1", resolve: never })).rejects.toThrow("exact host");
  });
  it("refuses link-local and metadata addresses even with the flag, by literal or by DNS answer", async () => {
    await expect(assessTarget(new URL("http://169.254.169.254/latest"), { acknowledge: "169.254.169.254", resolve: never })).rejects.toThrow("never probes these");
    await expect(assessTarget(new URL("http://[fd00:ec2::254]/"), { acknowledge: "[fd00:ec2::254]", resolve: never })).rejects.toThrow("never probes these");
    await expect(assessTarget(new URL("http://[::ffff:169.254.169.254]/"), { resolve: never })).rejects.toThrow("never probes these");
    await expect(assessTarget(new URL("https://metadata.example.com/"), { acknowledge: "metadata.example.com", resolve: dns("203.0.113.9", "169.254.169.254") })).rejects.toThrow("never probes these");
  });
  it("a name that resolves only to private addresses is private; one public answer makes it public", async () => {
    expect(await assessTarget(new URL("https://llm.corp.example/"), { resolve: dns("10.0.0.7") })).toMatchObject({ network: "private", addresses: ["10.0.0.7"] });
    expect(await assessTarget(new URL("https://llm.corp.example/"), { resolve: dns("127.0.0.1") })).toMatchObject({ network: "loopback" });
    await expect(assessTarget(new URL("https://mixed.example/"), { resolve: dns("10.0.0.7", "203.0.113.9") })).rejects.toThrow("public host");
  });
  it("refuses credentials in the URL and an unresolvable name", async () => {
    await expect(assessTarget(new URL("http://user:pw@127.0.0.1/"), { resolve: never })).rejects.toThrow("user name or password");
    await expect(assessTarget(new URL("https://nope.example/"), { resolve: async () => { throw new Error("ENOTFOUND"); } })).rejects.toThrow("Could not resolve");
    await expect(assessTarget(new URL("https://nope.example/"), { resolve: dns() })).rejects.toThrow("no addresses");
  });
  it("ZERO_ENTERPRISE does not change the decision: the operator names the target", async () => {
    const before = process.env["ZERO_ENTERPRISE"];
    process.env["ZERO_ENTERPRISE"] = "1";
    try {
      expect(enterpriseMode()).toBe(true);
      expect(await assessTarget(new URL("http://127.0.0.1/"), { resolve: never })).toMatchObject({ network: "loopback" });
      await expect(assessTarget(new URL("https://chat.example.com/"), { resolve: dns("203.0.113.9") })).rejects.toThrow("--i-own-this");
      expect(await assessTarget(new URL("https://chat.example.com/"), { acknowledge: "chat.example.com", resolve: dns("203.0.113.9") })).toMatchObject({ network: "public" });
    } finally { if (before === undefined) delete process.env["ZERO_ENTERPRISE"]; else process.env["ZERO_ENTERPRISE"] = before; }
  });
});

describe("probing a real loopback server", () => {
  it("works with no flag, as before, and records the scope in the findings", async () => {
    const port = await listen((req, res) => { let b = ""; req.on("data", d => { b += d; }); req.on("end", () => { const canary = /ZX[0-9A-F]{8}/.exec(b)?.[0] ?? ""; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ choices: [{ message: { content: canary } }] })); }); });
    const url = `http://127.0.0.1:${port}/v1`;
    const { results, requests, scope } = await runProbes({ url, repeat: 1, probes: selectProbes(["direct-override"]) });
    expect(requests).toBe(1);
    expect(results[0]!.hits).toBe(1);
    expect(scope).toMatchObject({ network: "loopback", addresses: ["127.0.0.1"] });
    expect(probeFindings(url, results, 1, scope)[0]!.evidence.analysis).toContain("scope: 127.0.0.1:");
  });
  it("refuses a redirect to another host and sends nothing there", async () => {
    let elsewhere = 0;
    const other = await listen((_req, res) => { elsewhere++; res.end("{}"); });
    const port = await listen((_req, res) => { res.statusCode = 302; res.setHeader("location", `http://localhost:${other}/steal`); res.end(); });
    await expect(runProbes({ url: `http://127.0.0.1:${port}/`, repeat: 1, probes: selectProbes(["direct-override"]) })).rejects.toThrow("redirect off");
    expect(elsewhere).toBe(0);
  });
  it("follows a redirect inside the same origin", async () => {
    const port = await listen((req, res) => { if (req.url === "/old") { res.statusCode = 307; res.setHeader("location", "/new"); res.end(); } else { req.resume(); res.setHeader("content-type", "application/json"); res.end('{"reply":"ok"}'); } });
    const fetcher = createScopedFetch(await assessTarget(new URL(`http://127.0.0.1:${port}/old`)));
    const response = await fetcher(`http://127.0.0.1:${port}/old`, { method: "POST", body: "{}" });
    expect(await response.json()).toEqual({ reply: "ok" });
  });
  it("connects to the address it checked, not to a later DNS answer", async () => {
    const port = await listen((req, res) => { req.resume(); res.end("pinned"); });
    // The name resolves to loopback at check time; nothing resolves "rebind.invalid" again, so a re-resolution would fail.
    const scope = await assessTarget(new URL(`http://rebind.invalid:${port}/`), { resolve: dns("127.0.0.1") });
    expect(scope.network).toBe("loopback");
    expect(await (await createScopedFetch(scope)(`http://rebind.invalid:${port}/`, { method: "POST", body: "{}" })).text()).toBe("pinned");
  });
  it("sends a public target no faster than the floor and no more than the ceiling", async () => {
    const times: number[] = [];
    const fake = (async () => { times.push(Date.now()); return new Response('{"reply":"no"}'); }) as typeof fetch;
    const { requests } = await runProbes({ url: "https://chat.example.com/", acknowledge: "chat.example.com", resolve: dns("203.0.113.9"), fetch: fake, repeat: 1, delayMs: 0, maxRequests: 3, probes: selectProbes(["direct-override", "delimiter-injection", "indirect-document"]) });
    expect(requests).toBe(3);
    expect(times[2]! - times[0]!).toBeGreaterThanOrEqual(PUBLIC_MIN_DELAY_MS * 2 - 20);
  });
});
