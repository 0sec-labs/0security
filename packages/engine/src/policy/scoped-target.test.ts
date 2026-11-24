import { describe, expect, it } from "vitest";
import { EnterpriseEgressError } from "./enterprise.js";
import { assertScopedTarget, classifyAddress, describeScopedTarget, parseScopeFile, ScopedTargetError } from "./scoped-target.js";

const dns = (...addresses: string[]) => async () => addresses;
const never = () => { throw new Error("DNS must not be asked for an IP literal"); };

describe("classifyAddress", () => {
  it("separates loopback, private, public and never-allowed addresses", () => {
    expect(["127.0.0.1", "::1", "::ffff:127.0.0.1", "0:0:0:0:0:ffff:7f00:1"].map(classifyAddress)).toEqual(Array(4).fill("loopback"));
    expect(["0:0:0:0:0:ffff:a00:1", "64:ff9b::808:808"].map(classifyAddress)).toEqual(["private", "public"]);
    expect(["10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fd12::1"].map(classifyAddress)).toEqual(Array(5).fill("private"));
    expect(["8.8.8.8", "172.32.0.1", "203.0.113.9"].map(classifyAddress)).toEqual(Array(3).fill("public"));
    expect(["0:0:0:0:0:ffff:a9fe:a9fe", "0000:0000:0000:0000:0000:ffff:169.254.169.254", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "::a9fe:a9fe", "169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "garbage"].map(classifyAddress)).toEqual(Array(13).fill("blocked"));
  });
});

describe("parseScopeFile", () => {
  it("reads hosts and host:port, ignoring comments and blank lines", () => {
    expect(parseScopeFile("# staging\nStaging.Example.com\n\n127.0.0.1:8080 # local\n[::1]:9000\n")).toEqual(["staging.example.com", "127.0.0.1:8080", "[::1]:9000"]);
  });
  it("refuses a scheme, a path or a wildcard", () => {
    for (const line of ["https://a.test", "a.test/x", "*.a.test", "a b", "a.test:99999999"]) expect(() => parseScopeFile(line)).toThrow(ScopedTargetError);
  });
});

describe("assertScopedTarget", () => {
  it("allows loopback and private hosts that the scope file lists or the operator typed", async () => {
    expect(await assertScopedTarget("http://127.0.0.1:8080/app", { scopeHosts: ["127.0.0.1:8080"], resolve: never })).toMatchObject({ network: "loopback", host: "127.0.0.1:8080", authorisedBy: ["scope-file"] });
    expect(await assertScopedTarget("http://localhost:3000", { acknowledge: "localhost", resolve: dns("127.0.0.1", "::1") })).toMatchObject({ network: "loopback", authorisedBy: ["acknowledged"] });
    expect(await assertScopedTarget("http://192.168.1.20/", { scopeHosts: ["192.168.1.20"], resolve: never })).toMatchObject({ network: "private" });
  });
  it("refuses a target nobody named, and a host not in the scope file", async () => {
    await expect(assertScopedTarget("http://127.0.0.1:8080", { resolve: never })).rejects.toThrow("--scope-file");
    await expect(assertScopedTarget("http://127.0.0.1:8080", { scopeHosts: ["other.test"], resolve: never })).rejects.toThrow("not listed in the scope file");
  });
  it("refuses a public host without the typed host, even when the scope file lists it", async () => {
    await expect(assertScopedTarget("https://app.example.com", { scopeHosts: ["app.example.com"], resolve: dns("203.0.113.9") })).rejects.toThrow("--acknowledge-host app.example.com");
    expect(await assertScopedTarget("https://app.example.com", { acknowledge: "app.example.com", resolve: dns("203.0.113.9") })).toMatchObject({ network: "public", authorisedBy: ["acknowledged"] });
    expect(await assertScopedTarget("https://app.example.com", { acknowledge: "app.example.com", scopeHosts: ["app.example.com"], resolve: dns("203.0.113.9") })).toMatchObject({ authorisedBy: ["scope-file", "acknowledged"] });
  });
  it("refuses a public host that the scope file does not list, even when typed", async () => {
    await expect(assertScopedTarget("https://app.example.com", { acknowledge: "app.example.com", scopeHosts: ["other.test"], resolve: dns("203.0.113.9") })).rejects.toThrow("not listed");
  });
  it("needs the exact host: a different or partial host is refused", async () => {
    await expect(assertScopedTarget("https://app.example.com", { acknowledge: "example.com", resolve: dns("203.0.113.9") })).rejects.toThrow("exactly");
    await expect(assertScopedTarget("https://app.example.com:8443", { acknowledge: "app.example.com:9", resolve: dns("203.0.113.9") })).rejects.toThrow("exactly");
  });
  it("always refuses link-local and metadata addresses, with every flag", async () => {
    for (const url of ["http://169.254.169.254/latest", "http://[fe80::1]/", "http://100.100.100.200/", "http://0.0.0.0/"]) {
      const host = new URL(url).host;
      await expect(assertScopedTarget(url, { acknowledge: host, scopeHosts: [host], resolve: never })).rejects.toThrow("never tested");
    }
  });
  it("refuses a name that resolves to a metadata address, or to a mix that includes one", async () => {
    await expect(assertScopedTarget("http://rebind.test", { acknowledge: "rebind.test", resolve: dns("203.0.113.9", "169.254.169.254") })).rejects.toThrow("never tested");
  });
  it("refuses credentials in the URL, other schemes and unresolvable names", async () => {
    await expect(assertScopedTarget("http://user:pw@127.0.0.1", { acknowledge: "127.0.0.1" })).rejects.toThrow("user name");
    await expect(assertScopedTarget("ftp://127.0.0.1", { acknowledge: "127.0.0.1" })).rejects.toThrow("http or https");
    await expect(assertScopedTarget("not a url")).rejects.toThrow("not a URL");
    await expect(assertScopedTarget("http://gone.test", { acknowledge: "gone.test", resolve: async () => { throw new Error("ENOTFOUND"); } })).rejects.toThrow("Could not resolve");
  });
  it("under ZERO_ENTERPRISE allows loopback only", async () => {
    const env = { ZERO_ENTERPRISE: "1" };
    expect(await assertScopedTarget("http://127.0.0.1:8080", { acknowledge: "127.0.0.1", resolve: never, env })).toMatchObject({ network: "loopback" });
    await expect(assertScopedTarget("http://192.168.1.20", { acknowledge: "192.168.1.20", resolve: never, env })).rejects.toBeInstanceOf(EnterpriseEgressError);
    await expect(assertScopedTarget("https://app.example.com", { acknowledge: "app.example.com", resolve: dns("203.0.113.9"), env })).rejects.toBeInstanceOf(EnterpriseEgressError);
  });
  it("describes what authorised the run", async () => {
    expect(describeScopedTarget(await assertScopedTarget("http://127.0.0.1:8080", { scopeHosts: ["127.0.0.1:8080"], acknowledge: "127.0.0.1:8080", resolve: never }))).toBe("127.0.0.1:8080 (loopback network, 127.0.0.1), authorised by the scope file and the typed host 127.0.0.1:8080");
  });
});
