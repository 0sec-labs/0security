import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { checkSlopsquat, editDistance, lookalikeOf, slopsquatFails, slopsquatSarifParts, slopsquatToText } from "./slopsquat.js";
import { parseNpmLock, parsePipfileLock, parsePnpmLock, parsePoetryLock, parseRequirements, parseYarnLock } from "./parsers.js";
import { parseSarif } from "../shared/sarif-import.js";

const NOW = new Date("2026-06-01T00:00:00Z");
const daysAgo = (days: number): string => new Date(NOW.getTime() - days * 86_400_000).toISOString();
const npmDoc = (ageDays: number, releases: number, extra: Record<string, unknown> = {}): unknown => ({
  time: { created: daysAgo(ageDays) }, maintainers: [{ name: "one" }],
  versions: Object.fromEntries(Array.from({ length: releases }, (_, index) => [`1.0.${index}`, { scripts: {}, ...extra }])),
});
const pypiDoc = (ageDays: number, releases: number): unknown => ({ releases: Object.fromEntries(Array.from({ length: releases }, (_, index) => [`1.${index}`, [{ upload_time_iso_8601: daysAgo(ageDays - index) }]])) });
const component = (purl: string, properties: unknown[] = []): Record<string, unknown> => ({ type: "library", purl, properties });
const bomOf = (...components: Array<Record<string, unknown>>): unknown => ({ metadata: { component: { name: "my-app" } }, components });

type Route = { status?: number; body?: unknown; raw?: string; delayMs?: number; headers?: Record<string, string> };
let server: Server; let base = "";
const routes = new Map<string, Route>(); const hits: string[] = [];
beforeAll(async () => {
  server = createServer((request, response) => {
    const url = request.url ?? "";
    hits.push(url);
    const route = routes.get(url);
    const send = (): void => {
      if (!route) { response.writeHead(404).end("{}"); return; }
      response.writeHead(route.status ?? 200, { "content-type": "application/json", ...route.headers });
      response.end(route.raw ?? JSON.stringify(route.body ?? {}));
    };
    if (route?.delayMs) setTimeout(send, route.delayMs); else send();
  });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => { server.closeAllConnections(); server.close(); });
afterEach(() => { routes.clear(); hits.length = 0; delete process.env["ZERO_ENTERPRISE"]; delete process.env["ZERO_OFFLINE"]; });
const run = (bom: unknown, extra: Parameters<typeof checkSlopsquat>[1] = {}) => checkSlopsquat(bom, { baseUrls: { npm: base, npmDownloads: base, pypi: base }, now: NOW, ...extra });

describe("name signals", () => {
  it("measures edit distance with neighbouring swaps as one edit", () => {
    expect(editDistance("lodash", "lodazh")).toBe(1);
    expect(editDistance("react", "raect")).toBe(1);
    expect(editDistance("abc", "xyz")).toBe(3);
  });
  it("finds a look-alike of a popular name but not the popular name itself or a distant name", () => {
    expect(lookalikeOf("npm", "lodazh")).toBe("lodash");
    expect(lookalikeOf("npm", "lodash")).toBeUndefined();
    expect(lookalikeOf("npm", "left-padder-of-nothing")).toBeUndefined();
    expect(lookalikeOf("pypi", "reqeusts")).toBe("requests");
    expect(lookalikeOf("npm", "@types/lodazh")).toBeUndefined();
  });
});

describe("slopsquat check", () => {
  it("reports a name that is not on the registry, worded for private packages", async () => {
    const result = await run(bomOf(component("pkg:npm/zzz-made-up-name@1.0.0"), component("pkg:pypi/zzz-made-up-name@1.0.0")));
    expect(result.findings.map(item => item.ruleId)).toEqual(["slopsquat/nonexistent", "slopsquat/nonexistent"]);
    expect(result.findings[0]!.severity).toBe("medium");
    expect(result.findings[0]!.message).toContain("not found on the public registry: if this is private, ignore");
    expect(result.notChecked).toBeUndefined();
  });
  it("reports a brand-new package with an install script as high, and sends only the name", async () => {
    routes.set("/fresh-pkg", { body: npmDoc(3, 1, { scripts: { postinstall: "node x.js" } }) });
    routes.set("/downloads/point/last-week/fresh-pkg", { body: { downloads: 12 } });
    const result = await run(bomOf(component("pkg:npm/fresh-pkg@1.0.0")));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: "slopsquat/new-package", severity: "high", signals: { ageDays: 3, releases: 1, maintainers: 1, weeklyDownloads: 12, installScript: true } });
    expect(result.findings[0]!.message).toContain("first published 3 days ago");
    expect(hits).toEqual(["/fresh-pkg", "/downloads/point/last-week/fresh-pkg"]);
  });
  it("does not flag an old package or a new package with many releases", async () => {
    routes.set("/old-pkg", { body: npmDoc(900, 2) });
    routes.set("/busy-pkg", { body: npmDoc(5, 40) });
    routes.set("/pypi/old-lib/json", { body: pypiDoc(900, 5) });
    const result = await run(bomOf(component("pkg:npm/old-pkg@1.0.0"), component("pkg:npm/busy-pkg@1.0.0"), component("pkg:pypi/old-lib@1.0.0")));
    expect(result.findings).toEqual([]);
    expect(result.checked).toBe(3);
    expect(hits).not.toContain("/downloads/point/last-week/old-pkg");
  });
  it("reports a typosquat candidate only when it is also new or little used", async () => {
    routes.set("/lodazh", { body: npmDoc(400, 2) });
    routes.set("/downloads/point/last-week/lodazh", { body: { downloads: 40 } });
    routes.set("/lodashh", { body: npmDoc(2000, 30) });
    routes.set("/downloads/point/last-week/lodashh", { body: { downloads: 90_000 } });
    const result = await run(bomOf(component("pkg:npm/lodazh@1.0.0"), component("pkg:npm/lodashh@1.0.0")));
    expect(result.findings.map(item => [item.name, item.ruleId, item.severity])).toEqual([["lodazh", "slopsquat/typosquat-candidate", "medium"]]);
    expect(result.findings[0]!.signals.lookalikeOf).toBe("lodash");
  });
  it("checks a new PyPI look-alike", async () => {
    routes.set("/pypi/reqeusts/json", { body: pypiDoc(4, 1) });
    const result = await run(bomOf(component("pkg:pypi/reqeusts@1.0")));
    expect(result.findings[0]).toMatchObject({ ruleId: "slopsquat/typosquat-candidate", severity: "high" });
  });
  it("honours --new-days", async () => {
    routes.set("/mid-pkg", { body: npmDoc(45, 1) });
    expect((await run(bomOf(component("pkg:npm/mid-pkg@1.0.0")))).findings).toEqual([]);
    expect((await run(bomOf(component("pkg:npm/mid-pkg@1.0.0")), { newDays: 60 })).findings).toHaveLength(1);
  });
});

describe("private and local packages", () => {
  it("skips private scopes, workspace members, qualified registries, patterns and the project itself without any request", async () => {
    const result = await run(bomOf(
      component("pkg:npm/%40acme-internal/tool@1.0.0"),
      component("pkg:npm/workspace-lib@1.0.0", [{ name: "0:local", value: "workspace" }]),
      component("pkg:npm/from-private@1.0.0", [{ name: "0:local", value: "private-registry" }]),
      component("pkg:pypi/internal-lib@1.0?repository_url=https%3A%2F%2Fpypi.corp.test%2Fsimple"),
      component("pkg:npm/named-private@1.0.0"),
      component("pkg:npm/my-app@1.0.0"),
    ), { privatePatterns: ["named-private"] });
    expect(result.skipped).toHaveLength(6);
    expect(result.skipped.every(item => item.reason === "skipped: private or local")).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.checked).toBe(0);
    expect(hits).toEqual([]);
    expect(slopsquatToText(result)).toContain("6 skipped: private or local");
  });
  it("still checks a well-known public scope", async () => {
    const result = await run(bomOf(component("pkg:npm/%40types/zzz-made-up@1.0.0")));
    expect(result.findings[0]!.ruleId).toBe("slopsquat/nonexistent");
  });
});

describe("offline and enterprise", () => {
  for (const name of ["ZERO_ENTERPRISE", "ZERO_OFFLINE"]) {
    it(`refuses under ${name} without a request and never says ok`, async () => {
      process.env[name] = "1";
      const calls: string[] = [];
      const result = await checkSlopsquat(bomOf(component("pkg:npm/lodash@4.17.21")));
      expect(calls).toEqual([]);
      expect(result.notChecked).toContain(name);
      expect(result.checked).toBe(0);
      const text = slopsquatToText(result);
      expect(text).toContain("Not checked: offline");
      expect(text).not.toContain("No signals");
    });
  }
});

describe("hostile registries", () => {
  it("lists a lookup that exceeds the size limit as not checked", async () => {
    routes.set("/big-pkg", { raw: JSON.stringify({ time: { created: daysAgo(1) }, versions: {}, pad: "x".repeat(5000) }) });
    const result = await run(bomOf(component("pkg:npm/big-pkg@1.0.0")), { maxBytes: 1000 });
    expect(result.findings).toEqual([]);
    expect(result.failed[0]).toContain("big-pkg (response over the size limit)");
    expect(slopsquatToText(result)).toContain("not checked");
  });
  it("stops reading a body that lies about its length", async () => {
    routes.set("/chunk-pkg", { raw: "{\"a\":\"" + "y".repeat(50_000) + "\"}" });
    const result = await run(bomOf(component("pkg:npm/chunk-pkg@1.0.0")), { maxBytes: 2000 });
    expect(result.failed[0]).toContain("size limit");
  });
  it("times out a slow registry", async () => {
    routes.set("/slow-pkg", { body: npmDoc(1, 1), delayMs: 400 });
    const result = await run(bomOf(component("pkg:npm/slow-pkg@1.0.0")), { timeoutMs: 100 });
    expect(result.findings).toEqual([]);
    expect(result.failed).toHaveLength(1);
  });
  it("treats server errors, redirects, non-JSON and wrong types as not checked, never as a finding or ok", async () => {
    routes.set("/err-pkg", { status: 503 });
    routes.set("/redir-pkg", { status: 302, headers: { location: `${base}/err-pkg` } });
    routes.set("/text-pkg", { raw: "not json" });
    routes.set("/array-pkg", { body: [1, 2] });
    routes.set("/types-pkg", { body: { time: { created: 5 }, versions: "many", maintainers: {} } });
    routes.set("/pypi/pytypes/json", { body: { releases: [] } });
    const result = await run(bomOf(...["err-pkg", "redir-pkg", "text-pkg", "array-pkg", "types-pkg"].map(name => component(`pkg:npm/${name}@1.0.0`)), component("pkg:pypi/pytypes@1.0")));
    expect(result.findings).toEqual([]);
    expect(result.failed).toHaveLength(6);
  });
  it("ignores prototype-pollution keys and unknown fields", async () => {
    routes.set("/proto-pkg", { raw: `{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"time":{"created":"${daysAgo(2)}","__proto__":{"x":1}},"maintainers":[],"versions":{"__proto__":{"scripts":{"postinstall":"x"}},"1.0.0":{}}}` });
    routes.set("/downloads/point/last-week/proto-pkg", { raw: `{"__proto__":{"downloads":99999},"downloads":3}` });
    const result = await run(bomOf(component("pkg:npm/proto-pkg@1.0.0")));
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(result.findings[0]!.signals).toMatchObject({ weeklyDownloads: 3, releases: 2 });
    expect(result.findings[0]!.signals.installScript).toBeUndefined();
  });
  it("ignores a hostile download count and a huge maintainers list", async () => {
    routes.set("/dl-pkg", { body: npmDoc(2, 1) });
    routes.set("/downloads/point/last-week/dl-pkg", { body: { downloads: "lots" } });
    const result = await run(bomOf(component("pkg:npm/dl-pkg@1.0.0")));
    expect(result.findings[0]!.signals.weeklyDownloads).toBeUndefined();
  });
  it("rejects names that are not valid registry names without a request", async () => {
    const result = await run(bomOf(component("pkg:npm/UP%20per%2F..%2Fx@1.0.0"), component("pkg:pypi/a%2Fb@1.0")));
    expect(result.checked).toBe(0);
    expect(hits).toEqual([]);
  });
  it("caps the number of lookups and says so", async () => {
    const result = await run(bomOf(...Array.from({ length: 5 }, (_, index) => component(`pkg:npm/capped-${index}@1.0.0`))), { cap: 2 });
    expect(result.checked).toBe(2);
    expect(result.overCap).toBe(3);
    expect(hits.filter(url => url.startsWith("/capped-"))).toHaveLength(2);
  });
});

describe("output", () => {
  it("fails on the severity named by --fail-on", () => {
    const finding = { severity: "medium" } as never;
    expect(slopsquatFails([finding], undefined)).toBe(false);
    expect(slopsquatFails([finding], "high")).toBe(false);
    expect(slopsquatFails([finding], "medium")).toBe(true);
    expect(slopsquatFails([finding], "info")).toBe(true);
  });
  it("writes SARIF that findings import accepts", async () => {
    const result = await run(bomOf(component("pkg:npm/zzz-made-up-name@1.0.0")));
    const parts = slopsquatSarifParts(result.findings, () => "package-lock.json");
    const sarif = { version: "2.1.0", runs: [{ tool: { driver: { name: "0 sbom check", rules: parts.rules } }, results: parts.results }] };
    const { findings } = parseSarif(JSON.stringify(sarif));
    expect(findings.map(item => [item.ruleId, item.path, item.severity])).toEqual([["slopsquat/nonexistent", "package-lock.json", "medium"]]);
  });
});

describe("lockfile marks local packages", () => {
  it("marks workspace members, file paths and other registries, and leaves registry packages alone", () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "root" },
      "packages/app": { name: "app", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" },
      "node_modules/corp": { version: "1.0.0", resolved: "https://npm.corp.test/corp/-/corp-1.0.0.tgz" },
      "node_modules/vendored": { version: "1.0.0", resolved: "file:vendor/vendored" },
    } });
    expect(parseNpmLock(lock).map(item => [item.name, item.local])).toEqual([["app", "workspace"], ["lodash", undefined], ["corp", "private-registry"], ["vendored", "workspace"]]);
  });
});

describe("other lockfiles mark private sources", () => {
  const local = (items: Array<{ name: string; local?: string }>): Array<[string, string | undefined]> => items.map(item => [item.name, item.local]);
  it("npm v1", () => {
    expect(local(parseNpmLock(JSON.stringify({ dependencies: { a: { version: "1.0.0", resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz" }, b: { version: "1.0.0", resolved: "https://npm.corp.test/b.tgz" } } })))).toEqual([["a", undefined], ["b", "private-registry"]]);
  });
  it("pnpm", () => {
    const lock = "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n  b@1.0.0:\n    resolution: {tarball: https://npm.corp.test/b.tgz}\n";
    expect(local(parsePnpmLock(lock))).toEqual([["a", undefined], ["b", "private-registry"]]);
  });
  it("yarn classic and Berry", () => {
    const classic = 'a@^1.0.0:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"\n\nb@^1.0.0:\n  version "1.0.0"\n  resolved "https://npm.corp.test/b.tgz"\n';
    expect(local(parseYarnLock(classic))).toEqual([["a", undefined], ["b", "private-registry"]]);
    const berry = '"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n\n"a@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n';
    expect(local(parseYarnLock(berry))).toEqual([["app", "workspace"], ["a", undefined]]);
  });
  it("poetry, Pipfile and requirements", () => {
    const poetry = '[[package]]\nname = "pub"\nversion = "1.0"\n\n[[package]]\nname = "priv"\nversion = "1.0"\n\n[package.source]\ntype = "legacy"\nurl = "https://pypi.corp.test/simple"\n';
    expect(local(parsePoetryLock(poetry))).toEqual([["pub", undefined], ["priv", "private-registry"]]);
    expect(local(parsePipfileLock(JSON.stringify({ default: { a: { version: "==1.0", index: "pypi" }, b: { version: "==1.0", index: "corp" } } })))).toEqual([["a", undefined], ["b", "private-registry"]]);
    expect(local(parseRequirements("a==1.0\n"))).toEqual([["a", undefined]]);
    expect(local(parseRequirements("--extra-index-url https://pypi.corp.test/simple\na==1.0\n"))).toEqual([["a", "private-registry"]]);
  });
});

describe("untrusted SBOM text", () => {
  it("prints skipped package URLs without control characters", async () => {
    const result = await run(bomOf(component("pkg:npm/%40acme/x@1.0.0\u001b[2J\u0007")));
    const text = slopsquatToText(result);
    expect(text).toContain("1 skipped: private or local");
    // eslint-disable-next-line no-control-regex
    expect(/[\u0000-\u0008\u000b-\u001f\u007f]/.test(text)).toBe(false);
  });
});

describe("one name, several components", () => {
  it("never looks a name up when any component of that name is private", async () => {
    const result = await run(bomOf(component("pkg:npm/shared-name@1.0.0"), component("pkg:npm/shared-name@2.0.0", [{ name: "0:local", value: "private-registry" }])));
    expect(result.checked).toBe(0);
    expect(hits).toEqual([]);
  });
});
