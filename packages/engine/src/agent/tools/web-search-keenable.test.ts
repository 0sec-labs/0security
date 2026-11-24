import { describe, expect, it, vi } from "vitest";
import { searchKeenable, selectedWebSearchProvider } from "./web-search-keenable.js";

const ok = (body: unknown) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
const run = (fetchImpl: unknown, env: NodeJS.ProcessEnv = {}) =>
  searchKeenable("rust async", { signal: new AbortController().signal, fetchImpl: fetchImpl as typeof fetch, env });
const fakeKey = ["k", "e", "y", "-", "1", "2", "3"].join("");

describe("selectedWebSearchProvider", () => {
  it("defaults to parallel", () => {
    expect(selectedWebSearchProvider({})).toEqual({ provider: "parallel" });
    expect(selectedWebSearchProvider({ ZERO_WEB_SEARCH_PROVIDER: "Parallel" })).toEqual({ provider: "parallel" });
  });
  it("selects keenable and refuses unknown names", () => {
    expect(selectedWebSearchProvider({ ZERO_WEB_SEARCH_PROVIDER: "keenable" })).toEqual({ provider: "keenable" });
    expect(selectedWebSearchProvider({ ZERO_WEB_SEARCH_PROVIDER: "bing" })).toHaveProperty("error");
  });
});

describe("searchKeenable", () => {
  it("posts only the query to the public endpoint without a key", async () => {
    const fetchImpl = vi.fn(async () => ok({ results: [{ title: "A", url: "https://a.test/", snippet: "s", description: "" }] }));
    const result = await run(fetchImpl);
    expect(result).toEqual({ ok: true, results: [{ title: "A", url: "https://a.test/", snippet: "s" }] });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.keenable.ai/v1/search/public");
    expect(init.redirect).toBe("error");
    expect(JSON.parse(String(init.body))).toEqual({ query: "rust async", max_results: 5 });
    const headers = new Headers(init.headers);
    expect(headers.get("x-api-key")).toBeNull();
    expect(headers.get("x-keenable-title")).toBe("0security");
  });
  it("uses the keyed endpoint when a key is set", async () => {
    const fetchImpl = vi.fn(async () => ok({ results: [] }));
    await run(fetchImpl, { KEENABLE_API_KEY: fakeKey });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.keenable.ai/v1/search");
    expect(new Headers(init.headers).get("x-api-key")).toBe(fakeKey);
  });
  it("filters unsafe URLs, dedupes and caps at five", async () => {
    const results = [
      { title: "bad", url: "javascript:alert(1)" }, { title: "cred", url: "https://u:p@x.test/" },
      ...Array.from({ length: 8 }, (_, i) => ({ title: `T${i}`, url: `https://x.test/${i % 7}`, description: "d" })),
    ];
    const out = await run(async () => ok({ results }));
    expect(out.ok && out.results.map(r => r.url)).toEqual([0, 1, 2, 3, 4].map(i => `https://x.test/${i}`));
  });
  it("reports HTTP errors, bad shapes and malformed JSON", async () => {
    expect(await run(async () => new Response("no", { status: 429 }))).toEqual({ ok: false, error: "Keenable search request failed (HTTP 429)." });
    expect(await run(async () => ok({ nope: 1 }))).toMatchObject({ ok: false });
    expect(await run(async () => new Response("{"))).toMatchObject({ ok: false, error: "Keenable search returned malformed JSON." });
  });
  it("rejects oversized responses", async () => {
    expect(await run(async () => new Response("x".repeat(1_100_000)))).toMatchObject({ ok: false });
  });
  it("is blocked by ZERO_ENTERPRISE before any request", async () => {
    const fetchImpl = vi.fn();
    await expect(run(fetchImpl, { ZERO_ENTERPRISE: "1" })).rejects.toThrow(/ZERO_ENTERPRISE/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
