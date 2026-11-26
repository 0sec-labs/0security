import { createServer } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { assertBitbucketDestination, BitbucketClient } from "../client.js";

afterEach(() => vi.unstubAllEnvs());

describe("operator-approved Bitbucket egress", () => {
  it("defaults closed, and permits only the configured origin and context path", () => {
    const env = { ZERO_ENTERPRISE: "1", ZERO_BITBUCKET_URL: "https://git.internal/bitbucket" };
    expect(() => assertBitbucketDestination("https://git.internal/bitbucket/rest/api/latest?start=50", env)).not.toThrow();
    for (const url of ["https://other.internal/bitbucket", "https://git.internal:444/bitbucket", "https://git.internal/bitbucket-evil", "https://git.internal/rest/api/latest", "https://user:password@git.internal/bitbucket", "http://git.internal/bitbucket"]) {
      expect(() => assertBitbucketDestination(url, env)).toThrow();
    }
    expect(() => assertBitbucketDestination("https://git.internal/bitbucket", { ZERO_ENTERPRISE: "1" })).toThrow();
    for (const base of ["http://git.internal", "https://user:password@git.internal", "https://git.internal/?x=1", "https://git.internal/#fragment"]) {
      expect(() => assertBitbucketDestination("https://git.internal", { ZERO_ENTERPRISE: "1", ZERO_BITBUCKET_URL: base })).toThrow();
    }
  });

  it("uses a real HTTP listener, while refusing cross-origin and context-escaping redirects before sending a token", async () => {
    const seen: string[] = [];
    let redirect = "";
    const server = createServer((req, res) => {
      seen.push(req.url!);
      expect(req.headers.authorization).toBe("Bearer test-secret");
      if (redirect) { res.writeHead(302, { location: redirect }); res.end(); }
      else { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify({ values: [], isLastPage: true })); }
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as { port: number };
    const base = `http://127.0.0.1:${address.port}/bitbucket`;
    vi.stubEnv("ZERO_ENTERPRISE", "1"); vi.stubEnv("ZERO_BITBUCKET_URL", base);
    const client = new BitbucketClient({ platform: "bitbucket-dc", baseUrl: base, token: "test-secret" });
    try {
      await expect(client.listOpenPullRequests("PRJ", "app")).resolves.toEqual([]);
      for (const location of ["http://127.0.0.1:1/stolen", "/outside", `${base.replace("http://", "http://user:pass@")}/rest/api/latest`]) {
        redirect = location;
        const before = seen.length;
        await expect(client.listOpenPullRequests("PRJ", "app")).rejects.toThrow();
        expect(seen.length).toBe(before + 1);
      }
    } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
  });
});
