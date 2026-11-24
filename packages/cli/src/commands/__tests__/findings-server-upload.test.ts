import { describe, expect, it } from "vitest";
import { ingestEndpoint, isServerTarget, repoFromRemote, runServerUpload } from "../findings-server-upload.js";

// A key-shaped string built at runtime; it is not a real key.
const KEY = ["0", "find", "x".repeat(43)].join("_");
const git = (answers: Record<string, string>) => async (args: string[]) => {
  const answer = answers[args.join(" ")];
  if (answer === undefined) throw new Error("no git");
  return answer;
};
const reply = (status: number, body: unknown) => async () => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });

describe("target and endpoint", () => {
  it("tells a server URL from the other targets", () => {
    expect(isServerTarget("https://findings.example.com")).toBe(true);
    expect(isServerTarget("github")).toBe(false);
    expect(isServerTarget("bitbucket-cloud")).toBe(false);
    expect(isServerTarget(undefined)).toBe(false);
  });
  it("builds the ingest URL under a path prefix and refuses plain http and embedded credentials", () => {
    expect(ingestEndpoint("https://example.com/findings").toString()).toBe("https://example.com/findings/api/v1/findings/ingest");
    expect(ingestEndpoint("http://127.0.0.1:4000").pathname).toBe("/api/v1/findings/ingest");
    expect(() => ingestEndpoint("http://example.com")).toThrow(/plaintext/);
    expect(() => ingestEndpoint("http://example.com", true)).not.toThrow();
    expect(() => ingestEndpoint("https://user:pw@example.com")).toThrow(/credentials/);
    expect(() => ingestEndpoint("not a url")).toThrow(/valid URL/);
  });
  it("reads owner/name from a git remote", () => {
    expect(repoFromRemote("git@github.com:acme/api.git")).toBe("acme/api");
    expect(repoFromRemote("https://github.com/acme/api\n")).toBe("acme/api");
    expect(repoFromRemote("")).toBeUndefined();
  });
});

describe("runServerUpload", () => {
  it("posts the file with the key in the header and the labels in the query", async () => {
    let seen: { url: string; init: { method: string; headers: Record<string, string>; body: string } } | undefined;
    const result = await runServerUpload("{\"runs\":[]}", { to: "https://findings.example.com", source: "nightly" }, {
      env: { ZERO_FINDINGS_API_KEY: KEY },
      git: git({ "remote get-url origin": "git@github.com:acme/api.git\n", "rev-parse HEAD": "abcdef1234567890\n", "rev-parse --abbrev-ref HEAD": "main\n" }),
      fetch: async (url, init) => { seen = { url, init }; return { ok: true, status: 201, text: async () => JSON.stringify({ repo: "acme/api", source: "nightly", format: "sarif", total: 3, created: 2, known: 1, alreadyImported: false }) }; },
    });
    expect(result).toMatchObject({ total: 3, created: 2, known: 1 });
    const url = new URL(seen!.url);
    expect(url.origin + url.pathname).toBe("https://findings.example.com/api/v1/findings/ingest");
    expect(Object.fromEntries(url.searchParams)).toEqual({ repo: "acme/api", source: "nightly", commit: "abcdef1234567890", ref: "main" });
    expect(seen!.init).toMatchObject({ method: "POST", body: "{\"runs\":[]}", redirect: "manual", headers: { Authorization: `Bearer ${KEY}` } });
    expect(seen!.url).not.toContain(KEY);
  });

  it("needs a key from the environment and a repository", async () => {
    await expect(runServerUpload("{}", { to: "https://s.example", repo: "a/b" }, { env: {}, git: git({}) })).rejects.toThrow(/ZERO_FINDINGS_API_KEY/);
    await expect(runServerUpload("{}", { to: "https://s.example", repo: "a/b" }, { env: { ZERO_FINDINGS_API_KEY: "nope" }, git: git({}) })).rejects.toThrow(/not a findings API key/);
    await expect(runServerUpload("{}", { to: "https://s.example" }, { env: { ZERO_FINDINGS_API_KEY: KEY }, git: git({}) })).rejects.toThrow(/--repo/);
  });

  it("shows the server's reason when it refuses, without the key", async () => {
    const failure = runServerUpload("{}", { to: "https://s.example", repo: "a/b" }, { env: { ZERO_FINDINGS_API_KEY: KEY }, git: git({}), fetch: reply(403, { error: "The shared findings server needs an enterprise license." }) });
    await expect(failure).rejects.toThrow(/403.*needs an enterprise license/);
    await failure.catch(error => expect(String(error.message)).not.toContain(KEY));
  });

  it("names the host when it cannot be reached", async () => {
    await expect(runServerUpload("{}", { to: "https://s.example", repo: "a/b" }, { env: { ZERO_FINDINGS_API_KEY: KEY }, git: git({}), fetch: async () => { throw new Error("ECONNREFUSED"); } })).rejects.toThrow(/Could not reach s\.example/);
  });
});
