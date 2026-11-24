import { describe, expect, it, vi } from "vitest";
import { parseHeaders, runProbe, type ProbeDeps, type ProbeOptions } from "../probe.js";

const reply = (text: string) => new Response(JSON.stringify({ reply: text }));
const prompt = (init?: RequestInit) => JSON.parse(String(init?.body)).message as string;
const options = (extra: Partial<ProbeOptions> = {}): ProbeOptions => ({ repeat: "1", delay: "0", timeout: "5", maxRequests: "50", format: "json", ...extra });
const harness = (fetchImpl: typeof fetch, extra: Partial<ProbeDeps> = {}) => {
  const out: string[] = []; const err: string[] = []; const saved: unknown[] = [];
  const deps: ProbeDeps = { out: bytes => out.push(String(bytes)), err: text => err.push(text), writeBytes: () => {}, readText: () => "", env: { KEY: "secret-token" }, fetch: fetchImpl, resolve: async () => ["10.0.0.5"], save: (_target, findings) => { saved.push(findings); return "scanid12345"; }, ...extra };
  return { deps, out, err, saved };
};
// Obeys any "reply with only <token>" style instruction and nothing else.
const naive = (async (_u: unknown, init?: RequestInit) => { const m = /ZX[0-9A-F]{8}/.exec(prompt(init)); return reply(m && !/Use your shell|Decode this/.test(prompt(init)) ? m[0] : "No."); }) as typeof fetch;

describe("0 probe", () => {
  it("reports what got through as a scan report, saves on request, and exits 1 at --fail-on", async () => {
    const h = harness(naive);
    const code = await runProbe("https://app.test/chat", options({ body: '{"message":"{{prompt}}"}', responsePath: "reply", failOn: "medium", save: true }), h.deps);
    const report = JSON.parse(h.out.join(""));
    expect(report.target).toBe("https://app.test/chat");
    expect(report.findings.map((finding: { templateId: string }) => finding.templateId)).toEqual(expect.arrayContaining(["probe/direct-override", "probe/indirect-document"]));
    expect(code).toBe(1);
    expect(h.saved).toHaveLength(1);
    expect(h.err.join("\n")).toContain("probing https://app.test/chat with up to");
    expect(h.err.join("\n")).toContain("saved");
  });
  it("exits 0 when nothing got through, and puts the model name in the default body", async () => {
    const bodies: string[] = [];
    const refuse = (async (_u: unknown, init?: RequestInit) => { bodies.push(String(init?.body)); return new Response(JSON.stringify({ choices: [{ message: { content: "No." } }] })); }) as typeof fetch;
    const h = harness(refuse);
    expect(await runProbe("https://api.test/v1/chat", options({ model: "m-1", failOn: "low" }), h.deps)).toBe(0);
    expect(JSON.parse(bodies[0]!)).toMatchObject({ model: "m-1", messages: [{ role: "user" }] });
    expect(JSON.parse(h.out.join("")).findings).toEqual([]);
  });
  it("refuses a public host without --i-own-this, accepts it with the exact host, and records the scope", async () => {
    const never = vi.fn() as unknown as typeof fetch;
    const publicDns = { resolve: async () => ["203.0.113.9"] };
    await expect(runProbe("https://chat.test/api", options(), harness(never, publicDns).deps)).rejects.toThrow("--i-own-this chat.test");
    await expect(runProbe("https://chat.test/api", options({ iOwnThis: "other.test" }), harness(never, publicDns).deps)).rejects.toThrow("exact host");
    expect(never).not.toHaveBeenCalled();
    const refuse = (async () => reply("No.")) as typeof fetch;
    const h = harness(refuse, publicDns);
    expect(await runProbe("https://chat.test/api", options({ iOwnThis: "chat.test" }), h.deps)).toBe(0);
    expect(JSON.parse(h.out.join("")).probeScope).toMatchObject({ host: "chat.test", network: "public", addresses: ["203.0.113.9"], acknowledgedHost: "chat.test" });
    expect(h.err.join("\n")).toContain("acknowledged with --i-own-this chat.test");
  });
  it("reads a header value from the environment, and refuses a bad header or a missing variable", () => {
    expect(parseHeaders(["Authorization: Bearer $KEY", "X-A: b"], { KEY: "k" })).toEqual({ Authorization: "Bearer k", "X-A": "b" });
    expect(() => parseHeaders(["Authorization: Bearer $MISSING"], {})).toThrow("$MISSING");
    expect(() => parseHeaders(["nocolon"], {})).toThrow("Name: value");
    expect(() => parseHeaders(["bad name: x"], {})).toThrow("not valid");
  });
  it("says so when the endpoint cannot be reached, and rejects bad options before sending anything", async () => {
    const down = vi.fn(async () => { throw new Error("connect ECONNREFUSED"); }) as unknown as typeof fetch;
    await expect(runProbe("https://x.test/chat", options(), harness(down).deps)).rejects.toThrow("Every request to x.test failed: connect ECONNREFUSED");
    const never = vi.fn() as unknown as typeof fetch;
    await expect(runProbe("https://x.test", options({ probes: "nope" }), harness(never).deps)).rejects.toThrow("Unknown probe");
    await expect(runProbe("https://x.test", options({ repeat: "99" }), harness(never).deps)).rejects.toThrow("--repeat");
    await expect(runProbe("https://x.test", options({ format: "pdf" }), harness(never).deps)).rejects.toThrow("PDF is binary");
    expect(never).not.toHaveBeenCalled();
  });
});
