import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseNucleiJsonl } from "@0/engine/shared";
import type { NucleiTargetRun } from "../../nuclei-target.js";
import { runScan, type ScanDeps } from "../scan.js";

afterEach(() => { process.exitCode = undefined; });
const jsonl = readFileSync(new URL("../../../../engine/src/shared/__fixtures__/nuclei.jsonl", import.meta.url), "utf8");
const options = (extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "60", skill: "scan", passes: "1", batches: "auto", scanner: ["nuclei"], targetUrl: "http://127.0.0.1:18089", acknowledgeHost: "127.0.0.1:18089", ...extra }) as never;

function fakes(extra: Partial<ScanDeps> = {}) {
  const out: string[] = []; const err: string[] = [];
  const nucleiTarget = vi.fn(async (_options: Record<string, unknown>): Promise<NucleiTargetRun> => ({ target: { url: "http://127.0.0.1:18089/", host: "127.0.0.1:18089", hostname: "127.0.0.1", addresses: ["127.0.0.1"], network: "loopback", authorisedBy: ["acknowledged"] }, scope: "127.0.0.1:18089 (loopback network, 127.0.0.1), authorised by the typed host 127.0.0.1:18089", findings: parseNucleiJsonl(jsonl).findings, jsonl, version: "3.9.9", rateLimit: 10, concurrency: 5 }));
  const saveTargetFindings = vi.fn(() => ({ scanId: "sarif-0123456789abcdef", findings: 1 }));
  const deps = {
    out: (bytes: Uint8Array | string) => out.push(typeof bytes === "string" ? bytes : Buffer.from(bytes).toString("utf8")), err: (text: string) => err.push(text), now: () => new Date("2026-11-24T10:00:00Z"),
    writeBytes: vi.fn(), nucleiTarget, saveTargetFindings, open: vi.fn(async () => { throw new Error("no console for a target scan"); }), startConsole: vi.fn(),
    ...extra,
  } as unknown as ScanDeps;
  return { deps, out, err, nucleiTarget, saveTargetFindings };
}

describe("scan --scanner nuclei --target-url", () => {
  it("runs Nuclei, reports the findings with the scope recorded, saves them for triage, and starts no console or model", async () => {
    const { deps, out, err, nucleiTarget, saveTargetFindings } = fakes();
    await runScan(undefined, options(), deps);
    expect(nucleiTarget).toHaveBeenCalledWith(expect.objectContaining({ targetUrl: "http://127.0.0.1:18089", acknowledgeHost: "127.0.0.1:18089" }));
    expect(nucleiTarget.mock.calls[0]![0]).not.toHaveProperty("rateLimit");
    expect(nucleiTarget.mock.calls[0]![0]).not.toHaveProperty("concurrency");
    const report = JSON.parse(out.join(""));
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({ title: "Admin panel exposed without login", severity: "medium" });
    expect(report.findings[0].evidence.request).toBe("GET http://127.0.0.1:18089/admin");
    expect(JSON.stringify(report)).toContain("authorised by the typed host 127.0.0.1:18089");
    expect(JSON.stringify(report)).toContain("0 sent no request itself");
    expect(saveTargetFindings).toHaveBeenCalledOnce();
    expect(err.join("\n")).toContain("saved for triage");
    expect(deps.open).not.toHaveBeenCalled();
  });
  it("passes the rate limit, concurrency, templates and scope file through", async () => {
    const { deps, nucleiTarget } = fakes();
    await runScan(undefined, options({ acknowledgeHost: undefined, scopeFile: "/s.txt", rateLimit: "3", concurrency: "2", templates: "/t", explicit: ["concurrency"] }), deps);
    expect(nucleiTarget).toHaveBeenCalledWith(expect.objectContaining({ scopeFile: "/s.txt", rateLimit: 3, concurrency: 2, templates: "/t" }));
  });
  it("is a usage error without a scope file or typed host, without --scanner nuclei, and with a folder or a folder-only flag", async () => {
    for (const [target, extra, message] of [
      [undefined, { acknowledgeHost: undefined }, "Name what you may test"],
      [undefined, { scanner: undefined }, "needs --scanner nuclei"],
      [undefined, { scanner: ["nuclei", "foxguard"] }, "no other scanner"],
      ["./app", {}, "give one or the other"],
      [undefined, { diff: "origin/main" }, "--diff"],
      [undefined, { targetUrl: undefined }, "add --target-url"],
    ] as const) {
      const { deps, err, nucleiTarget } = fakes();
      process.exitCode = undefined;
      await runScan(target, options(extra), deps);
      expect(err.join("\n")).toContain(message);
      expect(process.exitCode).toBe(2);
      expect(nucleiTarget).not.toHaveBeenCalled();
    }
  });
  it("turns a refused target or a missing Nuclei into a usage error with the way forward", async () => {
    const { deps, err } = fakes({ nucleiTarget: vi.fn(async () => { throw new Error("Refused: x is a public host. add --acknowledge-host x."); }) });
    await runScan(undefined, options(), deps);
    expect(err.join("\n")).toContain("--acknowledge-host");
    expect(process.exitCode).toBe(2);
  });
  it("keeps the findings in a file when they cannot be saved, and says how to import them", async () => {
    const { deps, err } = fakes({ saveTargetFindings: vi.fn(() => { throw new Error("a console is running"); }) });
    await runScan(undefined, options(), deps);
    expect(deps.writeBytes).toHaveBeenCalledWith(expect.stringMatching(/^nuclei-results-.*\.jsonl$/), expect.anything());
    expect(err.join("\n")).toContain("0security findings import nuclei-results-");
  });
  it("exits 1 with --fail-on when a finding is at or above the severity", async () => {
    const { deps } = fakes();
    await runScan(undefined, options({ failOn: "medium" }), deps);
    expect(process.exitCode).toBe(1);
  });
  it("does not accept --scanner nuclei for a folder scan", async () => {
    const { deps, err } = fakes();
    await runScan("./app", options({ targetUrl: undefined }), deps);
    expect(err.join("\n")).toContain("add --target-url");
  });
});
