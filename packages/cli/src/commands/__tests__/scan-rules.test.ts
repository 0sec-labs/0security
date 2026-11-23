import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { prePassBlock, scannerArguments, scannerById, scannerTakesRules, type Finding } from "@0/engine/shared";
import { defaultScanDeps, runScan, type ScanDeps } from "../scan.js";
import { resolveRulePaths, tagCustomFindings } from "../../scan-rules.js";
import { toScanReport, type ScanOutcome } from "../../scan-report.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "scan-rules-")); dirs.push(dir); return dir; };
const saved = { semgrep: process.env.ZERO_SEMGREP_PATH, opengrep: process.env.ZERO_OPENGREP_PATH, foxguard: process.env.ZERO_FOXGUARD_PATH };
beforeEach(() => { delete process.env.ZERO_OPENGREP_PATH; delete process.env.ZERO_FOXGUARD_PATH; });
afterEach(() => {
  for (const [key, value] of Object.entries({ ZERO_SEMGREP_PATH: saved.semgrep, ZERO_OPENGREP_PATH: saved.opengrep, ZERO_FOXGUARD_PATH: saved.foxguard })) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  process.exitCode = undefined;
});

const SARIF = (ruleId: string) => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "fake", rules: [] } }, results: [{ ruleId, level: "error", message: { text: "hit" }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.js" }, region: { startLine: 3 } } }] }] }] });

/** A scanner that records its arguments, one per line, and prints one SARIF hit (or fails with a message). */
function fakeScanner(dir: string, name: string, mode: "ok" | "fail" = "ok"): { binary: string; log: string } {
  const binary = join(dir, name);
  const log = join(dir, `${name}.args`);
  const body = mode === "ok"
    ? `printf '%s\\n' "$@" > '${log}'\ncat <<'EOF'\n${SARIF("acme.rules.no-backdoor")}\nEOF\n`
    : `printf '%s\\n' "$@" > '${log}'\necho 'invalid rule file' >&2\nexit 2\n`;
  writeFileSync(binary, `#!/bin/sh\n${body}`);
  chmodSync(binary, 0o755);
  return { binary, log };
}
const argsOf = (log: string) => readFileSync(log, "utf8").split("\n").filter(Boolean);

describe("scanner arguments", () => {
  it("passes each rule path as its own --config, and the default pack when there are none", () => {
    const semgrep = scannerById("semgrep")!;
    expect(scannerArguments(semgrep, "/w", ["/r/a.yml", "/r/dir"], "", { repoIgnores: true })).toEqual(["scan", "--sarif", "--quiet", "--metrics", "off", "--config", "/r/a.yml", "--config", "/r/dir", "/w"]);
    expect(scannerArguments(semgrep, "/w", [])).toContain("p/default");
    expect(scannerArguments(scannerById("opengrep")!, "/w", ["/r/a.yml"], "", { repoIgnores: true })).toEqual(["scan", "--sarif", "--quiet", "--config", "/r/a.yml", "/w"]);
  });
  it("does not give rules to foxguard", () => {
    expect(scannerTakesRules(scannerById("foxguard")!)).toBe(false);
    expect(scannerArguments(scannerById("foxguard")!, "/w", ["/r/a.yml"], "", { repoIgnores: true })).toEqual(["--format", "sarif", "/w"]);
  });
});

describe("resolveRulePaths", () => {
  it("makes paths absolute and accepts files and folders", () => {
    const dir = temp();
    const file = join(dir, "r.yml");
    writeFileSync(file, "rules: []\n");
    const resolved = resolveRulePaths([file, dir, file]);
    expect(resolved).toHaveLength(2);
    expect(resolved.every(path => path.startsWith("/"))).toBe(true);
  });
  it("names a path that does not exist", () => {
    expect(() => resolveRulePaths(["/nonexistent/rules.yml"])).toThrow("--rules /nonexistent/rules.yml: no such file or folder.");
  });
});

describe("the pre-pass with rules", () => {
  it("runs semgrep with every named rule, without a shell, and tags the hits as custom", async () => {
    const dir = temp();
    const { binary, log } = fakeScanner(dir, "semgrep");
    process.env.ZERO_SEMGREP_PATH = binary;
    const repo = temp();
    const rules = ["/abs/one.yml", "/abs/two dir; touch pwned"];
    const result = await defaultScanDeps.prePass(repo, ["semgrep"], rules);
    expect(argsOf(log)).toEqual(["scan", "--sarif", "--quiet", "--metrics", "off", "--config", "/abs/one.yml", "--config", "/abs/two dir; touch pwned", "--x-semgrepignore-filename", ".0-no-semgrepignore", repo]);
    expect(result?.leads).toHaveLength(1);
    expect(result?.leads[0]).toMatchObject({ ruleId: "acme.rules.no-backdoor", ruleSource: "custom" });
  });
  it("runs opengrep with the rules too", async () => {
    const dir = temp();
    const { binary, log } = fakeScanner(dir, "opengrep");
    process.env.ZERO_OPENGREP_PATH = binary;
    await defaultScanDeps.prePass(temp(), ["opengrep"], ["/abs/one.yml"]);
    expect(argsOf(log)).toContain("/abs/one.yml");
  });
  it("leaves foxguard without rules and its hits untagged", async () => {
    const dir = temp();
    const { binary, log } = fakeScanner(dir, "foxguard");
    process.env.ZERO_FOXGUARD_PATH = binary;
    const result = await defaultScanDeps.prePass(temp(), ["foxguard"], ["/abs/one.yml"]);
    expect(argsOf(log)).not.toContain("/abs/one.yml");
    expect(result?.leads[0]?.ruleSource).toBeUndefined();
  });
  it("uses the default rules and no tag without --rules", async () => {
    const dir = temp();
    const { binary, log } = fakeScanner(dir, "semgrep");
    process.env.ZERO_SEMGREP_PATH = binary;
    const result = await defaultScanDeps.prePass(temp(), ["semgrep"]);
    expect(argsOf(log)).toContain("p/default");
    expect(result?.leads[0]?.ruleSource).toBeUndefined();
  });
  it("fails with the scanner's message when it cannot run the rules", async () => {
    const dir = temp();
    process.env.ZERO_SEMGREP_PATH = fakeScanner(dir, "semgrep", "fail").binary;
    await expect(defaultScanDeps.prePass(temp(), ["semgrep"], ["/abs/bad.yml"])).rejects.toThrow("semgrep could not run your rules: invalid rule file");
  });
  it("ignores a rules folder inside the scanned repository unless it is named", async () => {
    const dir = temp();
    const { binary, log } = fakeScanner(dir, "semgrep");
    process.env.ZERO_SEMGREP_PATH = binary;
    const repo = temp();
    for (const name of [".semgrep", "semgrep-rules"]) { mkdirSync(join(repo, name)); writeFileSync(join(repo, name, "r.yml"), "rules: []\n"); }
    writeFileSync(join(repo, ".semgrep.yml"), "rules: []\n");
    await defaultScanDeps.prePass(repo, ["semgrep"]);
    expect(argsOf(log).filter(arg => arg.includes("semgrep-rules") || arg.includes(".semgrep"))).toEqual([]);
    expect(argsOf(log)).toContain("p/default");
    // Named on the command line, it is used.
    await defaultScanDeps.prePass(repo, ["semgrep"], resolveRulePaths([join(repo, "semgrep-rules")]));
    expect(argsOf(log).some(arg => arg.endsWith("semgrep-rules"))).toBe(true);
    expect(argsOf(log)).not.toContain("p/default");
  });
});

describe("scan --rules", () => {
  const options = (extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "60", skill: "scan", passes: "1", ...extra }) as never;
  function fakes() {
    const err: string[] = [];
    const deps: ScanDeps = {
      open: async () => { throw new Error("should not connect"); }, out: () => {}, err: text => err.push(text), sleep: async () => {}, now: () => new Date("2026-01-01T00:00:00Z"),
      writeBytes: vi.fn(), loadReport: vi.fn(), startConsole: vi.fn(async () => () => {}), changedFiles: vi.fn(async () => undefined), prePass: vi.fn(async () => undefined), diffFiles: vi.fn(async () => []), clone: vi.fn(),
    };
    return { deps, err };
  }

  it("refuses a path that does not exist", async () => {
    const { deps, err } = fakes();
    await runScan(temp(), options({ rules: ["/nonexistent/r.yml"], scanner: ["semgrep"] }), deps);
    expect(err.join("\n")).toContain("--rules /nonexistent/r.yml: no such file or folder.");
    expect(process.exitCode).toBe(2);
    expect(deps.prePass).not.toHaveBeenCalled();
  });
  it("asks for semgrep or opengrep when only foxguard would run", async () => {
    const dir = temp();
    const file = join(dir, "r.yml");
    writeFileSync(file, "rules: []\n");
    const { deps, err } = fakes();
    await runScan(temp(), options({ rules: [file] }), deps);
    expect(err.join("\n")).toContain("not by foxguard");
    expect(process.exitCode).toBe(2);
  });
  it("refuses --prepass off", async () => {
    const dir = temp();
    const file = join(dir, "r.yml");
    writeFileSync(file, "rules: []\n");
    const { deps, err } = fakes();
    await runScan(temp(), options({ rules: [file], scanner: ["semgrep"], prepass: "off" }), deps);
    expect(err.join("\n")).toContain("drop --prepass off");
    expect(process.exitCode).toBe(2);
  });
});

describe("tagging", () => {
  const finding = (templateId: string, line: number) => ({ id: "f", templateId, title: "t", description: "d", severity: "high", category: "other", status: "discovered", timestamp: 1, evidence: { request: "", response: "" }, reviewAnnotation: { path: "a.js", startLine: line } }) as unknown as Finding;
  const lead = { ruleId: "acme.rules.no-backdoor", path: "a.js", startLine: 10, endLine: 10 };

  it("tags a finding that names the rule or sits on the flagged lines, and leaves others alone", () => {
    const tagged = tagCustomFindings([finding("no-backdoor", 99), finding("manual", 11), finding("manual", 50)], [lead]);
    expect(tagged[0]).toMatchObject({ ruleSource: "custom" });
    expect(tagged[1]).toMatchObject({ ruleSource: "custom" });
    expect(tagged[1]!.description).toContain("Flagged by your rule acme.rules.no-backdoor");
    expect(tagged[2]!.ruleSource).toBeUndefined();
  });
  it("shows up in the SARIF properties and marks the lead in the prompt", async () => {
    const outcome = { target: "app", roots: [], threadId: "t", startedAt: "", completedAt: "", budgetUsd: 1, budgetExhausted: false, failed: false, customLeads: [lead] } as ScanOutcome;
    const report = toScanReport(outcome, { findings: [finding("manual", 10)], summary: {}, warnings: [] } as never);
    expect(report.findings[0]!.ruleSource).toBe("custom");
    const block = prePassBlock({ tools: ["semgrep"], total: 1, leads: [{ tool: "semgrep", ruleId: lead.ruleId, title: "x", description: "", severity: "high", category: "other", path: "a.js", startLine: 10, fingerprint: "f", cwe: [], ruleSource: "custom" }] });
    expect(block).toContain("custom-rule high a.js:10 acme.rules.no-backdoor");
    expect(block).toContain("template_id");
  });
});
