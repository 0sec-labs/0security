import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseScannerList, scanPrompt, scannerArguments, scannerById, SCANNERS } from "@0/engine/shared";
import { runPrePass } from "../../prepass.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const tmp = () => { const dir = mkdtempSync(join(tmpdir(), "0-prepass-")); dirs.push(dir); return dir; };
const posix = process.platform === "win32" ? it.skip : it;

/** Assembled at run time, so no secret-shaped text is ever written to the repository. */
const FAKE_SECRET = ["AKIA", "Q3GJ7KWV", "XHLN4P2B"].join("");
const FAKE_TOKEN = ["k8Jd93Lp", "Q2xZvN7b", "R4tY6wA1", "sE5uH0cF"].join("");

const sarif = (tool: string, results: unknown[], rules: unknown[] = []) => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: tool, rules } }, results }] });
const result = (ruleId: string, message: string, uri: string, line: number, extra: Record<string, unknown> = {}) => ({ ruleId, message: { text: message }, level: "error", locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line, ...extra } } }] });

/** A fake scanner: records its arguments one per line, then prints `output` and exits with `code`. */
function fakeTool(name: string, output: string, code = 0, extra = "") {
  const dir = tmp(); const log = join(dir, "args.log"); const body = join(dir, "out.json"); const bin = join(dir, name);
  writeFileSync(body, output);
  writeFileSync(bin, `#!/bin/sh\nprintf '%s\\n' "$@" > '${log}'\n${extra}\ncat '${body}'\nexit ${code}\n`);
  chmodSync(bin, 0o755);
  return { bin, args: () => readFileSync(log, "utf8").trim().split("\n") };
}

describe("scanner list", () => {
  it("keeps foxguard as the default and names the new scanners", () => {
    expect(parseScannerList(undefined)).toEqual(["foxguard"]);
    expect(parseScannerList(["gitleaks,trivy", "osv-scanner"])).toEqual(["gitleaks", "trivy", "osv-scanner"]);
    expect(() => parseScannerList(["nope"])).toThrow(/choose from foxguard, semgrep, opengrep, gitleaks, trivy, osv-scanner/);
  });
  it("gives each new scanner an override variable and an install hint", () => {
    for (const id of ["gitleaks", "trivy", "osv-scanner"]) {
      const spec = scannerById(id)!;
      expect(spec.pathEnv).toMatch(/^ZERO_[A-Z_]+_PATH$/);
      expect(spec.install).toContain("brew install");
    }
    expect(scannerById("osv-scanner")!.pathEnv).toBe("ZERO_OSV_SCANNER_PATH");
  });
  it("runs each new scanner with the documented flags, redaction on, and the folder last", () => {
    expect(scannerArguments(scannerById("gitleaks")!, "/w/app")).toEqual(["dir", "--report-format", "sarif", "--report-path", "-", "--redact", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error", "--config", "/dev/null", "--gitleaks-ignore-path", "/dev/null", "/w/app"]);
    expect(scannerArguments(scannerById("trivy")!, "/w/app")).toEqual(["fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--quiet", "--no-progress", "--disable-telemetry", "--ignorefile", "/dev/null", "--config", "/dev/null", "/w/app"]);
    expect(scannerArguments(scannerById("osv-scanner")!, "/w/app")).toEqual(["scan", "source", "--format", "sarif", "--allow-no-lockfiles", "--verbosity", "error", "-r", "--config", "/dev/null", "/w/app"]);
    expect(scannerArguments(scannerById("checkov")!, "/w/app", undefined, "/tmp/out")).toEqual(["-d", "/w/app", "-o", "sarif", "--output-file-path", "/tmp/out", "--quiet", "--skip-download", "--config-file", "/dev/null"]);
    expect(scannerArguments(scannerById("gitleaks")!, "/w/app", undefined, "", { repoIgnores: true })).toEqual(["dir", "--report-format", "sarif", "--report-path", "-", "--redact", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error", "/w/app"]);
    expect(scannerArguments(scannerById("trivy")!, "/w/app", undefined, "", { repoIgnores: true })).toEqual(["fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--quiet", "--no-progress", "--disable-telemetry", "/w/app"]);
    expect(scannerArguments(scannerById("osv-scanner")!, "/w/app", undefined, "", { repoIgnores: true })).toEqual(["scan", "source", "--format", "sarif", "--allow-no-lockfiles", "--verbosity", "error", "-r", "/w/app"]);
    expect(scannerArguments(scannerById("checkov")!, "/w/app", undefined, "/tmp/out", { repoIgnores: true })).toEqual(["-d", "/w/app", "-o", "sarif", "--output-file-path", "/tmp/out", "--quiet", "--skip-download"]);
    expect(SCANNERS.filter(spec => spec.args.includes("{rules}")).map(spec => spec.id)).toEqual(["semgrep", "opengrep"]);
  });
});

describe("runPrePass with fake scanners", () => {
  posix("passes the arguments to gitleaks and keeps no secret in a lead", async () => {
    const folder = tmp();
    // A scanner that failed to redact: the value is in the snippet and in the message.
    const output = sarif("gitleaks", [result("aws-access-token", `Match: ${FAKE_SECRET}\nfound in file`, `${folder}/src/a.js`, 3, { snippet: { text: FAKE_SECRET } })]);
    const tool = fakeTool("gitleaks", output, 0);
    const found = await runPrePass(folder, ["gitleaks"], [], { env: { ...process.env, ZERO_GITLEAKS_PATH: tool.bin } });
    expect(tool.args().slice(0, 11)).toEqual(["dir", "--report-format", "sarif", "--report-path", "-", "--redact", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error"]);
    expect(tool.args()).toContain("--config");
    expect(tool.args()).toContain("--gitleaks-ignore-path");
    expect(tool.args().slice(-1)).toEqual([folder]);
    await runPrePass(folder, ["gitleaks"], [], { env: { ...process.env, ZERO_GITLEAKS_PATH: tool.bin }, repoIgnores: true });
    expect(tool.args()).toEqual(["dir", "--report-format", "sarif", "--report-path", "-", "--redact", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error", folder]);
    expect(found?.leads).toHaveLength(1);
    expect(found?.leads[0]).toMatchObject({ tool: "gitleaks", ruleId: "aws-access-token", path: "src/a.js", startLine: 3 });
    expect(JSON.stringify(found)).not.toContain(FAKE_SECRET);
    // What the scan thread is told, and what a finding recorded from the lead would carry.
    const prompt = scanPrompt("/w/app", "scan", found);
    expect(prompt).toContain("src/a.js:3 aws-access-token");
    expect(prompt).not.toContain(FAKE_SECRET);
  });

  posix("removes a matched value from trivy secret leads as well", async () => {
    const folder = tmp();
    const output = sarif("Trivy", [result("generic-token", `Artifact: app.env\nType: \nSecret Token\nSeverity: HIGH\nMatch: TOKEN=${FAKE_TOKEN}`, "app.env", 1, { snippet: { text: `TOKEN=${FAKE_TOKEN}` } })]);
    const tool = fakeTool("trivy", output);
    const found = await runPrePass(folder, ["trivy"], [], { env: { ...process.env, ZERO_TRIVY_PATH: tool.bin } });
    expect(tool.args().slice(0, 4)).toEqual(["fs", "--scanners", "vuln,misconfig,secret", "--format"]);
    expect(found?.leads[0]?.path).toBe("app.env");
    expect(JSON.stringify(found)).not.toContain(FAKE_TOKEN);
    expect(scanPrompt("/w/app", "scan", found)).not.toContain(FAKE_TOKEN);
  });

  posix("reads the report of a scanner that exits non-zero because it found something", async () => {
    const folder = tmp();
    const tool = fakeTool("osv-scanner", sarif("osv-scanner", [result("CVE-2020-28500", "Package 'lodash@4.17.15' is vulnerable", `file://${folder}/package-lock.json`, 1)]), 1);
    const found = await runPrePass(folder, ["osv-scanner"], [], { env: { ...process.env, ZERO_OSV_SCANNER_PATH: tool.bin } });
    expect(tool.args().slice(0, 3)).toEqual(["scan", "source", "--format"]);
    expect(found?.leads[0]).toMatchObject({ ruleId: "CVE-2020-28500", path: "package-lock.json" });
  });

  posix("runs several scanners at once and labels the leads by tool", async () => {
    const folder = tmp();
    const g = fakeTool("gitleaks", sarif("gitleaks", [result("generic-api-key", "x", `${folder}/a.js`, 1)]));
    const t = fakeTool("trivy", sarif("Trivy", [result("AWS-0092", "public acl", "main.tf", 3)]));
    const env = { ...process.env, ZERO_GITLEAKS_PATH: g.bin, ZERO_TRIVY_PATH: t.bin, PATH: "/bin:/usr/bin" };
    const notes: string[] = [];
    const found = await runPrePass(folder, ["gitleaks", "trivy", "osv-scanner"], [], { env, note: text => notes.push(text) });
    expect(found?.tools).toEqual(["gitleaks", "trivy"]);
    expect(found?.total).toBe(2);
    expect(scanPrompt("/w/app", "scan", found)).toMatch(/- gitleaks .*a\.js:1 generic-api-key[\s\S]*- trivy .*main\.tf:3 AWS-0092/);
  });

  it("skips a missing scanner and says how to install it", async () => {
    const notes: string[] = [];
    const found = await runPrePass(tmp(), ["gitleaks"], [], { env: { PATH: tmp() }, note: text => notes.push(text) });
    expect(found).toBeUndefined();
    expect(notes).toEqual([expect.stringContaining("gitleaks is not installed")]);
    expect(notes[0]).toContain("brew install gitleaks");
  });

  posix("finds a scanner on PATH", async () => {
    const tool = fakeTool("gitleaks", sarif("gitleaks", [result("generic-api-key", "x", "a.js", 1)]));
    const found = await runPrePass(tmp(), ["gitleaks"], [], { env: { PATH: `${tool.bin.replace(/\/gitleaks$/, "")}:/bin:/usr/bin` } });
    expect(found?.total).toBe(1);
  });

  posix("stops a scanner that runs too long and keeps going without it", async () => {
    const slow = fakeTool("gitleaks", "{}", 0, "exec sleep 5");
    const notes: string[] = [];
    const started = Date.now();
    const found = await runPrePass(tmp(), ["gitleaks"], [], { env: { ...process.env, ZERO_GITLEAKS_PATH: slow.bin }, timeoutSeconds: 0.3, note: text => notes.push(text) });
    expect(found).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(4000);
    expect(notes[0]).toContain("did not finish");
  });

  posix("skips a scanner that fails without a report", async () => {
    const bad = fakeTool("trivy", "boom", 2);
    const notes: string[] = [];
    expect(await runPrePass(tmp(), ["trivy"], [], { env: { ...process.env, ZERO_TRIVY_PATH: bad.bin }, note: text => notes.push(text) })).toBeUndefined();
    expect(notes[0]).toContain("trivy failed");
  });
});

// Real tools, run only when asked: ZERO_REAL_SCANNERS=1 and the tool installed. They need the network (rules, databases).
const which = (name: string): string | undefined => { try { return execFileSync("which", [name], { encoding: "utf8" }).trim() || undefined; } catch { return undefined; } };
const real = (name: string) => process.env.ZERO_REAL_SCANNERS === "1" && which(name) ? it : it.skip;

describe("runPrePass with the real tools", () => {
  real("gitleaks")("finds a planted secret and returns only the redacted form", async () => {
    const folder = tmp(); mkdirSync(join(folder, "src"));
    writeFileSync(join(folder, "src", "config.js"), `const awsKey = "${FAKE_SECRET}";\nconst token = "${FAKE_TOKEN}";\n`);
    const found = await runPrePass(folder, ["gitleaks"], [], { timeoutSeconds: 60 });
    expect(found?.leads.map(lead => lead.ruleId)).toContain("aws-access-token");
    expect(found?.leads.every(lead => lead.path === "src/config.js")).toBe(true);
    const serialized = JSON.stringify(found);
    expect(serialized).not.toContain(FAKE_SECRET);
    expect(serialized).not.toContain(FAKE_TOKEN);
    expect(scanPrompt(folder, "scan", found)).not.toContain(FAKE_SECRET);
  }, 90_000);

  real("trivy")("finds a Terraform misconfiguration and redacts a planted secret", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "main.tf"), 'resource "aws_s3_bucket" "b" {\n  bucket = "demo"\n  acl    = "public-read"\n}\n');
    writeFileSync(join(folder, "app.env"), `AWS_ACCESS_KEY_ID=${FAKE_SECRET}\n`);
    const found = await runPrePass(folder, ["trivy"], [], { timeoutSeconds: 240 });
    expect(found?.leads.some(lead => lead.path === "main.tf" && lead.ruleId === "AWS-0092")).toBe(true);
    expect(found?.leads.some(lead => lead.path === "app.env")).toBe(true);
    expect(JSON.stringify(found)).not.toContain(FAKE_SECRET);
  }, 300_000);

  real("osv-scanner")("reports a known-vulnerable package in a lockfile, and runs on this repository's lockfile", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "package-lock.json"), JSON.stringify({ name: "demo", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "demo", version: "1.0.0", dependencies: { lodash: "4.17.15" } }, "node_modules/lodash": { version: "4.17.15" } } }));
    const found = await runPrePass(folder, ["osv-scanner"], [], { timeoutSeconds: 120 });
    expect(found?.leads.some(lead => lead.ruleId === "CVE-2020-28500" && lead.path === "package-lock.json")).toBe(true);
    const repo = join(__dirname, "..", "..", "..", "..", "..");
    const own = await runPrePass(repo, ["osv-scanner"], [], { timeoutSeconds: 180 });
    expect(own === undefined || Array.isArray(own.leads)).toBe(true);
  }, 360_000);
});

describe("in-repo ignore files and scanner configuration isolation", () => {
  it("isolates gitleaks, trivy, osv-scanner, and checkov from in-repo ignore/config files by default", () => {
    const folder = tmp();
    // Plant in-repo ignore and config files
    writeFileSync(join(folder, ".gitleaksignore"), "some-ignore");
    writeFileSync(join(folder, ".gitleaks.toml"), "[allowlist]\npaths = [\"src/\"]");
    writeFileSync(join(folder, ".trivyignore"), "AVD-AWS-0092");
    writeFileSync(join(folder, "trivy.yaml"), "format: json");
    writeFileSync(join(folder, "osv-scanner.toml"), "IgnoredVulns = [\"CVE-2020-28500\"]");
    writeFileSync(join(folder, ".checkov.yml"), "framework: [terraform]");

    // gitleaks: default isolation provides empty ignore and explicit default config; repoIgnores drops them
    const gitleaksDefault = scannerArguments(scannerById("gitleaks")!, folder);
    expect(gitleaksDefault).toContain("--config");
    expect(gitleaksDefault).toContain("--gitleaks-ignore-path");
    const gitleaksHonored = scannerArguments(scannerById("gitleaks")!, folder, undefined, "", { repoIgnores: true });
    expect(gitleaksHonored).not.toContain("--config");
    expect(gitleaksHonored).not.toContain("--gitleaks-ignore-path");

    // trivy: default isolation provides empty ignore and empty config; repoIgnores drops them
    const trivyDefault = scannerArguments(scannerById("trivy")!, folder);
    expect(trivyDefault).toContain("--ignorefile");
    expect(trivyDefault).toContain("--config");
    const trivyHonored = scannerArguments(scannerById("trivy")!, folder, undefined, "", { repoIgnores: true });
    expect(trivyHonored).not.toContain("--ignorefile");
    expect(trivyHonored).not.toContain("--config");

    // osv-scanner: default isolation provides empty config; repoIgnores drops it
    const osvDefault = scannerArguments(scannerById("osv-scanner")!, folder);
    expect(osvDefault).toContain("--config");
    const osvHonored = scannerArguments(scannerById("osv-scanner")!, folder, undefined, "", { repoIgnores: true });
    expect(osvHonored).not.toContain("--config");

    // checkov: default isolation provides empty config; repoIgnores drops it
    const checkovDefault = scannerArguments(scannerById("checkov")!, folder, undefined, "/tmp/out");
    expect(checkovDefault).toContain("--config-file");
    const checkovHonored = scannerArguments(scannerById("checkov")!, folder, undefined, "/tmp/out", { repoIgnores: true });
    expect(checkovHonored).not.toContain("--config-file");
  });
});
