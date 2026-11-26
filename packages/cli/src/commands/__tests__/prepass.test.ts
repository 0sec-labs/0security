import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
    expect(scannerArguments(scannerById("checkov")!, "/w/app", undefined, "/tmp/out")).toEqual(["-d", "/w/app", "-o", "sarif", "--output-file-path", "/tmp/out", "--quiet", "--skip-download"]);
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
    expect(tool.args().slice(0, 12)).toEqual(["dir", "--report-format", "sarif", "--report-path", "-", "--redact", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error"]);
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
    expect(notes).toEqual([expect.stringContaining("No pattern scanner is installed, so the scan runs without leads.")]);
    expect(notes[0]).toContain("brew install gitleaks");
  });

  posix("names a missing scanner on its own line when another one ran", async () => {
    const tool = fakeTool("trivy", sarif("trivy", [result("CVE-1", "x", "a.js", 1)]));
    const notes: string[] = [];
    const found = await runPrePass(tmp(), ["trivy", "gitleaks"], [], { env: { ...process.env, ZERO_TRIVY_PATH: tool.bin, PATH: "/bin:/usr/bin" }, note: text => notes.push(text) });
    expect(found?.tools).toEqual(["trivy"]);
    expect(notes).toEqual([expect.stringContaining("gitleaks is not installed, so it was skipped")]);
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
  const args = (id: string, options: Parameters<typeof scannerArguments>[4] = {}) => scannerArguments(scannerById(id)!, "/w/app", undefined, "/tmp/out", { emptyConfig: "/s/empty", emptyIgnore: "/s/empty", gitleaksConfig: "/s/gitleaks.toml", ...options });

  it("points each scanner at an empty config or ignore file, placed before the folder", () => {
    expect(args("foxguard")).toEqual(["--format", "sarif", "--config", "/s/empty", "/w/app"]);
    expect(args("semgrep")).toEqual(["scan", "--sarif", "--quiet", "--metrics", "off", "--config", "p/default", "--x-semgrepignore-filename", ".0-no-semgrepignore", "/w/app"]);
    expect(args("opengrep")).toEqual(["scan", "--sarif", "--quiet", "--config", "p/default", "--semgrepignore-filename", ".0-no-semgrepignore", "/w/app"]);
    expect(args("gitleaks").slice(-5)).toEqual(["--config", "/s/gitleaks.toml", "--gitleaks-ignore-path", "/s/empty", "/w/app"]);
    expect(args("trivy").slice(-5)).toEqual(["--ignorefile", "/s/empty", "--config", "/s/empty", "/w/app"]);
    expect(args("osv-scanner").slice(-3)).toEqual(["--config", "/s/empty", "/w/app"]);
    // Checkov has no option that turns off the .checkov.yaml in the scanned folder, so it gets none.
    expect(args("checkov")).toEqual(["-d", "/w/app", "-o", "sarif", "--output-file-path", "/tmp/out", "--quiet", "--skip-download"]);
  });

  it("adds no isolation argument with repoIgnores", () => {
    for (const spec of SCANNERS) {
      const honored = args(spec.id, { repoIgnores: true });
      expect(honored).toEqual(scannerArguments(spec, "/w/app", undefined, "/tmp/out", { repoIgnores: true }));
      for (const flag of ["--ignorefile", "--gitleaks-ignore-path", "--semgrepignore-filename", "--x-semgrepignore-filename"]) expect(honored).not.toContain(flag);
      if (spec.id !== "semgrep" && spec.id !== "opengrep" && spec.id !== "checkov") expect(honored).not.toContain("--config");
    }
  });

  posix("gives foxguard an empty config file while it runs, removes it after, and omits it with repoIgnores", async () => {
    const folder = tmp();
    const dir = tmp(); const bin = join(dir, "foxguard"); const probe = join(dir, "probe");
    writeFileSync(bin, `#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "--config" ]; then echo "$2" > '${probe}'; wc -c < "$2" >> '${probe}'; fi; shift; done\necho '${sarif("foxguard", [])}'\n`);
    chmodSync(bin, 0o755);
    const env = { ...process.env, ZERO_FOXGUARD_PATH: bin };
    await runPrePass(folder, ["foxguard"], [], { env });
    const [config, size] = readFileSync(probe, "utf8").trim().split("\n");
    expect(config).not.toBe("/dev/null");
    expect(size!.trim()).toBe("0");
    expect(existsSync(config!)).toBe(false);
    rmSync(probe);
    await runPrePass(folder, ["foxguard"], [], { env, repoIgnores: true });
    expect(existsSync(probe)).toBe(false);
  });

  posix("skips checkov when the folder has a .checkov.yaml, unless repoIgnores", async () => {
    const folder = tmp();
    writeFileSync(join(folder, ".checkov.yaml"), "skip-check:\n  - CKV_DOCKER_2\n");
    const tool = fakeTool("checkov", "{}", 0);
    const ran = () => existsSync(join(tool.bin, "..", "args.log"));
    const notes: string[] = [];
    const env = { ...process.env, ZERO_CHECKOV_PATH: tool.bin };
    expect(await runPrePass(folder, ["checkov"], [], { env, note: text => notes.push(text) })).toBeUndefined();
    expect(notes[0]).toContain("always reads .checkov.yaml");
    expect(notes[0]).toContain("--repo-ignores");
    expect(ran()).toBe(false);
    await runPrePass(folder, ["checkov"], [], { env, repoIgnores: true });
    expect(ran()).toBe(true);
    const clean = tmp();
    await runPrePass(clean, ["checkov"], [], { env });
    expect(tool.args()).toContain(clean);
  });
});

// Each real scanner, with a finding in the folder and an in-repo file that would hide it. By default the finding is still reported.
const RULE = "rules:\n  - id: demo-eval\n    pattern: eval(...)\n    message: eval is dangerous\n    languages: [javascript]\n    severity: ERROR\n";
const EVAL_APP = "const express = require('express');\nconst app = express();\napp.get('/x', (req, res) => { eval(req.query.c); res.send('ok'); });\n";
const expat = "/opt/homebrew/opt/expat/lib";
// Checkov needs the Homebrew expat library on some Macs.
const realEnv = { ...process.env, ...(process.platform === "darwin" && existsSync(expat) ? { DYLD_LIBRARY_PATH: expat } : {}) };

describe("in-repo files do not hide findings from the real tools", () => {
  real("foxguard")("foxguard: scan.no_builtins in .foxguard.yml does not turn off the built-in rules", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "app.js"), EVAL_APP);
    writeFileSync(join(folder, ".foxguard.yml"), "scan:\n  no_builtins: true\n");
    expect((await runPrePass(folder, ["foxguard"], [], { env: realEnv, timeoutSeconds: 60 }))?.total ?? 0).toBeGreaterThan(0);
    expect((await runPrePass(folder, ["foxguard"], [], { env: realEnv, timeoutSeconds: 60, repoIgnores: true }))?.total ?? 0).toBe(0);
  }, 90_000);

  for (const id of ["semgrep", "opengrep"]) {
    real(id)(`${id}: .semgrepignore does not hide a finding`, async () => {
      const folder = tmp(); const rules = join(tmp(), "rule.yml");
      writeFileSync(rules, RULE);
      writeFileSync(join(folder, "app.js"), EVAL_APP);
      writeFileSync(join(folder, ".semgrepignore"), "*.js\n");
      const found = await runPrePass(folder, [id], [rules], { env: realEnv, timeoutSeconds: 120 });
      expect(found?.leads.some(lead => lead.path === "app.js")).toBe(true);
      const honored = await runPrePass(folder, [id], [rules], { env: realEnv, timeoutSeconds: 120, repoIgnores: true });
      expect(honored?.total ?? 0).toBe(0);
    }, 150_000);
  }

  real("gitleaks")("gitleaks: .gitleaks.toml does not hide a secret", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "config.js"), `const awsKey = "${FAKE_SECRET}";\n`);
    writeFileSync(join(folder, ".gitleaks.toml"), '[allowlist]\npaths = ["config.js"]\n');
    expect((await runPrePass(folder, ["gitleaks"], [], { env: realEnv, timeoutSeconds: 60 }))?.leads.length ?? 0).toBeGreaterThan(0);
    expect((await runPrePass(folder, ["gitleaks"], [], { env: realEnv, timeoutSeconds: 60, repoIgnores: true }))?.leads.length ?? 0).toBe(0);
  }, 90_000);

  real("trivy")("trivy: .trivyignore in the working folder does not hide a misconfiguration", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "main.tf"), 'resource "aws_s3_bucket" "b" {\n  bucket = "demo"\n  acl    = "public-read"\n}\n');
    writeFileSync(join(folder, ".trivyignore"), "AWS-0092\nAVD-AWS-0092\n");
    expect((await runPrePass(folder, ["trivy"], [], { env: realEnv, cwd: folder, timeoutSeconds: 240 }))?.leads.some(lead => lead.ruleId === "AWS-0092")).toBe(true);
    expect((await runPrePass(folder, ["trivy"], [], { env: realEnv, cwd: folder, timeoutSeconds: 240, repoIgnores: true }))?.leads.some(lead => lead.ruleId === "AWS-0092") ?? false).toBe(false);
  }, 600_000);

  real("osv-scanner")("osv-scanner: osv-scanner.toml does not hide a vulnerable package", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "package-lock.json"), JSON.stringify({ name: "demo", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "demo", version: "1.0.0", dependencies: { lodash: "4.17.15" } }, "node_modules/lodash": { version: "4.17.15" } } }));
    writeFileSync(join(folder, "osv-scanner.toml"), '[[IgnoredVulns]]\nid = "CVE-2020-28500"\nreason = "x"\n');
    expect((await runPrePass(folder, ["osv-scanner"], [], { env: realEnv, timeoutSeconds: 120 }))?.leads.some(lead => lead.ruleId === "CVE-2020-28500")).toBe(true);
  }, 180_000);

  real("checkov")("checkov: a folder with .checkov.yaml is skipped, one without is scanned", async () => {
    const folder = tmp();
    writeFileSync(join(folder, "Dockerfile"), "FROM ubuntu\n");
    writeFileSync(join(folder, ".checkov.yaml"), "skip-check:\n  - CKV_DOCKER_2\n  - CKV_DOCKER_3\n  - CKV_DOCKER_7\n");
    const notes: string[] = [];
    expect(await runPrePass(folder, ["checkov"], [], { env: realEnv, timeoutSeconds: 120, note: text => notes.push(text) })).toBeUndefined();
    expect(notes[0]).toContain("always reads .checkov.yaml");
    rmSync(join(folder, ".checkov.yaml"));
    expect((await runPrePass(folder, ["checkov"], [], { env: realEnv, timeoutSeconds: 120 }))?.total ?? 0).toBeGreaterThan(0);
  }, 150_000);
});

describe("where the scanners run", () => {
  /**
   * A stand-in scanner that runs on every platform: node with a preload that records the folder it was started in and what that
   * folder holds, prints an empty SARIF log and exits before node reads the scanner arguments.
   */
  function nodeScanner(envName: string) {
    const dir = tmp(); const log = join(dir, "where.json"); const preload = join(dir, "preload.cjs").replaceAll("\\", "/");
    writeFileSync(preload, `const fs = require("fs"); fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify({ cwd: process.cwd(), entries: fs.readdirSync(".") })); process.stdout.write(${JSON.stringify(sarif("x", []))}); process.exit(0);\n`);
    return {
      env: { ...process.env, [envName]: process.execPath, NODE_OPTIONS: `--require "${preload}"` },
      where: () => JSON.parse(readFileSync(log, "utf8")) as { cwd: string; entries: string[] },
    };
  }
  const started = process.cwd();
  afterEach(() => process.chdir(started));

  it("runs a scanner in an empty folder, not in the folder 0 was started in", async () => {
    const tool = nodeScanner("ZERO_TRIVY_PATH");
    const folder = tmp();
    expect(await runPrePass(folder, ["trivy"], [], { env: tool.env })).toEqual({ tools: ["trivy"], leads: [], total: 0 });
    expect(tool.where().cwd).not.toBe(process.cwd());
    expect(tool.where().entries).toEqual([]);
  });

  it("does not run a scanner in the repository 0 was started in when a subfolder is scanned", async () => {
    // `cd repo && 0 scan ./src`: scanners also read their config from their working folder. Checkov reads .checkov.yaml there as
    // well as from -d, and that file can name external-checks-dir, which runs Python from the repository.
    const repo = tmp();
    mkdirSync(join(repo, "src"));
    writeFileSync(join(repo, ".checkov.yaml"), "external-checks-dir:\n  - checks\n");
    writeFileSync(join(repo, "trivy.yaml"), "scan:\n  skip-dirs: [\"**\"]\n");
    const tool = nodeScanner("ZERO_TRIVY_PATH");
    process.chdir(repo);
    await runPrePass(join(repo, "src"), ["trivy"], [], { env: tool.env });
    expect(tool.where().cwd).not.toBe(process.cwd());
    expect(tool.where().entries).toEqual([]);
  });

  it("keeps the caller's folder and the operator's choice", async () => {
    const tool = nodeScanner("ZERO_TRIVY_PATH");
    const folder = tmp(); const cwd = tmp();
    await runPrePass(folder, ["trivy"], [], { env: tool.env, cwd });
    expect(tool.where().cwd).toBe(realpathSync(cwd));
    process.chdir(cwd);
    await runPrePass(folder, ["trivy"], [], { env: tool.env, repoIgnores: true });
    expect(tool.where().cwd).toBe(realpathSync(cwd));
  });

  it("still skips checkov when the folder it runs in holds a .checkov.yaml", async () => {
    const tool = nodeScanner("ZERO_CHECKOV_PATH");
    const folder = tmp(); const cwd = tmp();
    writeFileSync(join(cwd, ".checkov.yml"), "external-checks-dir:\n  - checks\n");
    const notes: string[] = [];
    expect(await runPrePass(folder, ["checkov"], [], { env: tool.env, cwd, note: text => notes.push(text) })).toBeUndefined();
    expect(notes[0]).toContain("always reads .checkov.yml");
  });
});
