import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";
import { listAudit, osecDB } from "@0/engine/storage";
import {
  detectCategoryFromAdvisory,
  detectCategoryFromRule,
  detectSeverityFromRule,
  fetchGithubAlerts,
  importGithubAlerts,
  parseAlertKinds,
  prepareGithubAlertsImport,
  type FetchedGithubAlerts,
  type GithubAlertsDeps,
  type GithubCodeScanningAlert,
  type GithubDependabotAlert,
  type GithubSecretScanningAlert,
} from "./github-alerts.js";
import { registerFindingsImportCommand, type FindingsImportDeps } from "./commands/findings-import.js";

const directories: string[] = [];
afterEach(() => {
  directories.splice(0).forEach(path => rmSync(path, { recursive: true, force: true }));
});
const createDb = () => {
  const dir = mkdtempSync(join(tmpdir(), "0-alerts-test-"));
  directories.push(dir);
  return join(dir, "0.db");
};

const sampleCodeScanningAlert: GithubCodeScanningAlert = {
  number: 101,
  created_at: "2026-01-15T10:00:00Z",
  html_url: "https://github.com/acme/repo/security/code-scanning/101",
  state: "open",
  rule: {
    id: "js/sql-injection",
    name: "SQL Injection",
    description: "Database query built from user-controlled input",
    security_severity_level: "critical",
    tags: ["security", "external/cwe/cwe-089"],
  },
  tool: {
    name: "CodeQL",
    version: "2.16.0",
  },
  most_recent_instance: {
    ref: "refs/heads/main",
    state: "open",
    message: { text: "Untrusted input in query" },
    location: {
      path: "src/server/db.ts",
      start_line: 42,
      end_line: 45,
    },
  },
};

const sampleDependabotAlert: GithubDependabotAlert = {
  number: 202,
  created_at: "2026-02-01T12:00:00Z",
  html_url: "https://github.com/acme/repo/security/dependabot/202",
  state: "open",
  dependency: {
    package: {
      ecosystem: "npm",
      name: "lodash",
    },
    manifest_path: "package.json",
  },
  security_advisory: {
    ghsa_id: "GHSA-p6mc-m468-83gw",
    cve_id: "CVE-2020-8203",
    summary: "Prototype Pollution in lodash",
    description: "lodash before 4.17.19 is vulnerable to prototype pollution",
    severity: "high",
    cvss: {
      score: 7.4,
      vector_string: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    },
    cwes: [{ cwe_id: "CWE-1321" }],
  },
  security_vulnerability: {
    vulnerable_version_range: "< 4.17.19",
    first_patched_version: { identifier: "4.17.19" },
  },
};

const sampleSecretScanningAlert: GithubSecretScanningAlert = {
  number: 303,
  created_at: "2026-03-01T08:30:00Z",
  html_url: "https://github.com/acme/repo/security/secret-scanning/303",
  state: "open",
  secret_type: "github_personal_access_token",
  secret_type_display_name: "GitHub Personal Access Token",
  validity: "active",
  locations: [
    {
      details: {
        path: ".env.example",
        start_line: 5,
        end_line: 5,
      },
    },
  ],
};

describe("GitHub alerts classification and mapping", () => {
  it("detects attack categories from CWE tags and rule ID keywords", () => {
    expect(detectCategoryFromRule("my-rule", ["cwe-89"])).toBe("sql-injection");
    expect(detectCategoryFromRule("my-rule", ["external/cwe/cwe-079"])).toBe("xss");
    expect(detectCategoryFromRule("my-rule", ["CWE-22"])).toBe("path-traversal");
    expect(detectCategoryFromRule("js/sql-injection-risk")).toBe("sql-injection");
    expect(detectCategoryFromRule("py/command-exec")).toBe("command-injection");
    expect(detectCategoryFromRule("ts/eval-code")).toBe("code-injection");
    expect(detectCategoryFromRule("net/ssrf-endpoint")).toBe("ssrf");
    expect(detectCategoryFromRule("crypto/weak-md5")).toBe("crypto-misuse");
    expect(detectCategoryFromRule("json/deserialization")).toBe("unsafe-deserialization");
    expect(detectCategoryFromRule("regex/dos")).toBe("regex-dos");
    expect(detectCategoryFromRule("object/prototype-pollution")).toBe("prototype-pollution");
    expect(detectCategoryFromRule("leak/secret-token")).toBe("information-disclosure");
    expect(detectCategoryFromRule("unknown-rule")).toBe("security-misconfiguration");
  });

  it("detects technical severity correctly", () => {
    expect(detectSeverityFromRule("critical")).toBe("critical");
    expect(detectSeverityFromRule("HIGH")).toBe("high");
    expect(detectSeverityFromRule("medium")).toBe("medium");
    expect(detectSeverityFromRule("low")).toBe("low");
    expect(detectSeverityFromRule(null, "error")).toBe("high");
    expect(detectSeverityFromRule(null, "warning")).toBe("medium");
    expect(detectSeverityFromRule(null, "note")).toBe("low");
    expect(detectSeverityFromRule(null, "none")).toBe("info");
    expect(detectSeverityFromRule(null, null)).toBe("medium");
  });

  it("detects Dependabot categories from CWE or defaults to known-vulnerable-package", () => {
    expect(detectCategoryFromAdvisory([{ cwe_id: "CWE-1321" }])).toBe("prototype-pollution");
    expect(detectCategoryFromAdvisory([{ cwe_id: "CWE-79" }])).toBe("xss");
    expect(detectCategoryFromAdvisory([])).toBe("known-vulnerable-package");
    expect(detectCategoryFromAdvisory(undefined)).toBe("known-vulnerable-package");
  });

  it("parses and validates alert kind options", () => {
    expect(parseAlertKinds("all")).toEqual(["code-scanning", "dependabot", "secret-scanning"]);
    expect(parseAlertKinds("")).toEqual(["code-scanning", "dependabot", "secret-scanning"]);
    expect(parseAlertKinds("code-scanning")).toEqual(["code-scanning"]);
    expect(parseAlertKinds("code-scanning,dependabot")).toEqual(["code-scanning", "dependabot"]);
    expect(() => parseAlertKinds("invalid-kind")).toThrow('Unknown alert kind "invalid-kind"');
  });
});

describe("fetchGithubAlerts", () => {
  it("rejects invalid repository format and unknown state", async () => {
    const deps: GithubAlertsDeps = { gh: vi.fn() };
    await expect(fetchGithubAlerts({ repo: "invalid" }, deps)).rejects.toThrow("Invalid repository name");
    await expect(fetchGithubAlerts({ repo: "o/r", state: "bogus" as never }, deps)).rejects.toThrow("Unknown alert state");
  });

  it("fetches all three alert types with correct query parameters", async () => {
    const calls: string[][] = [];
    const deps: GithubAlertsDeps = {
      gh: async args => {
        calls.push(args);
        if (args[1]?.includes("code-scanning")) return JSON.stringify([sampleCodeScanningAlert]);
        if (args[1]?.includes("dependabot")) return JSON.stringify([sampleDependabotAlert]);
        if (args[1]?.includes("secret-scanning")) return JSON.stringify([sampleSecretScanningAlert]);
        return "[]";
      },
    };

    const alerts = await fetchGithubAlerts({ repo: "acme/repo", state: "open" }, deps);
    expect(alerts.codeScanning).toHaveLength(1);
    expect(alerts.dependabot).toHaveLength(1);
    expect(alerts.secretScanning).toHaveLength(1);
    expect(alerts.warnings).toHaveLength(0);

    expect(calls.some(c => c[1]?.startsWith("repos/acme/repo/code-scanning/alerts?state=open"))).toBe(true);
    expect(calls.some(c => c[1]?.startsWith("repos/acme/repo/dependabot/alerts?state=open"))).toBe(true);
    expect(calls.some(c => c[1]?.startsWith("repos/acme/repo/secret-scanning/alerts?state=open"))).toBe(true);
  });

  it("handles pagination when multiple pages exist", async () => {
    const firstPage = Array.from({ length: 100 }, (_, i) => ({ ...sampleCodeScanningAlert, number: i + 1 }));
    const secondPage = [{ ...sampleCodeScanningAlert, number: 101 }];
    const calls: string[][] = [];
    const deps: GithubAlertsDeps = {
      gh: async args => {
        calls.push(args);
        if (args[1]?.includes("page=1&") || args[1]?.endsWith("page=1")) return JSON.stringify(firstPage);
        if (args[1]?.includes("page=2&") || args[1]?.endsWith("page=2")) return JSON.stringify(secondPage);
        return "[]";
      },
    };

    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["code-scanning"] }, deps);
    expect(alerts.codeScanning).toHaveLength(101);
    expect(calls.length).toBe(2);
  });

  it("records warnings when an alert type is disabled on the repo but other types succeed", async () => {
    const deps: GithubAlertsDeps = {
      gh: async args => {
        if (args[1]?.includes("secret-scanning")) throw new Error("Secret scanning is not enabled for this repository");
        if (args[1]?.includes("code-scanning")) return JSON.stringify([sampleCodeScanningAlert]);
        return "[]";
      },
    };

    const alerts = await fetchGithubAlerts({ repo: "acme/repo" }, deps);
    expect(alerts.codeScanning).toHaveLength(1);
    expect(alerts.secretScanning).toHaveLength(0);
    expect(alerts.warnings).toEqual([
      { stage: "secret-scanning", kind: "unavailable", message: "Secret scanning is not enabled for this repository" },
    ]);
  });

  it("throws authentication error immediately when gh requires login", async () => {
    const deps: GithubAlertsDeps = {
      gh: async () => {
        throw new Error("To re-authenticate, run: gh auth login");
      },
    };

    await expect(fetchGithubAlerts({ repo: "acme/repo" }, deps)).rejects.toThrow("GitHub authentication required");
  });
});

describe("prepareGithubAlertsImport & importGithubAlerts", () => {
  it("prepares valid report structure with stable digest and proper finding fields", () => {
    const alerts: FetchedGithubAlerts = {
      codeScanning: [sampleCodeScanningAlert],
      dependabot: [sampleDependabotAlert],
      secretScanning: [sampleSecretScanningAlert],
      warnings: [],
      failed: false,
      incomplete: false,
    };

    const prepared = prepareGithubAlertsImport("acme/repo", alerts, { state: "open" });
    expect(prepared.scanId).toMatch(/^ci-[a-f0-9]{64}$/);
    expect(prepared.provenance).toMatchObject({
      schemaVersion: 1,
      source: "github-alerts",
      trust: "unverified",
      repository: "acme/repo",
      digest: prepared.scanId.replace(/^ci-/, ""),
    });
    expect(prepared.findings).toHaveLength(3);

    const csFinding = prepared.findings.find(f => f.tool === "CodeQL")!;
    expect(csFinding.id.startsWith(prepared.scanId)).toBe(true);
    expect(csFinding.fingerprint?.startsWith(prepared.scanId)).toBe(true);
    expect(csFinding.category).toBe("sql-injection");
    expect(csFinding.severity).toBe("critical");
    expect(csFinding.reviewAnnotation).toEqual({ path: "src/server/db.ts", startLine: 42, endLine: 45 });
    expect(csFinding.evidence.analysis).toMatch(/Alert #101/i);

    const depFinding = prepared.findings.find(f => f.tool === "dependabot")!;
    expect(depFinding.category).toBe("prototype-pollution");
    expect(depFinding.severity).toBe("high");
    expect(depFinding.cvssScore).toBe(7.4);
    expect(depFinding.reviewAnnotation).toEqual({ path: "package.json", startLine: 1 });

    const secFinding = prepared.findings.find(f => f.tool === "secret-scanning")!;
    expect(secFinding.category).toBe("information-disclosure");
    expect(secFinding.severity).toBe("critical");
    expect(secFinding.reviewAnnotation).toEqual({ path: ".env.example", startLine: 5, endLine: 5 });
  });

  it("imports findings into SQLite database, logs audit event, and detects duplicate imports", async () => {
    const dbPath = createDb();
    const deps: GithubAlertsDeps = {
      gh: async args => {
        if (args[1]?.includes("code-scanning")) return JSON.stringify([sampleCodeScanningAlert]);
        if (args[1]?.includes("dependabot")) return JSON.stringify([sampleDependabotAlert]);
        if (args[1]?.includes("secret-scanning")) return JSON.stringify([sampleSecretScanningAlert]);
        return "[]";
      },
    };

    const first = await importGithubAlerts({ repo: "acme/repo", dbPath }, deps);
    expect(first.findings).toBe(3);
    expect(first.alreadyImported).toBe(false);

    // Verify stored findings in database
    const db = new osecDB(dbPath);
    try {
      const stored = db.getFindings(first.scanId);
      expect(stored).toHaveLength(3);
      expect(stored.map(s => s.tool)).toEqual(expect.arrayContaining(["CodeQL", "dependabot", "secret-scanning"]));
    } finally {
      db.close();
    }

    // Verify audit log
    const auditEvents = listAudit({}, { dbPath }).events;
    const importAudit = auditEvents.find(e => e.action === "findings.import.github");
    expect(importAudit).toBeDefined();
    expect(importAudit?.subject).toBe("acme/repo");
    expect(importAudit?.detail?.count).toBe(3);

    // Re-importing the same alerts
    const second = await importGithubAlerts({ repo: "acme/repo", dbPath }, deps);
    expect(second.alreadyImported).toBe(true);
    expect(second.scanId).toBe(first.scanId);
  });
});

describe("0 findings import CLI command", () => {
  function makeDeps(overrides: Partial<FindingsImportDeps> = {}): {
    deps: FindingsImportDeps;
    outLines: string[];
    errLines: string[];
  } {
    const outLines: string[] = [];
    const errLines: string[] = [];
    const deps: FindingsImportDeps = {
      out: text => outLines.push(text),
      err: text => errLines.push(text),
      readInput: () => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "test-tool" } }, results: [] }] }),
      gh: async args => {
        if (args[1]?.includes("code-scanning")) return JSON.stringify([sampleCodeScanningAlert]);
        return "[]";
      },
      ...overrides,
    };
    return { deps, outLines, errLines };
  }

  it("throws UsageError when neither file nor --github is passed", async () => {
    const program = new Command();
    const { deps, errLines } = makeDeps();
    registerFindingsImportCommand(program, deps);

    await program.parseAsync(["node", "test", "import"]);
    expect(errLines.join("\n")).toContain("Provide a SARIF file or specify --github <owner/repo>");
  });

  it("throws UsageError when both file and --github are passed", async () => {
    const program = new Command();
    const { deps, errLines } = makeDeps();
    registerFindingsImportCommand(program, deps);

    await program.parseAsync(["node", "test", "import", "scan.sarif", "--github", "acme/repo"]);
    expect(errLines.join("\n")).toContain("Cannot combine SARIF file with --github");
  });

  it("imports GitHub alerts via --github and outputs text summary", async () => {
    const dbPath = createDb();
    const program = new Command();
    const { deps, outLines } = makeDeps();
    registerFindingsImportCommand(program, deps);

    await program.parseAsync(["node", "test", "import", "--github", "acme/repo", "--db-path", dbPath]);
    expect(outLines.join("\n")).toMatch(/Imported 1 finding \(ci-[a-f0-9]+…\)\./);
  });

  it("outputs JSON with --format json", async () => {
    const dbPath = createDb();
    const program = new Command();
    const { deps, outLines } = makeDeps();
    registerFindingsImportCommand(program, deps);

    await program.parseAsync(["node", "test", "import", "--github", "acme/repo", "--db-path", dbPath, "--format", "json"]);
    const json = JSON.parse(outLines[0]!);
    expect(json).toMatchObject({
      findings: 1,
      alreadyImported: false,
      dbPath,
    });
    expect(json.scanId).toMatch(/^ci-[a-f0-9]{64}$/);
  });
});

describe("partial fetches are reported, not hidden", () => {
  const full = (n: number) => Array.from({ length: 100 }, (_, i) => ({ ...sampleCodeScanningAlert, number: n * 1000 + i }));

  it("flags a failure on page 2 as failed and incomplete, keeping page 1", async () => {
    const deps: GithubAlertsDeps = {
      gh: async args => {
        if (args[1]?.includes("page=2")) throw new Error("HTTP 502 bad gateway");
        return JSON.stringify(full(1));
      },
    };
    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["code-scanning"] }, deps);
    expect(alerts.codeScanning).toHaveLength(100);
    expect(alerts.failed).toBe(true);
    expect(alerts.incomplete).toBe(true);
    expect(alerts.warnings[0]).toMatchObject({ stage: "code-scanning", kind: "failed" });
    expect(alerts.warnings[0]!.message).toMatch(/page 2.*incomplete/);
  });

  it("flags bad JSON on a later page", async () => {
    const deps: GithubAlertsDeps = { gh: async args => args[1]?.includes("page=2") ? "<html>" : JSON.stringify(full(1)) };
    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["code-scanning"] }, deps);
    expect(alerts.failed).toBe(true);
    expect(alerts.warnings[0]!.message).toMatch(/not valid JSON/);
  });

  it("flags hitting the page cap as truncated and incomplete", async () => {
    let calls = 0;
    const deps: GithubAlertsDeps = { gh: async () => { calls++; return JSON.stringify(full(calls)); } };
    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["code-scanning"] }, deps);
    expect(calls).toBe(20);
    expect(alerts.incomplete).toBe(true);
    expect(alerts.failed).toBe(false);
    expect(alerts.warnings[0]).toMatchObject({ kind: "truncated" });
  });

  it("records the partial import as not complete, under its own identity", () => {
    const base = { codeScanning: [sampleCodeScanningAlert], dependabot: [], secretScanning: [], warnings: [] };
    const complete = prepareGithubAlertsImport("acme/repo", { ...base, failed: false, incomplete: false });
    const partial = prepareGithubAlertsImport("acme/repo", {
      ...base, failed: true, incomplete: true,
      warnings: [{ stage: "code-scanning", kind: "failed", message: "page 2 failed" }],
    });
    expect(partial.scanId).not.toBe(complete.scanId);
    expect(partial.provenance).toMatchObject({ complete: false });
    expect(partial.summary).toMatchObject({ executionSuccessful: false, exitReason: "partial-fetch" });
    expect(complete.provenance).toMatchObject({ complete: true });
  });

  it("CLI prints the warning on stderr, says INCOMPLETE and exits non-zero on a failed fetch", async () => {
    const saved = process.exitCode;
    try {
      process.exitCode = undefined;
      const errLines: string[] = [];
      const outLines: string[] = [];
      const program = new Command();
      registerFindingsImportCommand(program, {
        out: t => outLines.push(t), err: t => errLines.push(t), readInput: () => "",
        gh: async args => {
          if (args[1]?.includes("page=2")) throw new Error("HTTP 502");
          return JSON.stringify(full(1));
        },
      });
      await program.parseAsync(["node", "test", "import", "--github", "acme/repo", "--types", "code-scanning", "--db-path", createDb()]);
      expect(errLines.join("\n")).toMatch(/warning: GitHub code-scanning: page 2 failed/);
      expect(outLines.join("\n")).toContain("INCOMPLETE");
      expect(process.exitCode).toBe(1);
    } finally {
      process.exitCode = saved;
    }
  });
});

describe("idempotency covers alert content", () => {
  it("a changed alert (text, updated_at) gets a new digest; an identical one keeps it", () => {
    const wrap = (a: GithubSecretScanningAlert): FetchedGithubAlerts => ({ codeScanning: [], dependabot: [], secretScanning: [a], warnings: [], failed: false, incomplete: false });
    const a = prepareGithubAlertsImport("acme/repo", wrap(sampleSecretScanningAlert));
    const same = prepareGithubAlertsImport("acme/repo", wrap({ ...sampleSecretScanningAlert }));
    const updated = prepareGithubAlertsImport("acme/repo", wrap({ ...sampleSecretScanningAlert, updated_at: "2026-04-01T00:00:00Z" }));
    expect(same.scanId).toBe(a.scanId);
    expect(updated.scanId).not.toBe(a.scanId);

    const cs = (text: string): FetchedGithubAlerts => ({
      codeScanning: [{ ...sampleCodeScanningAlert, most_recent_instance: { ...sampleCodeScanningAlert.most_recent_instance, message: { text } } }],
      dependabot: [], secretScanning: [], warnings: [], failed: false, incomplete: false,
    });
    expect(prepareGithubAlertsImport("acme/repo", cs("one")).scanId).not.toBe(prepareGithubAlertsImport("acme/repo", cs("two")).scanId);
  });
});

describe("secret scanning locations", () => {
  const SECRET = "ghp_SUPERSECRETVALUE1234567890";
  const listDeps = (calls: string[][], locations: (n: number) => string): GithubAlertsDeps => ({
    gh: async args => {
      calls.push(args);
      const endpoint = args[1] ?? "";
      const m = endpoint.match(/alerts\/(\d+)\/locations/);
      if (m) return locations(Number(m[1]));
      // A raw gh would return the secret; the fake ignores --jq to prove the code never keeps it.
      return JSON.stringify([{ ...sampleSecretScanningAlert, secret: SECRET, locations_url: "https://evil.example/x" }]);
    },
  });

  it("fetches the first location, drops the secret, and builds the URL itself", async () => {
    const calls: string[][] = [];
    const deps = listDeps(calls, () => JSON.stringify([{ type: "commit", details: { path: "config/.env", start_line: 7, end_line: 7, blob_sha: "x" } }, { details: { path: "other" } }]));
    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["secret-scanning"] }, deps);
    expect(JSON.stringify(alerts)).not.toContain(SECRET);
    expect(alerts.secretScanning[0]!.locations).toEqual([{ details: { path: "config/.env", start_line: 7, end_line: 7 } }]);
    const locationCall = calls.find(c => c[1]?.includes("/locations"))!;
    expect(locationCall[1]).toBe("repos/acme/repo/secret-scanning/alerts/303/locations?per_page=1");
    expect(calls.some(c => c.join(" ").includes("evil.example"))).toBe(false);
    for (const c of calls) expect(c).toContain("--jq");
    const prepared = prepareGithubAlertsImport("acme/repo", alerts);
    expect(prepared.findings[0]!.reviewAnnotation).toEqual({ path: "config/.env", startLine: 7, endLine: 7 });
    expect(JSON.stringify(prepared)).not.toContain(SECRET);
  });

  it("degrades to a warning when a lookup fails", async () => {
    const deps = listDeps([], () => { throw new Error("HTTP 403"); });
    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["secret-scanning"] }, deps);
    expect(alerts.secretScanning).toHaveLength(1);
    expect(alerts.secretScanning[0]!.locations).toBeUndefined();
    expect(alerts.warnings).toEqual([expect.objectContaining({ kind: "locations", message: expect.stringContaining("1 location lookup failed") })]);
    expect(alerts.incomplete).toBe(false);
  });

  it("looks up at most the first 50 alerts", async () => {
    const calls: string[][] = [];
    const many = Array.from({ length: 60 }, (_, i) => ({ ...sampleSecretScanningAlert, number: i + 1 }));
    const deps: GithubAlertsDeps = {
      gh: async args => { calls.push(args); return args[1]?.includes("/locations") ? "[]" : JSON.stringify(many); },
    };
    const alerts = await fetchGithubAlerts({ repo: "acme/repo", types: ["secret-scanning"] }, deps);
    expect(calls.filter(c => c[1]?.includes("/locations"))).toHaveLength(50);
    expect(alerts.warnings[0]!.message).toContain("10 alerts beyond the first 50");
  });
});

describe("alert text is bounded and stripped of control characters", () => {
  it("cleans title, description and evidence", () => {
    const evil = `bad\u001b[31mred\u0000‮text\n${"x".repeat(5000)}`;
    const alerts: FetchedGithubAlerts = {
      codeScanning: [{
        ...sampleCodeScanningAlert,
        rule: { ...sampleCodeScanningAlert.rule, description: evil },
        most_recent_instance: { ...sampleCodeScanningAlert.most_recent_instance, message: { text: evil } },
      }],
      dependabot: [{ ...sampleDependabotAlert, security_advisory: { ...sampleDependabotAlert.security_advisory, summary: evil, description: evil } }],
      secretScanning: [], warnings: [], failed: false, incomplete: false,
    };
    const findings = prepareGithubAlertsImport("acme/repo", alerts).findings;
    for (const f of findings) {
      for (const text of [f.title, f.description, f.evidence.response ?? "", f.evidence.request ?? "", f.evidence.analysis ?? ""]) {
        expect(text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f‮]/);
      }
      expect(f.title.length).toBeLessThanOrEqual(200);
      expect(f.title).not.toContain("\n");
      expect(f.description.length).toBeLessThanOrEqual(2000);
      expect((f.evidence.response ?? "").length).toBeLessThanOrEqual(1000);
    }
    expect(findings[0]!.description).toContain("[31mred");
  });
});
