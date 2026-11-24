import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { locationLabel, looksLikeNucleiJsonl, looksLikeSarif, MAX_SARIF_RESULTS, parseNucleiJsonl, parseSarif, parseScannerOutput, repoRelativePath } from "./sarif-import.js";

const log = (results: unknown[], rules: unknown[] = [], extra: Record<string, unknown> = {}) => JSON.stringify({
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "CodeQL", semanticVersion: "2.20.1", rules } }, results, ...extra }],
});
const at = (uri: string, startLine = 12, endLine?: number) => ({ physicalLocation: { artifactLocation: { uri }, region: { startLine, ...(endLine ? { endLine } : {}), snippet: { text: "db.query(sql)" } } } });

describe("parseSarif", () => {
  it("reads tool, rule, severity, message, location and CWE", () => {
    const parsed = parseSarif(log(
      [{ ruleId: "js/sql-injection", level: "error", message: { text: "Query built from user input." }, locations: [at("src/db.ts", 12, 14)], partialFingerprints: { primaryLocationLineHash: "abc:1" } }],
      [{ id: "js/sql-injection", shortDescription: { text: "SQL injection" }, properties: { tags: ["security", "external/cwe/cwe-089"], "security-severity": "8.8" } }],
    ));
    expect(parsed.tools).toEqual(["CodeQL"]);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]).toMatchObject({ tool: "CodeQL", toolVersion: "2.20.1", ruleId: "js/sql-injection", title: "SQL injection", severity: "high", category: "sql-injection", path: "src/db.ts", startLine: 12, endLine: 14, snippet: "db.query(sql)", cwe: ["CWE-89"] });
    expect(parsed.findings[0]!.fingerprint).toMatch(/^sarif:[0-9a-f]{24}$/);
  });

  it("gives the same fingerprint on a second run and a different one for another place", () => {
    const run = (line: number, hash: string) => parseSarif(log([{ ruleId: "r", message: { text: "m" }, locations: [at("a.ts", line)], partialFingerprints: { primaryLocationLineHash: hash } }])).findings[0]!.fingerprint;
    expect(run(10, "h1")).toBe(run(40, "h1"));
    expect(run(10, "h1")).not.toBe(run(10, "h2"));
  });

  it("maps levels when there is no security severity, and skips suppressed results", () => {
    const parsed = parseSarif(log([
      { ruleId: "a", level: "warning", message: { text: "w" } },
      { ruleId: "b", level: "note", message: { text: "n" } },
      { ruleId: "c", level: "error", message: { text: "gone" }, suppressions: [{ kind: "inSource" }] },
    ]));
    expect(parsed.findings.map(f => [f.ruleId, f.severity])).toEqual([["a", "medium"], ["b", "low"]]);
  });

  it("lets --tool override the label", () => {
    expect(parseSarif(log([{ ruleId: "r", message: { text: "m" } }]), { tool: "ci-sast" }).findings[0]!.tool).toBe("ci-sast");
  });

  it("keeps locations inside the repository and strips control characters", () => {
    const parsed = parseSarif(log([
      { ruleId: "r1", message: { text: "bell\u0007 here" }, locations: [at("../../etc/passwd")] },
      { ruleId: "r2", message: { text: "m" }, locations: [at("file:///work/x")] },
      { ruleId: "r3", message: { text: "m" }, locations: [at("./pkg/a%20b.ts")] },
    ]));
    expect(parsed.findings[0]).toMatchObject({ description: "bell here" });
    expect(parsed.findings[0]!.path).toBeUndefined();
    expect(parsed.findings[1]!.path).toBeUndefined();
    expect(parsed.findings[2]!.path).toBe("pkg/a b.ts");
  });

  it("refuses non-SARIF, other versions and oversized logs", () => {
    expect(() => parseSarif("not json")).toThrow("valid JSON");
    expect(() => parseSarif(JSON.stringify({ target: "x", findings: [] }))).toThrow("not a SARIF log");
    expect(() => parseSarif(JSON.stringify({ version: "1.0.0", runs: [] }))).toThrow("Unsupported SARIF version");
    expect(() => parseSarif(log(Array.from({ length: 5001 }, () => ({ ruleId: "r", message: { text: "m" } }))))).toThrow("more than 5000");
  });

  it("detects SARIF without parsing 0's own reports as SARIF", () => {
    expect(looksLikeSarif(log([]))).toBe(true);
    expect(looksLikeSarif(JSON.stringify({ findings: [], target: "x" }))).toBe(false);
  });

  it("makes absolute paths relative to the scanned folder, and drops other absolute paths", () => {
    const text = log([{ ruleId: "r", message: { text: "m" }, locations: [at("file:///work/app/src/a.ts", 3)] }, { ruleId: "r", message: { text: "m" }, locations: [at("file:///elsewhere/b.ts", 3)] }]);
    const parsed = parseSarif(text, { roots: ["/work/app"] }).findings;
    expect(parsed[0]!.path).toBe("src/a.ts");
    expect(parsed[1]!.path).toBeUndefined();
    expect(parseSarif(text).findings[0]!.path).toBeUndefined();
  });

  it("repoRelativePath rejects escapes and absolute paths", () => {
    expect(repoRelativePath("a/../b")).toBeUndefined();
    expect(repoRelativePath("/abs/x")).toBeUndefined();
    expect(repoRelativePath("C:\\x\\y")).toBeUndefined();
    expect(repoRelativePath("src\\a.ts")).toBe("src/a.ts");
  });
});

describe("dynamic scanner output", () => {
  const read = (name: string) => readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), "utf8");

  it("reads Strix SARIF: web findings keep method and URL, the placeholder file is dropped, coverage entries are not findings", () => {
    const parsed = parseSarif(read("strix.sarif"));
    expect(parsed.tools).toEqual(["Strix"]);
    expect(parsed.findings).toHaveLength(2);
    const xss = parsed.findings.find(f => f.ruleId === "CWE-79")!;
    expect(xss).toMatchObject({ severity: "high", category: "xss", endpoint: "http://127.0.0.1:18089/search", method: "GET", cwe: ["CWE-79"] });
    expect(xss.path).toBeUndefined();
    expect(xss.evidence).toContain("returns the script tag unescaped");
    expect(xss.evidence).not.toContain("curl");
    const admin = parsed.findings.find(f => f.ruleId === "CWE-306")!;
    expect(admin).toMatchObject({ severity: "critical", endpoint: "http://127.0.0.1:18089/admin" });
    expect(locationLabel(admin)).toBe("GET http://127.0.0.1:18089/admin");
    expect(parsed.findings.some(f => f.ruleId.startsWith("strix-coverage"))).toBe(false);
  });

  it("reads ZAP SARIF: URL and method from the request, CWE from tags, credentials removed", () => {
    const parsed = parseSarif(read("zap.sarif"));
    expect(parsed.tools).toEqual(["ZAP"]);
    expect(parsed.findings).toHaveLength(2);
    const csp = parsed.findings[0]!;
    expect(csp).toMatchObject({ ruleId: "10038-1", severity: "medium", endpoint: "http://127.0.0.1:18089/", method: "GET", cwe: ["CWE-693"] });
    const xss = parsed.findings[1]!;
    expect(xss).toMatchObject({ severity: "high", method: "GET", cwe: ["CWE-79"], evidence: "<script>alert(1)</script>" });
    expect(xss.endpoint).toContain("127.0.0.1:18089/search?q=");
    expect(xss.endpoint).not.toContain("secret");
    expect(xss.path).toBeUndefined();
  });

  it("reads Nuclei SARIF as it is written: rule, severity from the score, host only", () => {
    const parsed = parseSarif(read("nuclei.sarif"));
    expect(parsed.tools).toEqual(["Nuclei"]);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]).toMatchObject({ ruleId: "local-admin-panel-exposed", severity: "medium", toolVersion: "v3.11.1" });
    expect(parsed.findings[0]!.path).toBeUndefined();
  });

  it("reads Nuclei JSON Lines: matched URL, method, CWE, severity and a request as evidence", () => {
    const text = read("nuclei.jsonl");
    expect(looksLikeNucleiJsonl(text)).toBe(true);
    const parsed = parseScannerOutput(text);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]).toMatchObject({ tool: "Nuclei", ruleId: "local-admin-panel-exposed", title: "Admin panel exposed without login", severity: "medium", endpoint: "http://127.0.0.1:18089/admin", method: "GET", cwe: ["CWE-306"] });
    expect(parsed.findings[0]!.evidence).toContain("Response status: 200");
    expect(parsed.findings[0]!.evidence).toContain("curl -X 'GET'");
  });

  it("does not treat SARIF as Nuclei JSON Lines", () => {
    expect(looksLikeNucleiJsonl(read("zap.sarif"))).toBe(false);
  });

  describe("hostile input", () => {
    const hostile = (result: Record<string, unknown>) => parseSarif(log([{ ruleId: "r", message: { text: "m" }, ...result }])).findings[0]!;
    it("never turns a URL, absolute path or traversal into a repo path", () => {
      for (const uri of ["http://evil.test/a", "file:///etc/passwd", "/etc/passwd", "../../etc/passwd", "a/../../b", "C:\\Windows\\win.ini", "javascript:alert(1)"]) {
        expect(hostile({ locations: [at(uri)] }).path).toBeUndefined();
      }
    });
    it("keeps only http and https URLs as endpoints", () => {
      expect(hostile({ locations: [at("javascript:alert(1)")] }).endpoint).toBeUndefined();
      expect(hostile({ locations: [at("ftp://host/x")] }).endpoint).toBeUndefined();
      expect(hostile({ webRequest: { target: "file:///etc/passwd", method: "GET" } }).endpoint).toBeUndefined();
      expect(hostile({ locations: [at("https://h.test/x#frag")] }).endpoint).toBe("https://h.test/x");
    });
    it("rejects an odd method and a route with traversal", () => {
      expect(hostile({ webRequest: { target: "http://h.test/", method: "GET; rm -rf" } }).method).toBeUndefined();
      const logical = { locations: [{ logicalLocations: [{ fullyQualifiedName: "/a/../../etc", kind: "endpoint" }] }] };
      expect(hostile(logical).endpoint).toBeUndefined();
    });
    it("strips control characters and limits huge fields", () => {
      const item = hostile({ message: { text: `bad\u0000\u001b[31m${"x".repeat(50000)}` }, properties: { evidence: `e\u0007${"y".repeat(50000)}` }, locations: [at(`http://h.test/${"a".repeat(5000)}`)] });
      expect(item.description).not.toMatch(/[\u0000-\u0008\u000e-\u001f]/);
      expect(item.description.length).toBeLessThanOrEqual(6000);
      expect(item.evidence!.length).toBeLessThanOrEqual(3000);
      expect(item.evidence).not.toContain("\u0007");
      expect(item.endpoint).toBeUndefined();
    });
    it("applies the same limits to Nuclei JSON Lines", () => {
      const line = JSON.stringify({ "template-id": "t\u0000x", info: { name: "n".repeat(9000), severity: "CRITICAL", description: "d\u001b".repeat(9000), classification: { "cwe-id": ["cwe-79", "../../x"] } }, "matched-at": "javascript:alert(1)", request: "G\u0000ET / HTTP/1.1", "curl-command": "c".repeat(9000) });
      const item = parseNucleiJsonl(`${line}\nnot json\n[1,2]\n`).findings;
      expect(item).toHaveLength(1);
      expect(item[0]!.title.length).toBeLessThanOrEqual(300);
      expect(item[0]!.ruleId).toBe("tx");
      expect(item[0]!.severity).toBe("critical");
      expect(item[0]!.endpoint).toBeUndefined();
      expect(item[0]!.method).toBeUndefined();
      expect(item[0]!.description.length).toBeLessThanOrEqual(3010);
      expect(item[0]!.evidence!.length).toBeLessThanOrEqual(3000);
      expect(item[0]!.cwe).toEqual(["CWE-79"]);
    });
    it("skips a huge run of empty lines and an over-long line without building a line array", () => {
      const valid = JSON.stringify({ "template-id": "t", info: { name: "n", severity: "low" } });
      const text = `${valid}\n${"\n".repeat(5_000_000)}${"x".repeat(600 * 1024)}\n${valid}x\n`;
      expect(parseNucleiJsonl(text).findings).toHaveLength(1);
    });
    it("takes credentials out of evidence text", () => {
      const line = JSON.stringify({ "template-id": "t", info: { name: "n", severity: "low" }, "matched-at": "http://h.test/x", request: "GET /x HTTP/1.1", "curl-command": "curl -X 'GET' -u 'admin:hunter2' -H 'Authorization: Bearer abc.def' -H 'Cookie: sid=1' -H 'Accept: */*' 'http://bob:pw@h.test/x'", "extracted-results": ["https://u:p@h.test/y"] });
      const evidence = parseNucleiJsonl(line).findings[0]!.evidence!;
      for (const secret of ["hunter2", "abc.def", "sid=1", "bob", ":pw@", "u:p@"]) expect(evidence).not.toContain(secret);
      expect(evidence).toContain("Accept");
      const sarif = hostile({ properties: { evidence: "GET http://a:b@h.test/ Authorization: Bearer zzz" } }).evidence!;
      expect(sarif).not.toContain("zzz");
      expect(sarif).not.toContain("a:b@");
    });
    it("stops at the result limit", () => {
      const lines = Array.from({ length: MAX_SARIF_RESULTS + 1 }, (_, i) => JSON.stringify({ "template-id": `t${i}`, info: { name: "n", severity: "low" } })).join("\n");
      expect(() => parseNucleiJsonl(lines)).toThrow(/more than/);
    });
  });
});
