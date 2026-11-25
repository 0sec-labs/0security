import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { locationLabel, looksLikeNucleiJsonl, looksLikeSarif, MAX_SARIF_RESULTS, parseNucleiJsonl, parseSarif, parseScannerOutput, redactEvidence, repoRelativePath } from "./sarif-import.js";

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

  it("retains findings with rejected, empty, or malformed suppressions while filtering accepted and underReview ones", () => {
    const parsed = parseSarif(log([
      { ruleId: "r-rejected", level: "error", message: { text: "keep 1" }, suppressions: [{ kind: "inSource", status: "rejected" }] },
      { ruleId: "r-accepted", level: "error", message: { text: "drop 1" }, suppressions: [{ kind: "inSource", status: "accepted" }] },
      { ruleId: "r-omitted", level: "error", message: { text: "drop 2" }, suppressions: [{ kind: "inSource" }] },
      { ruleId: "r-review", level: "error", message: { text: "drop 3" }, suppressions: [{ kind: "external", status: "underReview" }] },
      { ruleId: "r-multi-rejected", level: "warning", message: { text: "keep 2" }, suppressions: [{ kind: "inSource", status: "rejected" }, { kind: "external", status: "rejected" }] },
      { ruleId: "r-mixed", level: "error", message: { text: "drop 4" }, suppressions: [{ kind: "inSource", status: "rejected" }, { kind: "external", status: "accepted" }] },
      { ruleId: "r-malformed-str", level: "error", message: { text: "keep 3" }, suppressions: ["bad"] },
      { ruleId: "r-malformed-status", level: "note", message: { text: "keep 4" }, suppressions: [null, { status: 123 }] },
      { ruleId: "r-empty", level: "error", message: { text: "keep 5" }, suppressions: [] },
    ]));
    expect(parsed.findings.map(f => ({ ruleId: f.ruleId, severity: f.severity, title: f.title }))).toEqual([
      { ruleId: "r-rejected", severity: "high", title: "keep 1" },
      { ruleId: "r-multi-rejected", severity: "medium", title: "keep 2" },
      { ruleId: "r-malformed-str", severity: "high", title: "keep 3" },
      { ruleId: "r-malformed-status", severity: "low", title: "keep 4" },
      { ruleId: "r-empty", severity: "high", title: "keep 5" },
    ]);
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

  it("resolves rule metadata from nested rule.index, rule.id, and legacy ruleIndex", () => {
    const rules = [
      { id: "SEC-001", shortDescription: { text: "Hardcoded Secret" }, properties: { "security-severity": "9.1", tags: ["external/cwe/cwe-798"] } },
      { id: "SEC-002", shortDescription: { text: "Weak Hash" }, properties: { "security-severity": "5.0", tags: ["external/cwe/cwe-328"] } },
    ];
    const parsed = parseSarif(JSON.stringify({
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "TestScanner", rules } },
        results: [
          { rule: { index: 0 }, message: { text: "Found secret" }, locations: [at("config.ts", 12)] },
          { rule: { index: 1 }, message: { text: "Found md5" }, locations: [at("hash.ts", 4)] },
          { rule: { id: "SEC-002" }, message: { text: "By rule.id" } },
          { ruleIndex: 1, message: { text: "By legacy ruleIndex" } },
        ],
      }],
    }));
    expect(parsed.findings[0]).toMatchObject({ ruleId: "SEC-001", title: "Hardcoded Secret", severity: "critical", cwe: ["CWE-798"], path: "config.ts", startLine: 12 });
    expect(parsed.findings[1]).toMatchObject({ ruleId: "SEC-002", title: "Weak Hash", severity: "medium", cwe: ["CWE-328"], path: "hash.ts", startLine: 4 });
    expect(parsed.findings[2]).toMatchObject({ ruleId: "SEC-002", title: "Weak Hash", severity: "medium", cwe: ["CWE-328"] });
    expect(parsed.findings[3]).toMatchObject({ ruleId: "SEC-002", title: "Weak Hash", severity: "medium", cwe: ["CWE-328"] });
  });

  it("ignores invalid or out-of-range rule indices without resolving an unrelated rule", () => {
    const rules = [{ id: "SEC-001", shortDescription: { text: "Hardcoded Secret" }, properties: { "security-severity": "9.1", tags: ["CWE-798"] } }];
    for (const bad of [{ rule: { index: -1 } }, { rule: { index: 0.5 } }, { rule: { index: 99 } }, { rule: { index: "0" } }, { rule: {} }, { ruleIndex: -1 }, { rule: { index: 99 }, ruleIndex: 0 }]) {
      const finding = parseSarif(log([{ ...bad, message: { text: "Unknown issue" } }], rules)).findings[0]!;
      expect(finding).toMatchObject({ ruleId: "unknown-rule", title: "Unknown issue", severity: "medium", cwe: [] });
    }
    const emptyRules = parseSarif(log([{ rule: { index: 0 }, message: { text: "No rules" } }], [])).findings[0]!;
    expect(emptyRules).toMatchObject({ ruleId: "unknown-rule", title: "No rules", severity: "medium", cwe: [] });
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

  it("handles a leading UTF-8 BOM in SARIF without changing non-BOM or malformed behavior", () => {
    const sarif = read("nuclei.sarif");
    const withBom = `\uFEFF${sarif}`;
    expect(looksLikeSarif(withBom)).toBe(true);
    expect(parseSarif(withBom)).toEqual(parseSarif(sarif));
    expect(() => parseSarif("\uFEFF{bad")).toThrow("not valid JSON");
    expect(looksLikeSarif("\uFEFF{bad")).toBe(false);
  });

  it("handles a leading UTF-8 BOM in Nuclei JSON Lines without dropping the first record", () => {
    const first = read("nuclei.jsonl").trim();
    const second = JSON.stringify({ "template-id": "cve-2021-44228", info: { name: "Log4Shell", severity: "critical" }, "matched-at": "http://127.0.0.1:18089/login" });
    const withBom = `\uFEFF${first}\n\n{malformed\n${second}\n`;
    expect(looksLikeNucleiJsonl(withBom)).toBe(true);
    const parsed = parseNucleiJsonl(withBom);
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings.map(f => f.ruleId)).toEqual(["local-admin-panel-exposed", "cve-2021-44228"]);
    expect(parseScannerOutput(`\uFEFF${first}\n`).findings).toHaveLength(1);
    expect(() => parseNucleiJsonl("\uFEFF\n")).toThrow("empty");
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
    describe("credentials in imported text", () => {
      // Built at run time from fragments, so no secret-shaped literal sits in the repository.
      const pw = ["hun", "ter", "2"].join("");
      const tok = ["ab", "Cd", "12", "Ef", "34", "Gh", "56", "Ij", "78", "Kl", "90", "Mn", "op", "Qr"].join("");
      const bearer = ["be", "ar", "er", "-", "val"].join("");
      const sid = ["sess", "ion", "-", "val"].join("");
      const all = (text: string) => { for (const secret of [pw, tok, bearer, sid]) expect(text).not.toContain(secret); };
      const mixed = `http://bob:${pw}@h.test/p?token=${bearer}&keep=1&blob=${tok}&api_key=${sid}#frag Authorization: Bearer ${bearer}\nCookie: sid=${sid}\nSet-Cookie: s=${sid}\nX-API-Key: ${tok}`;
      it("removes them from every field of a SARIF result, for any tool", () => {
        const item = hostile({ message: { text: `Found at ${mixed}` }, locations: [{ physicalLocation: { artifactLocation: { uri: `https://u:${pw}@h.test/x?password=${pw}&q=1` }, region: { startLine: 3, snippet: { text: mixed } } } }], properties: { evidence: mixed } });
        all(JSON.stringify(item));
        expect(item.endpoint).toBe("https://h.test/x?password=REDACTED&q=1");
        expect(item.snippet).toContain("keep=1");
      });
      it("removes them from the rule text, the Strix endpoint and the proof text", () => {
        const parsed = parseSarif(log([{ ruleId: "r", message: { text: "m" }, locations: [{ logicalLocations: [{ fullyQualifiedName: `/api/x?auth=${bearer}&page=2`, kind: "endpoint" }] }], properties: { strix: { poc: { description: mixed } } } }], [{ id: "r", shortDescription: { text: `t ${mixed}` }, help: { text: mixed } }]));
        all(JSON.stringify(parsed.findings));
        expect(parsed.findings[0]!.endpoint).toBe("/api/x?auth=REDACTED&page=2");
      });
      it("removes them from Nuclei JSON Lines: matched URL, name, description, request and extracted values", () => {
        const line = JSON.stringify({ "template-id": "t", info: { name: `n ${mixed}`, description: mixed, remediation: mixed, severity: "low" }, "matched-at": `http://bob:${pw}@h.test/x?token=${bearer}&z=1`, request: "GET /x HTTP/1.1", response: `HTTP/1.1 200 OK\r\nSet-Cookie: s=${sid}`, "curl-command": `curl -u '${["bo", "b"].join("")}:${pw}' -H 'Authorization: Bearer ${bearer}' '${`http://h.test/x?sig=${tok}`}'`, "extracted-results": [mixed] });
        const found = parseNucleiJsonl(line).findings[0]!;
        all(JSON.stringify(found));
        expect(found.endpoint).toBe("http://h.test/x?token=REDACTED&z=1");
      });
      it("removes a secret query value from a route joined to the Strix target", () => {
        const parsed = parseSarif(log([{ ruleId: "r", message: { text: "m" }, properties: { strix: { target: "http://h.test", endpoint: `/api/x?token=${bearer}&page=2` } } }]));
        expect(parsed.findings[0]!.endpoint).toBe("http://h.test/api/x?token=REDACTED&page=2");
      });
      it("removes pass, passwd and user_pass values", () => {
        const text = redactEvidence(`http://h.test/a?pass=${pw}&passwd=${pw}&user_pass=${pw}&page=2`);
        expect(text).not.toContain(pw);
        expect(text).toContain("page=2");
      });
      it("keeps harmless query values and short ids", () => {
        expect(redactEvidence("GET http://h.test/a?page=2&sort=name&id=17")).toBe("GET http://h.test/a?page=2&sort=name&id=17");
      });
    });
    it("stops at the result limit", () => {
      const lines = Array.from({ length: MAX_SARIF_RESULTS + 1 }, (_, i) => JSON.stringify({ "template-id": `t${i}`, info: { name: "n", severity: "low" } })).join("\n");
      expect(() => parseNucleiJsonl(lines)).toThrow(/more than/);
    });
  });
});
