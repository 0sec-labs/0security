import { describe, expect, it } from "vitest";
import type { Finding, ScanReport } from "@0/engine/shared";
import { parseBusinessContext } from "./business-context.js";
import { scanJson, toScanReport, scanExitCode, type ScanOutcome } from "./scan-report.js";
import { exportReport } from "@0/engine";
import { selectCandidates } from "./commands/burndown.js";
import { normalizeFinding } from "./web/dashboard-summaries.js";

const finding = (id: string, severity: Finding["severity"], path: string): Finding => ({ id, templateId: "t", title: id, description: "description", severity, category: "xss", status: "discovered", evidence: { request: "req", response: "res" }, timestamp: 1, reviewAnnotation: { path, startLine: 1 } });
const findings = [finding("admin-high", "high", "admin/a.java"), finding("payments-medium", "medium", "payments/a.java")];
const outcome: ScanOutcome = { target: "shop", threadId: "t", startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:00:01Z", budgetUsd: 1, budgetExhausted: false, failed: false };
const stored = { target: "shop", scanDepth: "default", startedAt: outcome.startedAt, completedAt: outcome.completedAt, durationMs: 1000, findings, warnings: [], summary: { totalAttacks: 0, totalFindings: 2, high: 1, medium: 1, critical: 0, low: 0, info: 0 } } as ScanReport;

describe("scan business context across report boundaries", () => {
  it("two contexts change priority in JSON/markdown/HTML/SARIF without changing technical severity, verification or fail-on", async () => {
    const context = parseBusinessContext(JSON.stringify({ entries: [{ match: "payments/**", tags: ["payments", "personal-data"], note: "<operator>" }] }));
    const contextual = { ...outcome, businessContext: context };
    const json = scanJson(contextual, findings) as { findings: Finding[]; counts: unknown };
    expect(json.findings.map(f => f.id)).toEqual(["payments-medium", "admin-high"]);
    expect(json.findings[0]).toMatchObject({ severity: "medium", status: "discovered", businessContext: { provenance: "operator", repository: "shop", shift: 2 } });
    expect(json.findings[0]?.impactAssessment).toBeUndefined();
    expect(json.counts).toEqual(scanJson(outcome, findings).counts);
    expect(scanExitCode(contextual, findings, "high")).toBe(scanExitCode(outcome, findings, "high"));
    const report = toScanReport(contextual, stored);
    const outputs = await Promise.all((["markdown", "html", "sarif"] as const).map(format => exportReport(report, format, "context")));
    const [markdown, html, sarif] = outputs.map(output => typeof output.body === "string" ? output.body : new TextDecoder().decode(output.body)) as [string, string, string];
    expect(markdown.indexOf("payments-medium")).toBeLessThan(markdown.indexOf("admin-high"));
    expect(markdown).toContain("unverified declaration");
    expect(html).toContain("&lt;operator&gt;");
    expect(html).not.toContain("<operator>");
    const payload = typeof sarif === "string" ? JSON.parse(sarif) : sarif;
    expect(payload.runs[0].results[0]).toMatchObject({ level: "warning", properties: { businessContext: { provenance: "operator", shift: 2 } } });
    const other = { ...outcome, businessContext: parseBusinessContext(JSON.stringify({ entries: [{ match: "admin/**", tags: ["operationally-critical"] }] })) };
    expect((scanJson(other, findings).findings as Finding[]).map(f => f.id)).toEqual(["admin-high", "payments-medium"]);
    expect(findings[1]?.businessContext).toBeUndefined();
  });
  it("uses persisted declarations for burndown work ordering while technical severity filters stay technical", () => {
    const context = parseBusinessContext('{"entries":[{"match":"payments/**","tags":["payments","personal-data"]}]}');
    const labelled = (scanJson({ ...outcome, businessContext: context }, findings).findings as Finding[]).map(f => ({ ...f, fingerprint: f.id, scanId: "s", tool: null, triage: "new" }));
    expect(selectCandidates(labelled, {}).map(f => f.id)).toEqual(["payments-medium", "admin-high"]);
    expect(selectCandidates(labelled, { severity: "high" }).map(f => f.id)).toEqual(["admin-high"]);
  });
  it("API normalizes persisted context independently of impact and refuses malformed claims", () => {
    const labelled = (scanJson({ ...outcome, businessContext: parseBusinessContext('{"entries":[]}') }, findings).findings as Finding[])[0]!;
    const row = { ...labelled, businessContext: JSON.stringify(labelled.businessContext) };
    expect(normalizeFinding(row as never).businessContext?.provenance).toBe("operator");
    expect(normalizeFinding({ ...row, businessContext: "{}" } as never).businessContext).toBeNull();
  });
});
