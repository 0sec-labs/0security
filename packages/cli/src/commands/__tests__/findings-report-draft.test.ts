import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@0/engine/shared";
import { buildAllDrafts, buildReportDraft, readFactsFile, REPORT_STAGES, runReportDraft, type DraftContext, type ReportDraftDeps } from "../findings-report-draft.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const tmp = () => { const dir = mkdtempSync(join(tmpdir(), "0-draft-")); dirs.push(dir); return dir; };

const finding = (extra: Partial<Finding> = {}): Finding => ({
  id: "f-1234", templateId: "t", title: "SQL injection in login", description: "The username is concatenated into a query.\nSecond line.", severity: "high", category: "injection",
  status: "confirmed", evidence: { request: "SECRET-REQUEST-BODY", response: "SECRET-RESPONSE-BODY" }, fingerprint: "abc123", triageStatus: "accepted", timestamp: Date.UTC(2026, 8, 1, 12, 0, 0),
  reviewAnnotation: { path: "src/login.ts", startLine: 12 }, ...extra,
} as Finding);
const ctx = (facts: DraftContext["facts"] = {}, extra: Partial<Finding> = {}): DraftContext => ({ finding: finding(extra), target: "/srv/app", facts, toolVersion: "9.9.9", generatedAt: "2026-11-21T00:00:00.000Z" });
const BLANK = "[to be completed by the manufacturer:";

describe("report drafts", () => {
  it("takes finding fields from the record and leaves everything else visibly blank", () => {
    const text = buildReportDraft("early-warning", ctx());
    expect(text).toContain("SQL injection in login");
    expect(text).toContain("`src/login.ts:12`");
    expect(text).toContain("2026-09-01T12:00:00.000Z");
    expect(text).toContain("confirmed, triage: accepted");
    for (const field of ["Manufacturer:", "Product with digital elements:", "Affected versions:", "Contact for this report:", "Exploited since", "How the manufacturer knows"]) {
      expect(text, field).toMatch(new RegExp(`${field}[^\\n]*\\[to be completed by the manufacturer:`));
    }
  });

  it("never claims exploitation, user impact or a patch that was not supplied", () => {
    for (const stage of REPORT_STAGES) {
      const text = buildReportDraft(stage, ctx());
      expect(text, stage).toContain("does not state that the vulnerability is being exploited");
      expect(text, stage).not.toMatch(/is being exploited in the wild|has been exploited|patch (is )?available|fixed in version/i);
      expect(text, stage).toContain("DRAFT. Not submitted.");
      expect(text, stage).toContain("Article 14 of Regulation (EU) 2024/2847");
      expect(text, stage).toContain("must read it, correct it, complete every blank and submit it");
    }
    const final = buildReportDraft("final", ctx());
    expect(final).toMatch(/Corrective measure[^\n]*none was supplied, so none is claimed/);
    expect(final).toMatch(/Mitigation[^\n]*none were supplied/);
  });

  it("uses supplied facts and drops the no-exploitation notice only when exploitation facts exist", () => {
    const text = buildReportDraft("notification", ctx({ product: "Acme Widget", affectedVersions: "1.0 to 1.4", exploitedSince: "2026-10-30 08:00 UTC", mitigation: "Disable login form", contact: "J, sec@example.com" }));
    expect(text).toContain("Product with digital elements: Acme Widget");
    expect(text).toContain("Affected versions: 1.0 to 1.4");
    expect(text).toContain("Exploited since / first known exploitation: 2026-10-30 08:00 UTC");
    expect(text).toContain("Mitigation the manufacturer has taken or recommends: Disable login form");
    expect(text).not.toContain("does not state that the vulnerability is being exploited");
    expect(text).toContain("How the manufacturer knows it is being exploited: [to be completed");
  });

  it("includes the attacker impact only when it was assessed", () => {
    expect(buildReportDraft("early-warning", ctx())).toMatch(/Attacker impact[\s\S]*\[to be completed by the manufacturer: impact/);
    const assessed = { impactAssessment: { blast_radius: "Read every user's records.", reachability_tier: "remote-unauth", weaponizability: "info-leak", rationale: "x" } } as unknown as Partial<Finding>;
    const text = buildReportDraft("early-warning", ctx({}, assessed));
    expect(text).toContain("> Read every user's records. Who: anyone who can reach it over the network, without logging in. They can: read data they should not be able to read.");
  });

  it("never copies evidence bodies, and keeps a table intact for odd titles", () => {
    const text = buildAllDrafts(ctx({}, { title: "a | b\nc" }));
    expect(text).not.toContain("SECRET-REQUEST-BODY");
    expect(text).not.toContain("SECRET-RESPONSE-BODY");
    expect(text).toContain("| Title | a \\| b c |");
    for (const title of ["Early warning", "Vulnerability notification", "Final report"]) expect(text).toContain(`# ${title} (draft)`);
  });

  it("marks a missing location and date as blanks rather than inventing them", () => {
    const text = buildReportDraft("early-warning", ctx({}, { reviewAnnotation: undefined, timestamp: 0 }));
    expect(text).toContain(`${BLANK} location; the finding record has none]`);
    expect(text).toContain(`${BLANK} date; the finding record has none]`);
  });

  it("lists evidence files by name and checksum only", () => {
    const dir = tmp();
    const log = join(dir, "access.log");
    writeFileSync(log, "TOP-SECRET-LOG-LINE");
    const out: string[] = [];
    const deps: ReportDraftDeps = { out: t => out.push(t), err: () => undefined, write: () => undefined, load: () => ({ finding: finding() }), now: () => new Date("2026-11-21T00:00:00Z"), version: "1.2.3" };
    runReportDraft("f-1", { stage: "notification", evidenceFile: [log] }, deps);
    const text = out.join("");
    expect(text).toContain("access.log | 19 bytes");
    expect(text).toMatch(/`[0-9a-f]{64}`/);
    expect(text).not.toContain("TOP-SECRET-LOG-LINE");
    expect(text).toContain("`0` 1.2.3");
  });
});

describe("report-draft input", () => {
  const deps = (written: Record<string, string> = {}): ReportDraftDeps & { out_: string[]; err_: string[] } => {
    const out_: string[] = []; const err_: string[] = [];
    return { out_, err_, out: t => out_.push(t), err: t => err_.push(t), write: (p, t) => { written[p] = t; }, load: () => ({ finding: finding() }), now: () => new Date("2026-11-21T00:00:00Z"), version: "1" };
  };
  it("rejects an unknown stage and writes a file when asked", () => {
    expect(() => runReportDraft("f", { stage: "weekly" }, deps())).toThrow("--stage must be one of");
    expect(() => runReportDraft("f", {}, deps())).toThrow("--stage must be one of");
    const written: Record<string, string> = {};
    const io = deps(written);
    runReportDraft("f", { stage: "final", output: "/tmp/x/final.md" }, io);
    expect(Object.keys(written)).toEqual(["/tmp/x/final.md"]);
    expect(io.err_.join("")).toContain("nothing was sent");
  });
  it("reads facts from a file, lets flags win, and rejects unknown keys", () => {
    const dir = tmp();
    const file = join(dir, "facts.json");
    writeFileSync(file, JSON.stringify({ product: "From File", affectedVersions: "2.x" }));
    const io = deps();
    runReportDraft("f", { stage: "early-warning", facts: file, product: "From Flag" }, io);
    const text = io.out_.join("");
    expect(text).toContain("Product with digital elements: From Flag");
    expect(text).toContain("Affected versions: 2.x");
    writeFileSync(file, JSON.stringify({ affectedVersion: "typo" }));
    expect(() => readFactsFile(file)).toThrow("unknown key 'affectedVersion'");
    writeFileSync(file, "[]");
    expect(() => readFactsFile(file)).toThrow("must be a JSON object");
    expect(() => runReportDraft("f", { stage: "final", evidenceFile: [join(dir, "missing")] }, io)).toThrow("does not exist");
  });
});
