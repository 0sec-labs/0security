// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { describe, expect, it } from "vitest";
import { INGEST_LIMITS, IngestError, ingestDigest, ingestFingerprint, parseIngestBody, parseIngestLabels, summarizeOrg, suppressionReasonError, triageHistoryAction } from "./findings-server.js";

const params = (query: string) => new URLSearchParams(query);

describe("parseIngestLabels", () => {
  it("accepts a repository and defaults the source", () => {
    expect(parseIngestLabels(params("repo=acme/api&commit=ABCDEF1"), "ci-key")).toEqual({ repo: "acme/api", source: "ci-key", commit: "abcdef1" });
    expect(parseIngestLabels(params("repo=acme/api&source=nightly&ref=refs/heads/main"), "x")).toMatchObject({ source: "nightly", ref: "refs/heads/main" });
  });
  it("rejects a missing or odd repository, source, ref and commit", () => {
    for (const q of ["", "repo=api", "repo=a/b/c/d", "repo=ac%20me/api", "repo=a/b&source=bad%20label", "repo=a/b&ref=%3Cscript%3E", "repo=a/b&commit=zz"]) {
      expect(() => parseIngestLabels(params(q), "x")).toThrow(IngestError);
    }
  });
});

describe("parseIngestBody", () => {
  it("tells SARIF from findings JSON and counts", () => {
    expect(parseIngestBody(JSON.stringify({ version: "2.1.0", runs: [{ results: [{}, {}] }, { results: [{}] }] }))).toMatchObject({ format: "sarif", count: 3 });
    expect(parseIngestBody(JSON.stringify({ findings: [{}] }))).toMatchObject({ format: "findings-json", count: 1 });
  });
  it("rejects bad JSON, other shapes and too many findings", () => {
    expect(() => parseIngestBody("{")).toThrow(/not valid JSON/);
    expect(() => parseIngestBody("[]")).toThrow(IngestError);
    expect(() => parseIngestBody("{}")).toThrow(/SARIF/);
    const big = JSON.stringify({ findings: new Array(INGEST_LIMITS.maxFindings + 1).fill({}) });
    expect(() => parseIngestBody(big)).toThrow(expect.objectContaining({ statusCode: 413 }));
  });
  it("rejects a body over the size limit with 413", () => {
    expect(() => parseIngestBody(" ".repeat(INGEST_LIMITS.maxBytes + 1))).toThrow(expect.objectContaining({ statusCode: 413 }));
  });
});

describe("identity", () => {
  it("is stable per repository and key", () => {
    expect(ingestFingerprint("a/b", "k")).toBe(ingestFingerprint("a/b", "k"));
    expect(ingestFingerprint("a/b", "k")).not.toBe(ingestFingerprint("a/c", "k"));
    expect(ingestFingerprint("a/b", "k")).toMatch(/^fx:[0-9a-f]{32}$/);
    expect(ingestDigest("a/b", "s", "{}")).not.toBe(ingestDigest("a/b", "t", "{}"));
  });
});

describe("suppression reason", () => {
  it("is required only for suppression", () => {
    expect(suppressionReasonError("suppressed", undefined)).toMatch(/reason/);
    expect(suppressionReasonError("suppressed", "   short")).toMatch(/reason/);
    expect(suppressionReasonError("suppressed", "test fixture, not shipped")).toBeNull();
    expect(suppressionReasonError("accepted", undefined)).toBeNull();
    expect(triageHistoryAction("suppressed")).toBe("suppress");
    expect(triageHistoryAction("new")).toBe("reopen");
  });
});

describe("summarizeOrg", () => {
  it("counts by severity, status and repository", () => {
    const row = (over: object) => ({ fingerprint: "f", title: "t", severity: "high", triageStatus: "new", triageNote: null, triageExpiresAt: null, repo: "a/b", lastSeen: 1, ...over });
    const summary = summarizeOrg([row({}), row({ severity: "low", repo: "a/c" }), row({ triageStatus: "suppressed", triageNote: "because", fingerprint: "g" })]);
    expect(summary).toMatchObject({ total: 3, open: 2, bySeverity: { high: 2, low: 1, critical: 0 }, byStatus: { new: 2, suppressed: 1, accepted: 0 } });
    expect(summary.byRepo[0]).toMatchObject({ repo: "a/b", total: 2, open: 1 });
    expect(summary.suppressions).toEqual([expect.objectContaining({ fingerprint: "g", reason: "because" })]);
  });
});
