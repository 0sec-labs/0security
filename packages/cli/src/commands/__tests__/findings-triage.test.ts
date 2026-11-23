import { describe, expect, it, vi } from "vitest";

const audit = vi.hoisted(() => vi.fn());
vi.mock("@0/engine/storage", () => ({ recordAudit: audit }));

const { auditTriage, buildTriageRequest, triageLabel } = await import("../findings-triage.js");

const NOW = Date.parse("2026-06-01T12:00:00.000Z");

describe("buildTriageRequest", () => {
  it("accepts a risk with a reason, an expiry and an approver label", () => {
    const request = buildTriageRequest("accepted", { reason: "vendor patch due", expires: "90d", approver: "security lead" }, NOW);
    expect(request).toEqual({ status: "accepted", note: "vendor patch due", details: { expiresAt: "2026-08-30T12:00:00.000Z", approver: "security lead" } });
  });
  it("requires a reason and an expiry for an accepted risk", () => {
    expect(() => buildTriageRequest("accepted", { expires: "90d" }, NOW)).toThrow(/needs a reason/);
    expect(() => buildTriageRequest("accepted", { reason: "   ", expires: "90d" }, NOW)).toThrow(/needs a reason/);
    expect(() => buildTriageRequest("accepted", { reason: "x" }, NOW)).toThrow(/needs an expiry/);
    expect(() => buildTriageRequest("accepted", { reason: "x", expires: "2026-01-01" }, NOW)).toThrow(/future/);
    expect(() => buildTriageRequest("accepted", { reason: "x", expires: "nonsense" }, NOW)).toThrow(/--expires/);
  });
  it("caps the reason and the approver and flattens control characters", () => {
    expect(() => buildTriageRequest("accepted", { reason: "x".repeat(501), expires: "90d" }, NOW)).toThrow(/under 500/);
    expect(() => buildTriageRequest("accepted", { reason: "x", expires: "90d", approver: "y".repeat(81) }, NOW)).toThrow(/--approver/);
    expect(buildTriageRequest("accepted", { reason: "a\nb\u0007c", expires: "90d" }, NOW).note).toBe("a b c");
  });
  it("keeps expiry and approver out of reopening and suppression", () => {
    expect(() => buildTriageRequest("new", { expires: "90d" }, NOW)).toThrow(/accepted findings/);
    expect(() => buildTriageRequest("suppressed", { expires: "90d" }, NOW)).toThrow(/no expiry/);
    expect(buildTriageRequest("suppressed", { note: "duplicate" }, NOW)).toEqual({ status: "suppressed", note: "duplicate", details: {} });
    expect(buildTriageRequest("new", {}, NOW)).toEqual({ status: "new", note: undefined, details: {} });
  });
});

describe("triageLabel", () => {
  it("shows when an acceptance ends and when it has lapsed", () => {
    expect(triageLabel({ triageStatus: "accepted", triageExpiresAt: "2026-12-31T23:59:59.999Z" }, NOW)).toBe("accepted until 2026-12-31");
    expect(triageLabel({ triageStatus: "accepted", triageExpiresAt: "2026-05-01T00:00:00.000Z" }, NOW)).toBe("open (acceptance expired 2026-05-01)");
    expect(triageLabel({ triageStatus: "suppressed" }, NOW)).toBe("suppressed");
    expect(triageLabel({}, NOW)).toBe("new");
  });
});

describe("auditTriage", () => {
  it("writes one entry per change with the reason, expiry and approver label", () => {
    audit.mockClear();
    auditTriage({ findingId: "f-1234567890abcdef", fingerprint: "fp", from: "new", request: buildTriageRequest("accepted", { reason: "vendor patch due", expires: "90d", approver: "lead" }, NOW) });
    expect(audit).toHaveBeenCalledTimes(1);
    const [event] = audit.mock.calls[0]!;
    expect(event).toMatchObject({ action: "finding.triage.accepted", subject: "f-123456", detail: { old: "new", new: "accepted", reason: "vendor patch due", name: "lead", fingerprint: "fp" } });
    expect(event.detail.expires).toBe("2026-08-30T12:00:00.000Z");
  });
});
