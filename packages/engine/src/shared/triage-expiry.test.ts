import { describe, expect, it } from "vitest";
import { acceptanceExpired, acceptanceExpiresWithin, effectiveTriageStatus, parseTriageExpiry } from "./triage-expiry.js";

const NOW = Date.parse("2026-06-01T12:00:00.000Z");

describe("effectiveTriageStatus", () => {
  it("keeps an acceptance before its expiry", () => {
    expect(effectiveTriageStatus({ triageStatus: "accepted", triageExpiresAt: "2026-06-02T00:00:00.000Z" }, NOW)).toBe("accepted");
  });
  it("reopens an acceptance at and after its expiry", () => {
    expect(effectiveTriageStatus({ triageStatus: "accepted", triageExpiresAt: "2026-06-01T12:00:00.000Z" }, NOW)).toBe("new");
    expect(effectiveTriageStatus({ triageStatus: "accepted", triageExpiresAt: "2026-05-01T00:00:00.000Z" }, new Date(NOW))).toBe("new");
  });
  it("never lapses without a readable expiry", () => {
    expect(effectiveTriageStatus({ triageStatus: "accepted" }, NOW)).toBe("accepted");
    expect(effectiveTriageStatus({ triageStatus: "accepted", triageExpiresAt: "garbage" }, NOW)).toBe("accepted");
  });
  it("leaves other states alone", () => {
    expect(effectiveTriageStatus({ triageStatus: "suppressed", triageExpiresAt: "2001-01-01T00:00:00.000Z" }, NOW)).toBe("suppressed");
    expect(effectiveTriageStatus({ triageStatus: null }, NOW)).toBe("new");
    expect(effectiveTriageStatus({}, NOW)).toBe("new");
  });
  it("tells an expired acceptance from a finding that was never accepted", () => {
    expect(acceptanceExpired({ triageStatus: "accepted", triageExpiresAt: "2026-05-01T00:00:00.000Z" }, NOW)).toBe(true);
    expect(acceptanceExpired({ triageStatus: "new" }, NOW)).toBe(false);
  });
  it("finds live acceptances that lapse within N days", () => {
    const soon = { triageStatus: "accepted", triageExpiresAt: "2026-06-10T00:00:00.000Z" };
    expect(acceptanceExpiresWithin(soon, 30, NOW)).toBe(true);
    expect(acceptanceExpiresWithin(soon, 5, NOW)).toBe(false);
    expect(acceptanceExpiresWithin({ triageStatus: "accepted", triageExpiresAt: "2026-05-01T00:00:00.000Z" }, 30, NOW)).toBe(false);
    expect(acceptanceExpiresWithin({ triageStatus: "accepted" }, 30, NOW)).toBe(false);
  });
});

describe("parseTriageExpiry", () => {
  it("reads days, dates and full times", () => {
    expect(parseTriageExpiry("90d", NOW)).toBe("2026-08-30T12:00:00.000Z");
    expect(parseTriageExpiry("2026-12-31", NOW)).toBe("2026-12-31T23:59:59.999Z");
    expect(parseTriageExpiry("2026-12-31T08:00:00Z", NOW)).toBe("2026-12-31T08:00:00.000Z");
  });
  it("rejects past, impossible and unreadable values", () => {
    expect(() => parseTriageExpiry("2026-05-31", NOW)).toThrow(/future/);
    expect(() => parseTriageExpiry("2026-02-30", NOW)).toThrow(/not a real date/);
    expect(() => parseTriageExpiry("0d", NOW)).toThrow(/days/);
    expect(() => parseTriageExpiry("5000d", NOW)).toThrow(/--expires/);
    expect(() => parseTriageExpiry("soon", NOW)).toThrow(/--expires/);
  });
});
