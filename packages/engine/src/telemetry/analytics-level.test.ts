import { describe, expect, it } from "vitest";
import {
  ANALYTICS_OPT_OUT_ENV,
  type AnalyticsLevel,
  analyticsOptedOut,
  levelAtLeast,
  resolveAnalyticsLevel,
} from "./analytics-level.js";

describe("levelAtLeast", () => {
  it("orders off < usage", () => {
    expect(levelAtLeast("usage", "off")).toBe(true);
    expect(levelAtLeast("off", "usage")).toBe(false);
    expect(levelAtLeast("usage", "usage")).toBe(true);
  });
});

describe("resolveAnalyticsLevel — parsing", () => {
  const levels: AnalyticsLevel[] = ["off", "usage"];
  for (const level of levels) {
    it(`parses ${level}`, () => {
      expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": level })).toBe(level);
    });
  }

  it("is case-insensitive and trims", () => {
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "  USAGE " })).toBe("usage");
  });

  it("defaults new installations to usage metrics only", () => {
    expect(resolveAnalyticsLevel({})).toBe("usage");
  });

  it("fails closed to off on an unknown/invalid value, including the removed tiers", () => {
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "everything" })).toBe("off");
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "commands" })).toBe("off");
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "full" })).toBe("off");
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "" })).toBe("off");
  });
});

describe("the opt-outs", () => {
  it("are DO_NOT_TRACK and ZERO_ENTERPRISE and nothing else", () => {
    expect([...ANALYTICS_OPT_OUT_ENV]).toEqual(["DO_NOT_TRACK", "ZERO_ENTERPRISE"]);
  });

  it("DO_NOT_TRACK forces off", () => {
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "usage", DO_NOT_TRACK: "1" })).toBe("off");
    expect(resolveAnalyticsLevel({ DO_NOT_TRACK: "true" })).toBe("off");
    expect(analyticsOptedOut({ DO_NOT_TRACK: "1" })).toBe(true);
  });

  it("DO_NOT_TRACK explicitly falsy does NOT force off", () => {
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "usage", DO_NOT_TRACK: "0" })).toBe("usage");
    expect(resolveAnalyticsLevel({ "ZERO_ANALYTICS_LEVEL": "usage", DO_NOT_TRACK: "false" })).toBe("usage");
  });

  it("ZERO_ENTERPRISE forces analytics off, like DO_NOT_TRACK", () => {
    expect(analyticsOptedOut({ ZERO_ENTERPRISE: "1" })).toBe(true);
    expect(resolveAnalyticsLevel({ ZERO_ENTERPRISE: "1", ZERO_ANALYTICS_LEVEL: "usage" })).toBe("off");
    expect(analyticsOptedOut({ ZERO_ENTERPRISE: "0" })).toBe(false);
  });

  it("ZERO_NO_TELEMETRY and ZERO_OFFLINE do not affect analytics", () => {
    for (const name of ["ZERO_NO_TELEMETRY", "ZERO_OFFLINE"]) {
      expect(analyticsOptedOut({ [name]: "1" })).toBe(false);
      expect(resolveAnalyticsLevel({ [name]: "1" })).toBe("usage");
    }
  });
});
