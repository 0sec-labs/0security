import { describe, expect, it } from "vitest";
import { ageLabel, describeHistory, historyPath, overviewPath, repoFilter, severityShares, sortOrgFindings, triageLabel, type OrgFinding } from "./findings-org-model";

const finding = (over: Partial<OrgFinding>): OrgFinding => ({
  fingerprint: "fx:1", id: "1", title: "A", severity: "high", category: "injection", triageStatus: "new", triageNote: null, triageExpiresAt: null, triageApprover: null,
  repo: "acme/api", source: "ci", tool: null, firstSeen: 1, lastSeen: 1, ...over,
});

describe("paths", () => {
  it("adds the repository filter only when one is chosen, and encodes both parts", () => {
    expect(overviewPath(null)).toBe("/api/findings-server/overview");
    expect(overviewPath("acme/api")).toBe("/api/findings-server/overview?repo=acme%2Fapi");
    expect(historyPath("fx:abc")).toBe("/api/findings-server/history/fx%3Aabc");
  });
  it("accepts only a repository the server listed", () => {
    expect(repoFilter("acme/api", ["acme/api"])).toBe("acme/api");
    expect(repoFilter("other", ["acme/api"])).toBeNull();
    expect(repoFilter(null, ["acme/api"])).toBeNull();
  });
});

describe("severityShares", () => {
  it("lists every severity in order with rounded shares", () => {
    const shares = severityShares({ critical: 1, high: 2, low: 1 });
    expect(shares.map(item => item.severity)).toEqual(["critical", "high", "medium", "low", "info"]);
    expect(shares.map(item => item.count)).toEqual([1, 2, 0, 1, 0]);
    expect(shares.map(item => item.percent)).toEqual([25, 50, 0, 25, 0]);
  });
  it("is all zero without findings", () => {
    expect(severityShares({}).every(item => item.count === 0 && item.percent === 0)).toBe(true);
  });
});

describe("history and labels", () => {
  it("says who did what", () => {
    expect(describeHistory({ action: "suppress", actor: "user-1", source: null })).toBe("Suppressed by user-1");
    expect(describeHistory({ action: "open", actor: "key:ci", source: "nightly" })).toBe("First seen from nightly");
    expect(describeHistory({ action: "reopen", actor: "local operator", source: null })).toBe("Reopened by local operator");
  });
  it("names the triage states for people", () => {
    expect([triageLabel("new"), triageLabel("accepted"), triageLabel("suppressed")]).toEqual(["Open", "Accepted", "Suppressed"]);
  });
});

describe("sortOrgFindings and ageLabel", () => {
  it("puts the worst severity first, then the newest", () => {
    const sorted = sortOrgFindings([finding({ title: "old high", lastSeen: 1 }), finding({ title: "critical", severity: "critical", lastSeen: 0 }), finding({ title: "new high", lastSeen: 5 })]);
    expect(sorted.map(row => row.title)).toEqual(["critical", "new high", "old high"]);
  });
  it("reads ages", () => {
    const now = Date.UTC(2026, 0, 10);
    expect(ageLabel(now - 10_000, now)).toBe("just now");
    expect(ageLabel(now - 5 * 60_000, now)).toBe("5 min ago");
    expect(ageLabel(now - 3 * 3_600_000, now)).toBe("3 h ago");
    expect(ageLabel(now - 86_400_000, now)).toBe("1 day ago");
    expect(ageLabel(now - 4 * 86_400_000, now)).toBe("4 days ago");
  });
});
