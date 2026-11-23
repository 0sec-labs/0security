import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyTierSettings, globToRegExp, loadTierMap, parseTierMap, repoIdentifier, resolveTier, settingsSentence, tierSentence } from "./scan-tiers.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "scan-tiers-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const MAP = `
version: 1
default: light
tiers:
  critical: { budget: 30, batches: on, skill: scan, reason: handles money }
  light: { budget: 0.5, batches: off, prepassOnly: true }
  skip: { reason: archived }
repositories:
  - repo: Acme/*
    tier: standard
    reason: any acme repository
  - repo: acme/payments
    tier: critical
    reason: card data
  - repo: acme/old-site
    tier: skip
  - path: /work/labs/**
    tier: light
    reason: experiments
  - path: /work/labs/prod-tool
    tier: critical
`;

describe("resolveTier", () => {
  const map = parseTierMap(MAP, "tiers.yaml");

  it("prefers an exact repository over a pattern that comes first in the file", () => {
    const tier = resolveTier(map, { repo: "acme/payments" });
    expect(tier).toMatchObject({ name: "critical", source: "exact-repo", match: "acme/payments", reason: "card data" });
    expect(tier.settings).toMatchObject({ budget: 30, batches: "on" });
  });
  it("falls back to a pattern, then to the file's default", () => {
    expect(resolveTier(map, { repo: "acme/website" })).toMatchObject({ name: "standard", source: "glob", match: "acme/*", reason: "any acme repository" });
    expect(resolveTier(map, { repo: "other/thing" })).toMatchObject({ name: "light", source: "default", prepassOnly: true });
  });
  it("matches repository names without regard to case", () => {
    expect(resolveTier(map, { repo: "ACME/Payments" }).name).toBe("critical");
  });
  it("prefers an exact path over a path pattern, and matches a path pattern inside the folder", () => {
    expect(resolveTier(map, { path: "/work/labs/prod-tool" })).toMatchObject({ name: "critical", source: "exact-path" });
    expect(resolveTier(map, { path: "/work/labs/toy/deep" })).toMatchObject({ name: "light", source: "glob", reason: "experiments" });
    expect(resolveTier(map, { path: "/work/labs" }).source).toBe("glob");
    expect(resolveTier(map, { path: "/work/labsx" }).source).toBe("default");
  });
  it("prefers the repository over the path when both match", () => {
    expect(resolveTier(map, { repo: "acme/payments", path: "/work/labs/toy" }).name).toBe("critical");
  });
  it("marks a skipped tier and takes the reason from the tier when the entry has none", () => {
    expect(resolveTier(map, { repo: "acme/old-site" })).toMatchObject({ name: "skip", skipped: true, reason: "archived" });
  });
  it("uses the built-in standard tier when the file names no default", () => {
    const tier = resolveTier(parseTierMap("repositories: []\n", "t.yaml"), { repo: "a/b" });
    expect(tier).toMatchObject({ name: "standard", source: "default" });
    expect(tier.settings).toMatchObject({ budget: 5, batches: "auto" });
  });
  it("describes the result in one sentence", () => {
    expect(tierSentence(resolveTier(map, { repo: "acme/payments" }))).toBe("tier critical (repository acme/payments matched exactly; reason: card data)");
    expect(tierSentence(resolveTier(map, { repo: "x/y" }))).toContain("no entry matched, so the default applies");
    expect(settingsSentence(resolveTier(map, { repo: "acme/payments" }))).toBe("budget $30, batches on, skill scan");
    expect(settingsSentence(resolveTier(map, { repo: "acme/old-site" }))).toBe("the scan is skipped");
    expect(settingsSentence(resolveTier(map, { repo: "x/y" }))).toContain("no model");
  });
});

describe("parseTierMap validation", () => {
  const bad = (text: string, message: RegExp) => expect(() => parseTierMap(text, "t.yaml")).toThrow(message);
  it("names the file and the entry that is wrong", () => {
    bad("repositories:\n  - repo: acme/x\n    tier: gold\n", /t\.yaml: repositories\[0\]: tier must be one of critical, standard, light, skip/);
    bad("repositories:\n  - repo: acme\n    tier: skip\n", /repositories\[0\]\.repo must look like owner\/name/);
    bad("repositories:\n  - path: relative/dir\n    tier: skip\n", /path must be an absolute folder pattern/);
    bad("repositories:\n  - path: /a/../b\n    tier: skip\n", /must not contain '\.\.'/);
    bad("repositories:\n  - tier: skip\n", /exactly one of repo/);
    bad("repositories:\n  - repo: a/b\n    path: /x\n    tier: skip\n", /exactly one of repo/);
    bad("repositories:\n  - repo: a/b\n    tier: skip\n    note: x\n", /unknown key 'note'/);
    bad("tiers:\n  gold: { budget: 1 }\n", /tiers: tier must be one of/);
    bad("tiers:\n  light: { budget: -3 }\n", /tiers\.light\.budget must be a positive USD amount/);
    bad("tiers:\n  light: { batches: sometimes }\n", /batches must be auto, on or off/);
    bad("tiers:\n  light: { skill: 'Bad Skill' }\n", /skill must be a skill id/);
    bad("tiers:\n  light: { colour: red }\n", /unknown setting 'colour'/);
    bad("tiers:\n  skip: { budget: 1 }\n", /tiers\.skip takes only a reason/);
    bad("tiers:\n  light: { prepassOnly: true, skill: scan }\n", /skill has no effect with prepassOnly/);
    bad("default: gold\n", /default: tier must be one of/);
    bad("version: 2\n", /version must be 1/);
    bad("extra: 1\n", /unknown key 'extra'/);
    bad("- a\n- b\n", /must be a mapping/);
    bad("repositories:\n  - repo: a/b\n    tier: skip\n    reason: ''\n", /reason must be a non-empty text/);
  });
  it("reads JSON as well as YAML", () => {
    const map = parseTierMap(JSON.stringify({ repositories: [{ repo: "a/b", tier: "skip", reason: "r" }] }), "t.json");
    expect(resolveTier(map, { repo: "a/b" })).toMatchObject({ skipped: true, reason: "r" });
    expect(() => parseTierMap("{ nope", "t.json")).toThrow(/t\.json: could not be read/);
  });
});

describe("loadTierMap", () => {
  it("reads the state folder when no file is named, and nothing when it has none", () => {
    const state = temp();
    expect(loadTierMap(undefined, state)).toBeUndefined();
    writeFileSync(join(state, "scan-tiers.yaml"), "default: light\n");
    expect(loadTierMap(undefined, state)?.default).toBe("light");
  });
  it("reads the file --tiers names and refuses one that is missing", () => {
    const dir = temp();
    writeFileSync(join(dir, "mine.json"), JSON.stringify({ default: "critical" }));
    expect(loadTierMap(join(dir, "mine.json"), temp())?.default).toBe("critical");
    expect(() => loadTierMap(join(dir, "none.yaml"), temp())).toThrow(/is not a file/);
  });
  it("never looks in the folder being scanned: only the state folder and the named file are read", () => {
    const state = temp();
    const repo = temp();
    mkdirSync(join(repo, ".0"));
    writeFileSync(join(repo, "scan-tiers.yaml"), "default: skip\n");
    writeFileSync(join(repo, ".0", "scan-tiers.yaml"), "default: skip\n");
    expect(loadTierMap(undefined, state)).toBeUndefined();
  });
});

describe("applyTierSettings", () => {
  const map = parseTierMap(MAP, "t.yaml");
  const base = { budget: "5", batches: "auto", skill: "scan" };
  it("fills in what the person did not type", () => {
    const { options, notes } = applyTierSettings(base, resolveTier(map, { repo: "acme/payments" }), new Set());
    expect(options).toMatchObject({ budget: "30", batches: "on", skill: "scan" });
    expect(notes).toEqual([]);
  });
  it("keeps a typed flag over the tier and says so", () => {
    const { options, notes } = applyTierSettings({ ...base, budget: "2" }, resolveTier(map, { repo: "acme/payments" }), new Set(["budget"]));
    expect(options.budget).toBe("2");
    expect(options.batches).toBe("on");
    expect(notes).toEqual(["--budget 2 overrides the tier budget $30"]);
  });
  it("keeps the policy-check skill when policies are given", () => {
    const custom = parseTierMap("tiers:\n  standard: { skill: iac-review }\n", "t.yaml");
    expect(applyTierSettings({ ...base, policy: ["p.md"] }, resolveTier(custom, { repo: "a/b" }), new Set()).options.skill).toBe("scan");
    expect(applyTierSettings(base, resolveTier(custom, { repo: "a/b" }), new Set()).options.skill).toBe("iac-review");
  });
  it("changes nothing for a skipped or pre-pass-only tier", () => {
    expect(applyTierSettings(base, resolveTier(map, { repo: "acme/old-site" }), new Set()).options).toEqual(base);
    expect(applyTierSettings(base, resolveTier(map, { repo: "x/y" }), new Set()).options).toEqual(base);
  });
});

describe("repoIdentifier and globToRegExp", () => {
  it("reads owner/name from the usual remote forms", () => {
    expect(repoIdentifier("git@github.com:Acme/Payments.git")).toBe("acme/payments");
    expect(repoIdentifier("https://user:pw@github.com/acme/payments.git")).toBe("acme/payments");
    expect(repoIdentifier("ssh://git@host.example/team/sub/app")).toBe("sub/app");
    expect(repoIdentifier("/local/path")).toBe("local/path");
    expect(repoIdentifier("nothing")).toBeUndefined();
    expect(repoIdentifier(undefined)).toBeUndefined();
  });
  it("keeps * and ? inside one segment, and ** across segments", () => {
    expect(globToRegExp("acme/*").test("acme/x")).toBe(true);
    expect(globToRegExp("acme/*").test("acme/x/y")).toBe(false);
    expect(globToRegExp("/a/**/c").test("/a/b/d/c")).toBe(true);
    expect(globToRegExp("/a/**/c").test("/a/c")).toBe(true);
    expect(globToRegExp("/a/b?").test("/a/bc")).toBe(true);
    expect(globToRegExp("/a.b/*").test("/aXb/c")).toBe(false);
  });
});
