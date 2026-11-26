import { describe, expect, it } from "vitest";
import { lifecycleSuppressed } from "./lifecycle-gate.js";

const gate = (args: string[], env: NodeJS.ProcessEnv = {}, explicitOptIn = false) => lifecycleSuppressed({ args, env, explicitOptIn });

describe("lifecycle event gate", () => {
  it("allows an ordinary interactive run", () => {
    expect(gate(["scan", "web", "x"])).toBe(false);
  });
  it("suppresses help, version and completion, even with an explicit opt-in", () => {
    for (const args of [["--help"], ["scan", "-h"], ["--version"], ["-V"], ["help", "scan"], ["completion", "zsh"], ["__complete", "sc"]]) {
      expect(gate(args, {}, true), args.join(" ")).toBe(true);
    }
    expect(gate(["scan"], { COMP_LINE: "0 sc" }, true)).toBe(true);
  });
  it("suppresses the quiet commands, so config set analyticsLevel off writes nothing on a fresh install", () => {
    for (const args of [["config", "set", "analyticsLevel", "off"], ["reports"], ["workbench", "status"]]) expect(gate(args, {}, true), args.join(" ")).toBe(true);
  });
  it("suppresses CI and machine output unless the user opted in explicitly", () => {
    expect(gate(["scan"], { CI: "true" })).toBe(true);
    expect(gate(["scan", "--json"])).toBe(true);
    expect(gate(["scan", "--format", "sarif"])).toBe(true);
    expect(gate(["scan"], { ZERO_LOG_FORMAT: "json" })).toBe(true);
    expect(gate(["scan"], { CI: "true" }, true)).toBe(false);
    expect(gate(["scan", "--json"], {}, true)).toBe(false);
  });
  it("treats CI=false or empty as not CI", () => {
    expect(gate(["scan"], { CI: "false" })).toBe(false);
    expect(gate(["scan"], { CI: "" })).toBe(false);
  });
});
