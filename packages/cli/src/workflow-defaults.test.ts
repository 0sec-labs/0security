import { describe, expect, it } from "vitest";
import { Command } from "commander";
import { applyBurndownWorkflowDefaults, applyWorkflowDefaults, workflowDefault } from "./workflow-defaults.js";
import { DEFAULT_SETTINGS, isOperatorSetting, normalizeSettings, normalizeWorkflows, resolveLayeredSettings } from "./state/settings.js";

const load = () => ({ workflows: { fix: { budget: 0.4, model: "model-a" }, scan: { budget: 2 } } });

/** A command shaped like the real ones: --budget has a default, --model has none. */
function parse(args: string[]) {
  const command = new Command("x").exitOverride().option("--budget <usd>", "", "3").option("--model <model>");
  command.parse(args, { from: "user" });
  return { command, options: command.opts() as { budget?: string; model?: string } };
}

describe("workflow defaults", () => {
  it("fills budget and model when the flags were not passed", () => {
    const { command, options } = parse([]);
    expect(applyWorkflowDefaults("fix", options, command, load)).toMatchObject({ budget: "0.4", model: "model-a" });
  });

  it("keeps a flag that was passed, even when it equals the built-in default", () => {
    const { command, options } = parse(["--budget", "3"]);
    expect(applyWorkflowDefaults("fix", options, command, load)).toMatchObject({ budget: "3", model: "model-a" });
    const second = parse(["--model", "mine"]);
    expect(applyWorkflowDefaults("fix", second.options, second.command, load)).toMatchObject({ budget: "0.4", model: "mine" });
  });

  it("changes nothing for a workflow with no default, or when the settings cannot be read", () => {
    const { command, options } = parse([]);
    expect(applyWorkflowDefaults("verify", options, command, load)).toEqual({ budget: "3" });
    expect(applyWorkflowDefaults("fix", options, command, () => { throw new Error("unreadable"); })).toEqual({ budget: "3" });
    expect(workflowDefault("scan", load)).toEqual({ budget: 2 });
  });
});

describe("burndown workflow defaults", () => {
  function burndown(args: string[]) {
    const command = new Command("x").exitOverride().option("--budget <usd>", "", "10").option("--per-fix <usd>", "", "3").option("--model <model>");
    command.parse(args, { from: "user" });
    return { command, options: command.opts() as { budget?: string; perFix?: string; model?: string } };
  }
  it("maps the fix budget to the per-fix cap and leaves the total alone", () => {
    const { command, options } = burndown([]);
    expect(applyBurndownWorkflowDefaults(options, command, load)).toMatchObject({ budget: "10", perFix: "0.4", model: "model-a" });
  });
  it("keeps flags that were passed", () => {
    const { command, options } = burndown(["--per-fix", "3", "--model", "mine"]);
    expect(applyBurndownWorkflowDefaults(options, command, load)).toMatchObject({ perFix: "3", model: "mine" });
  });
});

describe("workflows setting", () => {
  it("keeps valid budgets and model ids and drops everything else", () => {
    expect(normalizeWorkflows({ fix: { budget: 1.5, model: " gpt-6-luna " }, scan: { budget: -1, model: "has spaces" }, verify: "x", other: { budget: 1 } })).toEqual({ fix: { budget: 1.5, model: "gpt-6-luna" } });
    expect(normalizeWorkflows({ fix: { budget: 5000 } })).toEqual({});
    expect(normalizeWorkflows("nope")).toBeUndefined();
    expect(normalizeWorkflows(null)).toBeUndefined();
  });

  it("round-trips through the settings file and defaults to none", () => {
    expect(DEFAULT_SETTINGS.workflows).toEqual({});
    expect(normalizeSettings({ workflows: { verify: { budget: 1 } } }).workflows).toEqual({ verify: { budget: 1 } });
    expect(normalizeSettings({}).workflows).toEqual({});
  });

  it("is operator-only: a project settings file cannot set it", () => {
    expect(isOperatorSetting("workflows")).toBe(true);
    const merged = resolveLayeredSettings({ workflows: { fix: { budget: 1 } } }, { workflows: { fix: { budget: 999, model: "evil" } } });
    expect(merged.settings.workflows).toEqual({ fix: { budget: 1 } });
    expect(merged.sources.workflows).toBe("global");
  });
});
