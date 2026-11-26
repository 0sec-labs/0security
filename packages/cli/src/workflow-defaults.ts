/**
 * Per-workflow defaults for `0 scan`, `0 findings fix` and `0 findings verify`.
 *
 * The defaults come from the `workflows` key of the operator's own settings file (`~/.0/tui-settings.json`), never
 * from a project folder: a repository must not choose the model or the spend of a run. A flag on the command line
 * always wins.
 */
import type { Command } from "commander";
import { loadGlobalSettings, type WorkflowDefault, type WorkflowName } from "./state/settings.js";

export function workflowDefault(name: WorkflowName, load: () => { workflows: Partial<Record<WorkflowName, WorkflowDefault>> } = () => loadGlobalSettings()): WorkflowDefault {
  try { return load().workflows[name] ?? {}; } catch { return {}; }
}

/**
 * Fill `budget` and `model` from the workflow default when the user did not pass the flag. A value is "passed" when
 * the command line or the environment set it; commander's own default does not count.
 */
export function applyWorkflowDefaults<T extends { budget?: string; model?: string }>(name: WorkflowName, options: T, command: Pick<Command, "getOptionValueSource"> | undefined, load?: Parameters<typeof workflowDefault>[1]): T {
  if (!command) return options;
  const wanted = workflowDefault(name, load);
  const explicit = (flag: string) => { const source = command.getOptionValueSource(flag); return source === "cli" || source === "env"; };
  const next = { ...options };
  if (wanted.budget !== undefined && !explicit("budget")) next.budget = String(wanted.budget);
  if (wanted.model !== undefined && !explicit("model")) next.model = wanted.model;
  return next;
}

/**
 * `findings burndown` runs one fix per finding, so the `fix` workflow's budget is its per-fix cap (`--per-fix`) and its
 * model is `--model`. The run's total (`--budget`) has no workflow default. A flag or environment value still wins.
 */
export function applyBurndownWorkflowDefaults<T extends { perFix?: string; model?: string }>(options: T, command: Pick<Command, "getOptionValueSource"> | undefined, load?: Parameters<typeof workflowDefault>[1]): T {
  if (!command) return options;
  const wanted = workflowDefault("fix", load);
  const explicit = (flag: string) => { const source = command.getOptionValueSource(flag); return source === "cli" || source === "env"; };
  const next = { ...options };
  if (wanted.budget !== undefined && !explicit("perFix")) next.perFix = String(wanted.budget);
  if (wanted.model !== undefined && !explicit("model")) next.model = wanted.model;
  return next;
}
