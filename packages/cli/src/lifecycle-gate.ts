/**
 * Decides whether this run may send lifecycle events (first_run, update,
 * command_invoked, error_exit).
 *
 * The first-run notice is never shown for help, version, shell completion,
 * CI or machine-readable output, so those runs must not send lifecycle events
 * either. The exception is CI and machine output when the user has explicitly
 * chosen `analyticsLevel usage` in a settings file.
 */

import { QUIET_COMMANDS, wantsMachineOutput } from "./telemetry-notice.js";

const INFO_FLAGS = new Set(["-h", "--help", "-V", "--version"]);
const INFO_COMMANDS = new Set(["help", "completion", "completions", "__complete"]);

function truthy(value: string | undefined): boolean {
  const v = value?.trim().toLowerCase();
  return v !== undefined && v !== "" && v !== "0" && v !== "false" && v !== "no";
}

/** True for help, version, shell-completion and the quiet commands (`config`, `reports`, `workbench`). Never overridden by a setting. */
export function isInformationalInvocation(args: readonly string[], env: NodeJS.ProcessEnv = process.env): boolean {
  if (env["COMP_LINE"] !== undefined || env["COMP_POINT"] !== undefined) return true;
  // `config` is included so that `config set analyticsLevel off` on a fresh install writes nothing first.
  if (INFO_COMMANDS.has(args[0] ?? "") || QUIET_COMMANDS.has(args[0] ?? "")) return true;
  return args.some((arg) => INFO_FLAGS.has(arg));
}

export function lifecycleSuppressed(options: {
  args: readonly string[];
  /** True only when `analyticsLevel` was set to `usage` in a settings file. */
  explicitOptIn: boolean;
  env?: NodeJS.ProcessEnv;
}): boolean {
  const env = options.env ?? process.env;
  if (isInformationalInvocation(options.args, env)) return true;
  if ((truthy(env["CI"]) || wantsMachineOutput(options.args, env)) && !options.explicitOptIn) return true;
  return false;
}
