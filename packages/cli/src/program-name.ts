/**
 * The command name to show in help and usage text: `0security` when the program was started under
 * that name, otherwise `0`. The name comes from `argv0`, the path the user typed, because a compiled
 * binary's `execPath` is already resolved to the real file and would name the target of the `0` symlink.
 * `ZERO_PROGRAM_NAME=0security|0` forces the name; it exists for tests and for generating the docs, not for users.
 */
export function invokedProgramName(
  argv0: string | undefined = process.argv0,
  env: Record<string, string | undefined> = process.env,
): "0security" | "0" {
  const forced = env["ZERO_PROGRAM_NAME"];
  if (forced === "0security" || forced === "0") return forced;
  const name = (argv0 ?? "").split(/[\\/]/).pop()!.replace(/\.exe$/i, "").toLowerCase();
  return name === "0security" ? "0security" : "0";
}
