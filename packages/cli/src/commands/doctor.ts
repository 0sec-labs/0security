import type { Command } from "commander";
import chalk from "chalk";
import { getRuntimeAvailability } from "../utils.js";
import { isNpmStyleInstall, NPM_MIGRATION_HINT } from "../utils/install-origin.js";

export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor")
    .description("Check local runtime prerequisites and suggest the next command")
    .option("--discard-reports", "Delete crash reports waiting for review on this computer")
    .option("--json", "Print JSON")
    .action(async (options: { discardReports?: boolean; json?: boolean }, command: Command) => {
      if (command.args.length) throw new Error(`Unknown check "${command.args[0]}". Use upgrade, workbench or checks, or no argument for the summary.`);
      const pending = await import("../state/pending-diagnostics.js");
      if (options.discardReports) {
        const removed = pending.discardPendingReports();
        console.log(`Discarded ${removed} crash report${removed === 1 ? "" : "s"}. Nothing was sent.`);
        return;
      }
      const { getRuntimeMetadata } = await import("../state/runtime.js");
      const { hasApiKey, availableRuntimes, apiRuntime } = await getRuntimeAvailability();
      const runtime = getRuntimeMetadata();
      const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
      const hasSupportedNode = nodeMajor >= 24;

      const waiting = pending.listPendingReports().length;
      const { detectSandbox, sandboxMode } = await import("@0/engine");
      const sandbox = detectSandbox();
      const sandboxSetting = sandboxMode();
      if (options.json) {
        const problem = !hasSupportedNode ? "Upgrade to Node 24+." : apiRuntime.configured && !apiRuntime.valid ? (apiRuntime.error ?? "The configured provider is unusable.") : !hasApiKey ? "No model is connected. Run `0security models connect`." : undefined;
        console.log(JSON.stringify({
          version: runtime.cliVersion, channel: runtime.releaseChannel, runtime: `${runtime.engine} ${runtime.engineVersion}`, platform: runtime.platform, arch: runtime.arch,
          node: { ok: hasSupportedNode, version: process.version },
          model: { connected: hasApiKey, provider: hasApiKey ? apiRuntime.providerLabel : null },
          cliProviders: availableRuntimes, crashReportsWaiting: waiting,
          sandbox: { mode: sandboxSetting.ok ? sandboxSetting.mode : null, ...(sandboxSetting.ok ? {} : { error: sandboxSetting.error }), backend: sandbox.backend, macosSandboxExec: sandbox.seatbelt, bwrap: sandbox.bwrap, docker: sandbox.docker, ...(sandbox.backend ? {} : { reason: sandbox.reason }) }, ok: problem === undefined, ...(problem ? { next: problem } : {}),
        }, null, 2));
        return;
      }
      console.log("");
      console.log(chalk.red.bold("  ◆ 0") + chalk.gray(" doctor"));
      console.log("");
      console.log(`  CLI version   v${runtime.cliVersion} [${runtime.releaseChannel}]`);
      console.log(`  Runtime       ${runtime.engine} ${runtime.engineVersion}`);
      console.log(`  Platform      ${runtime.platform}  ${runtime.arch}`);
      console.log(`  Node.js       ${hasSupportedNode ? chalk.green("ok") : chalk.red("bad")}  ${process.version}`);
      const apiStatus = hasApiKey
        ? `${chalk.yellow("configured")}  ${apiRuntime.providerLabel}`
        : apiRuntime.configured
          ? `${chalk.red("bad")}  ${apiRuntime.providerLabel}`
          : `${chalk.yellow("missing")}  not configured`;
      console.log(`  API provider  ${apiStatus}`);
      console.log(`  CLI providers  ${availableRuntimes.length > 0 ? chalk.yellow("found") : chalk.yellow("missing")}  ${availableRuntimes.join(", ") || "none"}`);
      const sandboxLine = (name: string, tool: { present: boolean; usable?: boolean; detail: string }): string =>
        `  ${name.padEnd(14)}${tool.present ? (tool.usable === false ? chalk.red("blocked") : chalk.green("found")) : chalk.gray("missing")}  ${tool.detail}`;
      console.log(`  Sandbox       ${sandbox.backend ? chalk.green("available") : chalk.yellow("unavailable")}  ZERO_SANDBOX=${sandboxSetting.ok ? sandboxSetting.mode : chalk.red("invalid")}${sandbox.backend ? ` (${sandbox.backend})` : ` (${sandbox.reason})`}`);
      console.log(sandboxLine("sandbox-exec", sandbox.seatbelt));
      console.log(sandboxLine("bwrap", sandbox.bwrap));
      console.log(sandboxLine("docker", sandbox.docker));
      console.log("");
      if (isNpmStyleInstall()) {
        console.log(chalk.yellow(`  ${NPM_MIGRATION_HINT}`));
        console.log("");
      }
      if (waiting > 0) {
        console.log(`  ${waiting} crash report${waiting === 1 ? " is" : "s are"} waiting for review: open the web console (0security) → Settings → Feedback, or discard with 0security config doctor --discard-reports`);
        console.log("");
      }

      if (!hasSupportedNode) {
        console.log(chalk.red("  Upgrade to Node 24+ before running 0."));
      } else if (apiRuntime.configured && !apiRuntime.valid && apiRuntime.error) {
        console.log(chalk.red("  API provider is configured but unusable."));
        console.log(chalk.gray(`  ${apiRuntime.error.split("\n").join("\n  ")}`));
      } else if (hasApiKey) {
        console.log(chalk.yellow("  Ready. The first request verifies credentials."));
        console.log(chalk.gray("  Open the console with: 0security     Run one prompt with: 0security -p \"<prompt>\""));
      } else {
        console.log(chalk.yellow("  No model is connected. Run `0security models connect` to see providers, then `0security models connect <provider> --key-env <VAR>`."));
      }
      console.log("");
    });
}
