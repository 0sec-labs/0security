import { spawn } from "node:child_process";
import { assertEgressAllowed } from "@0/engine";
import type { HostRun } from "./index.js";

/** Run `gh` with these arguments (no shell) and an optional request body on standard input. */
export const runGh: HostRun = (args, input) => new Promise((resolve, reject) => {
  try { assertEgressAllowed("GitHub (gh)"); } catch (error) { reject(error); return; }
  const child = spawn("gh", args, { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = ""; let stderr = "";
  child.stdout.on("data", chunk => { stdout += String(chunk); });
  child.stderr.on("data", chunk => { stderr += String(chunk); });
  child.on("error", reject);
  child.on("close", code => code === 0 ? resolve(stdout) : reject(new Error((stderr || stdout).trim().split("\n")[0] || `gh exited with ${code}`)));
  child.stdin.end(input ?? "");
});
