/**
 * Build a verifier spec from a finding's own PoC steps (pure).
 *
 * Only `shell` steps run: they execute inside the sandbox against a snapshot of
 * the scanned folder. `http`, `docker` and `note` steps never run here (an HTTP
 * step needs a live app and would need a network). A PoC is runnable only when
 * a shell step carries an observable expectation (`body-contains` or
 * `body-matches`) and that expectation is not simply written into the command,
 * so a PoC cannot "prove" itself by echoing the answer.
 */
import { isPinnedImage, type VerifySpec } from "../verifier/spec.js";
import type { PocStep } from "../shared/types.js";

export const POC_MAX_STEPS = 8;
export const POC_MAX_COMMAND = 4096;
export const POC_DEFAULT_TIMEOUT_SEC = 60;
export const POC_MAX_TIMEOUT_SEC = 300;
const MIN_EXPECT_LENGTH = 4;

export type PocPlan = { ok: true; spec: VerifySpec; stepIds: string[] } | { ok: false; reason: string };

const escapeRegex = (text: string): string => text.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");
const shellQuote = (text: string): string => `'${text.replace(/'/g, `'\\''`)}'`;

function safeCwd(cwd: string): boolean {
  return !!cwd && !cwd.includes("\0") && !cwd.includes("\\") && !cwd.startsWith("/") && !/^[A-Za-z]:/.test(cwd) && !cwd.split("/").some((part) => part === "..");
}

export function planPocSpec(steps: PocStep[] | undefined, options: { image: string | undefined; timeoutSec?: number }): PocPlan {
  if (!steps || steps.length === 0) return { ok: false, reason: "no-poc-steps" };
  const shell = steps.filter((s) => s.action.type === "shell");
  if (shell.length === 0) return { ok: false, reason: steps.some((s) => s.action.type === "http") ? "http-steps-need-a-running-app" : "no-runnable-steps" };
  if (shell.length > POC_MAX_STEPS) return { ok: false, reason: "too-many-steps" };
  if (!options.image) return { ok: false, reason: "no-sandbox-image" };
  if (!isPinnedImage(options.image)) return { ok: false, reason: "image-not-pinned-by-digest" };

  const commands: string[] = [];
  const raw: string[] = [];
  const needles: string[] = [];
  for (const step of shell) {
    const action = step.action as Extract<PocStep["action"], { type: "shell" }>;
    const cmd = action.cmd.trim();
    if (!cmd || cmd.length > POC_MAX_COMMAND || /\0/.test(cmd)) return { ok: false, reason: "unusable-command" };
    if (action.cwd !== undefined && !safeCwd(action.cwd)) return { ok: false, reason: "unsafe-cwd" };
    raw.push(cmd);
    commands.push(action.cwd ? `cd -- ${shellQuote(action.cwd)} && ${cmd}` : cmd);
    const expect = step.expect;
    if (expect?.type === "body-contains") {
      if (expect.text.trim().length < MIN_EXPECT_LENGTH) return { ok: false, reason: "expectation-too-weak" };
      needles.push(escapeRegex(expect.text));
    } else if (expect?.type === "body-matches") {
      if (!expect.pattern || expect.pattern.length > 512) return { ok: false, reason: "unusable-expectation" };
      try { new RegExp(expect.pattern); } catch { return { ok: false, reason: "unusable-expectation" }; }
      needles.push(expect.pattern);
    }
  }
  if (needles.length === 0) return { ok: false, reason: "no-observable-expectation" };
  for (const step of shell) {
    if (step.expect?.type === "body-contains" && raw.some((cmd) => cmd.includes((step.expect as { text: string }).text))) return { ok: false, reason: "expectation-written-in-command" };
  }

  const timeoutSec = Math.min(POC_MAX_TIMEOUT_SEC, Math.max(1, Math.floor(options.timeoutSec ?? POC_DEFAULT_TIMEOUT_SEC)));
  const regex = needles.map((n) => `(?=[\\s\\S]*?(?:${n}))`).join("");
  return {
    ok: true,
    stepIds: shell.map((s) => s.id),
    spec: {
      steps: commands.map((run, i) => ({ name: `poc-${i + 1}`, run })),
      image: options.image,
      network: "none",
      timeoutSec,
      success: { exit0: true, regex },
    },
  };
}
