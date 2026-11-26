/**
 * Opt in to the executed PoC without editing the environment by hand.
 *
 * The engine turns the feature on when `ZERO_POC_IMAGE` names a digest-pinned image. Two friendlier ways to set it:
 * `0security scan --poc-image <image@sha256:...>` for one scan, and `0security config set executedPocImage <image@sha256:...>`
 * for every scan. Precedence: the flag, then `ZERO_POC_IMAGE`, then the setting. A value that is not pinned by digest is
 * refused here with a usage error; the engine would also refuse it, but silently, and a typo should not look like "off".
 */
import { UsageError } from "./commands/output.js";
// Same rule as the engine's `isPinnedImage` (verifier/spec.ts), which the PoC planner applies again.
const isPinnedImage = (image: string): boolean => /^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$/.test(image);

export const POC_IMAGE_FORMAT = "name@sha256:<64 hex digits>, for example alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

/** The image to use for the executed PoC, or undefined when the feature stays off. Throws a UsageError for an unpinned image. */
export function resolvePocImage(flag: string | undefined, setting: string | undefined, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const fromFlag = flag?.trim();
  if (fromFlag) {
    if (!isPinnedImage(fromFlag)) throw new UsageError(`--poc-image must be pinned by digest (${POC_IMAGE_FORMAT}); tags are not accepted.`);
    return fromFlag;
  }
  if (env.ZERO_POC_IMAGE?.trim()) return undefined; // already set: the engine reads it as is
  const fromSetting = setting?.trim();
  if (!fromSetting) return undefined;
  if (!isPinnedImage(fromSetting)) throw new UsageError(`The executedPocImage setting must be pinned by digest (${POC_IMAGE_FORMAT}); fix it with \`0security config set executedPocImage <image>\`.`);
  return fromSetting;
}

/** Sets `ZERO_POC_IMAGE` for this process and the console it starts. Returns the image when it was set. */
export function applyPocImage(flag: string | undefined, setting: string | undefined, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const image = resolvePocImage(flag, setting, env);
  if (image) env.ZERO_POC_IMAGE = image;
  return image;
}
