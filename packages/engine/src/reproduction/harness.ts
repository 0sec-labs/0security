/**
 * The reproduction harness. It runs a proposed recipe against a local copy of the app inside the container runner
 * and writes the result record. It never touches a live URL: the only network the recipe can use is the loopback
 * inside the container, and the container has no other network. The model cannot call it and cannot set its result.
 *
 * What a result means: "reproduced" says the app as run returned the canary, a file planted fresh outside the served
 * folder, in a response to the replayed request. "not-reproduced" says it did not, for this one request on this one
 * commit. Neither says anything certain about the code, and an app built to lie can forge a hit. A run outside the
 * container is marked unisolated and can never be reproduced.
 */
import { createHash, randomBytes } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import type { ContainerLimits, ContainerRunner } from "../verifier/port.js";
import { redactLog } from "../verifier/redact.js";
import { imageDigest, isPinnedImage } from "../verifier/spec.js";
import { tailOf } from "../verifier/result.js";
import { REPRODUCTION_HARNESS, parseReproductionResult, type ReproProof, type ReproductionResult, type ReproductionStatus } from "../shared/reproduction.js";
import { DEFAULT_PORT, DEFAULT_START, PATH_TRAVERSAL_CLASS, buildPathTraversalScript, planPathTraversal } from "./path-traversal.js";

export interface ReproduceInput {
  proof: ReproProof | undefined;
  /** Snapshot of the committed tree to run. The caller makes it; the harness never reads it as instructions. */
  snapshotDir: string;
  /** Full commit id of that tree. */
  commit: string;
  runner: ContainerRunner;
  /** Digest-pinned image with node in it. */
  image: string;
  /** Start command from the operator. Never read from the repository. Default: `node server.js`. */
  start?: string;
  port?: number;
  /**
   * Allow a runner that is not a container (a host runner or a stand-in). Only tests set this. The result is marked
   * unisolated and cannot be reproduced or not-reproduced. The command line never sets it.
   */
  allowUnisolated?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
  now?: () => Date;
  randomHex?: (bytes: number) => string;
}

const MAX_START = 500;

/**
 * Limits for every reproduction container: the app is untrusted code. Processes, memory, CPU and writable storage are
 * capped, /tmp is a small tmpfs, and the run has a wall-clock timeout. The root file system is not read-only: the
 * snapshot is copied into the container and the canary is planted in the app folder's parent, both of which need
 * writable space, and `docker cp` cannot write into a tmpfs.
 */
export const REPRODUCTION_LIMITS: ContainerLimits = {
  pidsLimit: 128,
  memory: "512m",
  cpus: "1",
  tmpfs: ["/tmp:rw,size=64m,noexec,nosuid"],
  storageSize: "256m",
};
export const REPRODUCTION_TIMEOUT_MS = 120_000;

/** SHA-256 over the relative paths and contents of every file under `dir`, in a fixed order. Symlinks hash their target text. */
export function hashAppFiles(dir: string): string {
  const hash = createHash("sha256");
  const walk = (rel: string): void => {
    for (const entry of readdirSync(join(dir, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const next = rel ? `${rel}/${entry.name}` : entry.name;
      const full = join(dir, next);
      if (entry.isDirectory()) walk(next);
      else if (lstatSync(full).isSymbolicLink()) hash.update(`link ${next} ${readlinkSync(full)}\n`);
      else if (entry.isFile()) hash.update(`file ${next} ${createHash("sha256").update(readFileSync(full)).digest("hex")}\n`);
    }
  };
  walk("");
  return hash.digest("hex");
}

export async function reproduceFinding(input: ReproduceInput): Promise<ReproductionResult> {
  const now = input.now ?? (() => new Date());
  const hex = input.randomHex ?? ((n: number) => randomBytes(n).toString("hex"));
  const startedAt = now().toISOString();
  const start = input.start ?? DEFAULT_START;
  const nonce = hex(16);

  const done = (status: ReproductionStatus, reason: string, extra: Partial<ReproductionResult> = {}): ReproductionResult => {
    const record = {
      schemaVersion: 1, harness: REPRODUCTION_HARNESS, status, reason, startedAt, finishedAt: now().toISOString(), logTail: "", ...extra,
    };
    // The record is built through the same parser that guards storage: an incomplete record cannot claim a result.
    return parseReproductionResult(record) ?? { schemaVersion: 1, harness: REPRODUCTION_HARNESS, status: "error", reason: "incomplete-record", startedAt, finishedAt: record.finishedAt, logTail: "" };
  };

  if (!input.proof) return done("inconclusive", "no-proposed-steps");
  if (!isPinnedImage(input.image)) return done("error", "image-not-pinned-by-digest");
  if (!start || start.length > MAX_START || /[\0\r\n]/.test(start)) return done("error", "unusable-start-command");
  const isolated = input.runner.isolation === "container";
  if (!isolated && !input.allowUnisolated) return done("error", "no-container-isolation");
  const planned = planPathTraversal(input.proof);
  if (!planned.ok) return done("inconclusive", planned.reason);

  const probe = await input.runner.probe();
  if (!probe.ok) return done("error", "no-container-runtime", { logTail: tailOf(redactLog(probe.reason)) });

  const port = input.port ?? DEFAULT_PORT;
  let command: string;
  try { command = buildPathTraversalScript({ start, port, nonce, plan: planned.plan }); }
  catch (error) { return done("error", "recipe-could-not-be-built", { logTail: tailOf(redactLog(error instanceof Error ? error.message : String(error))) }); }

  const recipeSha256 = createHash("sha256").update(JSON.stringify({ class: PATH_TRAVERSAL_CLASS, start, port, plan: planned.plan, image: input.image })).digest("hex");
  let appSha256: string;
  try { appSha256 = hashAppFiles(input.snapshotDir); }
  catch (error) { return done("error", "app-files-could-not-be-hashed", { logTail: tailOf(redactLog(error instanceof Error ? error.message : String(error))) }); }
  const outcome = await input.runner.run({
    image: input.image, dir: input.snapshotDir, command, network: "none", timeoutMs: input.timeoutMs ?? REPRODUCTION_TIMEOUT_MS, limits: REPRODUCTION_LIMITS,
    ...(input.signal ? { signal: input.signal } : {}),
  });
  const notApplied = outcome.limitsNotApplied?.length ? `limits not applied: ${outcome.limitsNotApplied.join(", ")}\n` : "";
  const logTail = tailOf(redactLog(`${notApplied}${tailOf(outcome.output, 4096)}`));
  const common = { commit: input.commit, imageDigest: imageDigest(input.image), isolation: (isolated ? "container" : "unisolated") as "container" | "unisolated", network: "loopback" as const, recipeSha256, appSha256, logTail };

  if (outcome.infraError) return done("error", "runner-failed", { logTail: tailOf(redactLog(outcome.infraError)) });
  if (outcome.timedOut) return done("inconclusive", "timeout", common);

  // Only text before the app log counts: the app's own output is never read as a result.
  const clientPart = outcome.output.split("--- app log ---")[0] ?? "";
  const line = clientPart.split("\n").find((l) => l.startsWith(`0REPRO-${nonce} `));
  if (!line) return done("inconclusive", "no-client-result", common);
  let seen: { listening?: boolean; token?: string; control?: { hit?: boolean } | null; attack?: { hit?: boolean } | null };
  try { seen = JSON.parse(line.slice(`0REPRO-${nonce} `.length)); } catch { return done("inconclusive", "unreadable-client-result", common); }
  const alive = clientPart.includes(`0ALIVE-${nonce} 1`);

  if (!seen.listening) return done("inconclusive", "app-did-not-start", common);
  if (seen.control?.hit) return done("inconclusive", "canary-served-without-traversal", common);
  if (!seen.attack) return done("inconclusive", "no-response-to-the-request", common);
  if (!alive) return done("inconclusive", "app-exited-during-the-run", common);
  if (typeof seen.token !== "string" || !/^[0-9a-f]{32}$/.test(seen.token)) return done("inconclusive", "unreadable-client-result", common);
  const observed = seen.attack.hit === true;
  if (!isolated) return done("inconclusive", observed ? "unisolated-run-canary-observed" : "unisolated-run-canary-absent", { ...common, canary: { token: seen.token, observed } });
  return done(observed ? "reproduced" : "not-reproduced", observed ? "canary-observed" : "canary-absent", { ...common, canary: { token: seen.token, observed } });
}
