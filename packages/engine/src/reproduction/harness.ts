/**
 * The reproduction harness. It runs a proposed recipe against a local copy of the app inside the container runner
 * and writes the result record. It never touches a live URL: the only network the recipe can use is the loopback
 * inside the container, and the container has no other network. The model cannot call it and cannot set its result.
 *
 * What a result means: "reproduced" says the canary file, planted outside the served folder, came back in a response
 * to the replayed request. "not-reproduced" says it did not, for this one request on this one commit. It does not say
 * the code is safe.
 */
import { createHash, randomBytes } from "node:crypto";
import type { ContainerRunner } from "../verifier/port.js";
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
  timeoutMs?: number;
  signal?: AbortSignal;
  now?: () => Date;
  randomHex?: (bytes: number) => string;
}

const MAX_START = 500;

export async function reproduceFinding(input: ReproduceInput): Promise<ReproductionResult> {
  const now = input.now ?? (() => new Date());
  const hex = input.randomHex ?? ((n: number) => randomBytes(n).toString("hex"));
  const startedAt = now().toISOString();
  const start = input.start ?? DEFAULT_START;
  const token = hex(16);
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
  if (input.runner.isolation !== "container") return done("error", "no-container-isolation");
  const planned = planPathTraversal(input.proof);
  if (!planned.ok) return done("inconclusive", planned.reason);

  const probe = await input.runner.probe();
  if (!probe.ok) return done("error", "no-container-runtime", { logTail: tailOf(redactLog(probe.reason)) });

  const port = input.port ?? DEFAULT_PORT;
  let command: string;
  try { command = buildPathTraversalScript({ start, port, token, nonce, plan: planned.plan }); }
  catch (error) { return done("error", "recipe-could-not-be-built", { logTail: tailOf(redactLog(error instanceof Error ? error.message : String(error))) }); }

  const recipeSha256 = createHash("sha256").update(JSON.stringify({ class: PATH_TRAVERSAL_CLASS, start, port, plan: planned.plan, image: input.image })).digest("hex");
  const outcome = await input.runner.run({
    image: input.image, dir: input.snapshotDir, command, network: "none", timeoutMs: input.timeoutMs ?? 120_000,
    ...(input.signal ? { signal: input.signal } : {}),
  });
  const logTail = tailOf(redactLog(tailOf(outcome.output, 4096)));
  const common = { commit: input.commit, imageDigest: imageDigest(input.image), isolation: "container" as const, network: "loopback" as const, recipeSha256, logTail };

  if (outcome.infraError) return done("error", "runner-failed", { logTail: tailOf(redactLog(outcome.infraError)) });
  if (outcome.timedOut) return done("inconclusive", "timeout", common);

  const line = outcome.output.split("\n").find((l) => l.startsWith(`0REPRO-${nonce} `));
  if (!line) return done("inconclusive", "no-client-result", common);
  let seen: { listening?: boolean; control?: { hit?: boolean } | null; attack?: { hit?: boolean } | null };
  try { seen = JSON.parse(line.slice(`0REPRO-${nonce} `.length)); } catch { return done("inconclusive", "unreadable-client-result", common); }
  const alive = outcome.output.includes(`0ALIVE-${nonce} 1`);

  if (!seen.listening) return done("inconclusive", "app-did-not-start", common);
  if (seen.control?.hit) return done("inconclusive", "canary-served-without-traversal", common);
  if (!seen.attack) return done("inconclusive", "no-response-to-the-request", common);
  if (!alive) return done("inconclusive", "app-exited-during-the-run", common);
  const observed = seen.attack.hit === true;
  return done(observed ? "reproduced" : "not-reproduced", observed ? "canary-observed" : "canary-absent", { ...common, canary: { token, observed } });
}
