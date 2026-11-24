/**
 * `0 findings reproduce`: run a finding's proposed recipe against a local copy of the app, in a container with the
 * network off, and record what happened next to the finding.
 *
 * Experimental. The start command comes from the operator (`--start`) or the built-in `node server.js`. Nothing in the
 * repository is read as instructions. The recipe never touches a live URL: the request goes to the loopback inside
 * the container. A result of not reproduced never means the code is safe.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import type { Command } from "commander";
import { OciRunner, isGitRepo, isPinnedImage, reproduceFinding, snapshotHead, type ContainerRunner } from "@0/engine";
import { reproductionLine, type FindingReproduction, type ReproductionResult } from "@0/engine/shared";
import { osecDB, resolveOsecDbPath } from "@0/engine/storage";
import { resolveFindingId } from "../finding-id.js";
import { rowReproduction } from "../finding-reproduction.js";
import { finishWithError, UsageError } from "./output.js";

const run = promisify(execFile);

export interface ReproduceOptions { folder?: string; image?: string; start?: string; dbPath?: string; json?: boolean }

export interface ReproduceDeps {
  out(text: string): void;
  err(text: string): void;
  runner(): ContainerRunner;
  /** Full commit id of HEAD and whether the working tree has uncommitted changes. */
  head(folder: string): Promise<{ commit: string; dirty: boolean } | undefined>;
  /** A copy of the committed tree. The caller cleans it up. */
  snapshot(folder: string): Promise<{ dir: string; cleanup(): void }>;
}

const defaults: ReproduceDeps = {
  out: (text) => process.stdout.write(`${text}\n`),
  err: (text) => process.stderr.write(`${text}\n`),
  runner: () => new OciRunner(),
  async head(folder) {
    if (!(await isGitRepo(folder))) return undefined;
    const commit = (await run("git", ["-C", folder, "rev-parse", "HEAD"], { timeout: 10_000 })).stdout.trim();
    const dirty = (await run("git", ["-C", folder, "status", "--porcelain"], { timeout: 30_000 })).stdout.trim().length > 0;
    return { commit, dirty };
  },
  snapshot: (folder) => snapshotHead(folder),
};

export interface ReproduceOutcome { findingId: string; result: ReproductionResult; stored: boolean; line: string; note?: string }

export async function runReproduce(id: string, options: ReproduceOptions, deps: ReproduceDeps = defaults): Promise<ReproduceOutcome> {
  if (!options.image || !isPinnedImage(options.image)) throw new UsageError("--image must be pinned by digest, like node:24-bookworm-slim@sha256:<64 hex digits>. Tags are not accepted.");
  const folder = resolve(options.folder ?? ".");
  const db = new osecDB(resolveOsecDbPath(options.dbPath));
  try {
    let row: Record<string, unknown> | undefined;
    try { row = resolveFindingId(db.listFindings({ limit: 5000 }) as unknown as Array<{ id: string } & Record<string, unknown>>, id); }
    catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
    if (!row) throw new UsageError(`Finding '${id}' not found.`);
    const findingId = String(row.id);
    const rep = rowReproduction(row as { reproduction?: unknown; pocSteps?: unknown });
    const head = await deps.head(folder);
    if (!head) throw new UsageError(`${folder} is not a Git repository. Reproduction runs on a committed copy.`);

    const snapshot = await deps.snapshot(folder);
    let result: ReproductionResult;
    try {
      result = await reproduceFinding({ proof: rep?.proof, snapshotDir: snapshot.dir, commit: head.commit, runner: deps.runner(), image: options.image, ...(options.start ? { start: options.start } : {}) });
    } finally { snapshot.cleanup(); }

    // An error says nothing about the finding, so it never replaces an earlier result.
    const stored = result.status !== "error";
    if (stored) db.setFindingReproduction(findingId, { ...(rep?.proof ? { proof: rep.proof } : {}), result } as FindingReproduction);
    const note = head.dirty ? "The run used the committed tree. Uncommitted changes are not included." : undefined;
    return { findingId, result, stored, line: reproductionLine(result), ...(note ? { note } : {}) };
  } finally { db.close(); }
}

export function registerFindingsReproduceCommand(parent: Command, deps: ReproduceDeps = defaults): void {
  parent.command("reproduce")
    .description("Experimental: run a finding's proposed steps against a local copy of the app in a container with the network off, and record the result")
    .argument("<id>", "Finding ID (full or prefix)")
    .requiredOption("--image <image>", "Container image pinned by digest, with node in it, like node:24-bookworm-slim@sha256:<64 hex digits>")
    .option("--start <command>", "Command that starts the app inside the container (default: node server.js). It comes from you, never from the repository.")
    .option("--folder <path>", "Git repository holding the app (default: current directory)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--json", "Print JSON")
    .addHelpText("after", "\nOnly path traversal on an HTTP route of a Node app is supported. The request goes to the loopback inside the container, never to a live URL. Not reproduced does not mean safe: it means this recipe did not work on this commit.")
    .action(async (id: string, options: ReproduceOptions) => {
      try {
        const outcome = await runReproduce(id, options, deps);
        if (options.json) { deps.out(JSON.stringify(outcome, null, 2)); return; }
        deps.out(outcome.line);
        deps.out(outcome.stored ? "Recorded next to the finding. Severity, status and triage are unchanged." : "Nothing was recorded.");
        if (outcome.note) deps.out(outcome.note);
        if (outcome.result.status === "error" || outcome.result.status === "inconclusive") process.exitCode = 1;
      } catch (error) { finishWithError(error, deps, options.json); }
    });
}

