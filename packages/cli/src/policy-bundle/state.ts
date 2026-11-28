/** The last accepted bundle version per signing key, kept in ~/.0/policy-bundle-state.json so an older bundle cannot be replayed. */
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homeStateDir } from "@0/engine/shared";
import { PolicyBundleError, type VerifiedBundle } from "./verify.js";

type State = Record<string, { version: number; digest: string }>;

export function policyBundleStatePath(home?: string): string { return join(homeStateDir(home), "policy-bundle-state.json"); }

function readState(path: string): State {
  if (!existsSync(path)) return {};
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw as State;
  } catch { /* fall through */ }
  // A damaged file must not silently reset the floor.
  throw new PolicyBundleError(`Policy bundle state ${path} is unreadable; fix or remove it to continue.`);
}

const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 10_000;

/** Run fn while holding an exclusive lock file (O_EXCL). A stale lock is taken over only by renaming it to a unique name, which only one process can win, and then creating the new lock with O_EXCL like everyone else. */
function withLock<T>(path: string, fn: () => T): T {
  const lock = `${path}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try { closeSync(openSync(lock, "wx", 0o600)); break; } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) {
          const taken = `${lock}.stale.${process.pid}.${randomBytes(6).toString("hex")}`;
          renameSync(lock, taken);
          // If what we moved was a fresh lock that replaced the stale one meanwhile, put it back when the slot is free.
          try { if (Date.now() - statSync(taken).mtimeMs <= LOCK_STALE_MS) linkSync(taken, lock); } catch { /* slot taken or file gone */ }
          try { unlinkSync(taken); } catch { /* already gone */ }
          continue;
        }
      } catch { continue; }
      if (Date.now() > deadline) throw new PolicyBundleError(`Policy bundle state is locked by another run (${lock}); remove it if no run is active.`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try { return fn(); } finally { try { unlinkSync(lock); } catch { /* already gone */ } }
}

function refuseIfNotNewer(state: State, bundle: VerifiedBundle): boolean {
  const last = state[bundle.keyId];
  if (last && (bundle.version < last.version || (bundle.version === last.version && bundle.digest !== last.digest))) {
    throw new PolicyBundleError(`Policy bundle version ${bundle.version} is not newer than the last accepted version ${last.version}; it was refused as a replay.`);
  }
  return !(last && last.version === bundle.version);
}

/** Refuse a version below the last accepted one (or the same version with different content), then record this one. The state is re-read under the lock and again right before the atomic write, and a stored version is never lowered. */
export function acceptPolicyBundle(bundle: VerifiedBundle, home?: string): void {
  const path = policyBundleStatePath(home);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  withLock(path, () => {
    if (!refuseIfNotNewer(readState(path), bundle)) return;
    // Last line of defence if the lock failed: read again just before writing, keep the maximum.
    const fresh = readState(path);
    if (!refuseIfNotNewer(fresh, bundle)) return;
    fresh[bundle.keyId] = { version: Math.max(bundle.version, fresh[bundle.keyId]?.version ?? 0), digest: bundle.digest };
    const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(fresh, null, 2)}\n`, { mode: 0o600 });
    renameSync(tmp, path);
  });
}
