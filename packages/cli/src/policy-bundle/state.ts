/** The last accepted bundle version per signing key, kept in ~/.0/policy-bundle-state.json so an older bundle cannot be replayed. */
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
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

/** Run fn while holding an exclusive lock file (O_EXCL). A lock older than the stale limit is taken over. */
function withLock<T>(path: string, fn: () => T): T {
  const lock = `${path}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try { closeSync(openSync(lock, "wx", 0o600)); break; } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try { if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) { unlinkSync(lock); continue; } } catch { continue; }
      if (Date.now() > deadline) throw new PolicyBundleError(`Policy bundle state is locked by another run (${lock}); remove it if no run is active.`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try { return fn(); } finally { try { unlinkSync(lock); } catch { /* already gone */ } }
}

/** Refuse a version below the last accepted one (or the same version with different content), then record this one. The read, check and write happen under one lock, so a lower version never overwrites a higher one. */
export function acceptPolicyBundle(bundle: VerifiedBundle, home?: string): void {
  const path = policyBundleStatePath(home);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  withLock(path, () => {
    const state = readState(path);
    const last = state[bundle.keyId];
    if (last && (bundle.version < last.version || (bundle.version === last.version && bundle.digest !== last.digest))) {
      throw new PolicyBundleError(`Policy bundle version ${bundle.version} is not newer than the last accepted version ${last.version}; it was refused as a replay.`);
    }
    if (last && last.version === bundle.version) return;
    state[bundle.keyId] = { version: bundle.version, digest: bundle.digest };
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    renameSync(tmp, path);
  });
}
