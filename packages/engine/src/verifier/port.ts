/** Port the verifier runs steps through. Adapters: docker/podman, and a host adapter for explicit `--test-command` only. */

export type Probe = { ok: true; runtime: string } | { ok: false; reason: string };

/** Resource and filesystem limits for one container. Absent fields keep the runner's defaults. */
export interface ContainerLimits {
  pidsLimit?: number;
  /** Memory cap, like `512m`. Swap is capped to the same value. */
  memory?: string;
  /** CPU cap, like `1`. */
  cpus?: string;
  /** Size-capped tmpfs mounts, like `/tmp:rw,size=64m,noexec,nosuid`. */
  tmpfs?: string[];
  /**
   * Cap on writable storage, like `256m`. With `readOnlyRoot` it is the size of the tmpfs that holds the work folder,
   * which every daemon enforces. Without it, it caps the writable layer: only some storage drivers enforce that, and the
   * runner retries without it when the daemon refuses.
   */
  storageSize?: string;
  /**
   * Mount the root file system read-only. The work folder then lives on a tmpfs at `/sandbox/app` (its parent
   * `/sandbox` is also writable), and the snapshot is streamed in as a tar archive because `docker cp` refuses a
   * read-only root.
   */
  readOnlyRoot?: boolean;
  /** Never pull the image: it must already be on this machine, so a run makes no registry request. */
  pullNever?: boolean;
  /** Run even when the writable-layer cap cannot be applied. Off by default: the run is refused instead. */
  allowUnboundedStorage?: boolean;
}

export interface StepRequest {
  /** Digest-pinned image. Ignored by the host adapter. */
  image?: string;
  /** Directory holding the snapshot to verify. The adapter must not modify it. */
  dir: string;
  /** Runs first with network, then the network is cut before `command`. */
  setup?: string;
  command: string;
  network: "none" | "allowed";
  timeoutMs: number;
  signal?: AbortSignal;
  limits?: ContainerLimits;
}

export interface StepOutcome {
  exitCode: number | null;
  /** Combined stdout and stderr, unredacted; the runner redacts and tails it. */
  output: string;
  timedOut: boolean;
  durationMs: number;
  /** Set when the adapter could not run the step at all (image pull, runtime failure). */
  infraError?: string;
  /** Limits the adapter could not apply and ran without, only when the request allowed it. */
  limitsNotApplied?: string[];
}

export interface ContainerRunner {
  readonly isolation: "container" | "host";
  probe(): Promise<Probe>;
  run(request: StepRequest): Promise<StepOutcome>;
}
