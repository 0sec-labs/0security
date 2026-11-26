# Fix verification

"Verified" is a recorded result, not something the agent says in its reply.

- A skill declares `verify:` (steps, a digest-pinned image, network `none` or `allowed`, timeout, success as exit 0, a regex or a baseline comparison `no-worse` or `improves`, and an optional canary). Code: `packages/engine/src/verifier/`, with a pure spec, result and claim gate behind a `ContainerRunner` port. Adapters: Docker or podman (the snapshot is copied in, never mounted; capabilities dropped; the network is off, or disconnected after an optional setup step) and a host adapter used only for an explicit `--test-command` with no image.
- Result: `status` (pass, fail, not-run, error), `reason`, `command`, `imageDigest`, `isolation`, `durationMs`, a redacted 2 KB `logTail`, `canary` (ok, missing, n/a) and `baseline` `{before, after}`. A missing canary is `fail` with reason `detector-did-not-run`; no container runtime is `not-run`; only a container run that passed is "Verified".
- Gate: a thread started with `--skill` for a skill that declares `verify` ends with `Verified by: ...` or `Not verified: ...`; a fixed or verified claim without a pass is marked as not backed by a check and `threads start --wait` exits 1.
- Only built-in skills run a verifier; one declared by a community `SKILL.md` is shown but not run.

## Executed PoC for high and critical findings

After a high or critical finding is saved, the harness (not the model) tries to run a PoC built from the finding's own steps, through the same `runVerifier` and `ContainerRunner` port, on a snapshot of the scanned folder. Code: `packages/engine/src/executed-poc/`; record and wording: `packages/engine/src/shared/executed-poc.ts`.

- Outcomes, stored on the finding (`executedPoc`) with the run record: `executed-proven` (a container run passed and the expected output appeared), `executed-failed` (it ran and the expectation did not hold; not proof of safety), `static-only` (nothing was proven by execution). A high or critical finding with no record shows as `static-only`; it is never shown as proven.
- Only `shell` steps run. A PoC needs an observable expectation (`body-contains` or `body-matches`) that is not written into the command. HTTP steps are static-only: they need a live app.
- Sandbox: digest-pinned image, network off, the reproduction resource limits, a snapshot of the folder only. A host runner is refused. A run that cannot finish (no runtime, timeout, infra error) is static-only.
- Budget: at most `ZERO_POC_MAX_RUNS` runs (default 3), `ZERO_POC_TIMEOUT_SEC` per run (default 60, max 300) and `ZERO_POC_MAX_TOTAL_SEC` in total (default 300) per scan.
- Off unless `ZERO_POC_IMAGE` names a digest-pinned image. Shown in `findings list`, `findings show`, and in the JSON, Markdown, HTML and SARIF exports.
