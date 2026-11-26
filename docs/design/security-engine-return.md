# Bringing back the security engine, inside the current architecture

Status: plan, not started. Written 2026-11-25 against `main` at `b54750fd`. Owner: Doruk. Each workstream below is sized and written so that one agent session can pick it up alone.

#409 removed the security engine on 2026-11-17 and archived it at `5787484d` (branch `archive/security-engine`). Since then a lot has come back in the new shape:
- the GitHub Action
- `0 scan` as a thread
- `findings reproduce`
- declared scope
- `enterprise/` behind a licence key

This plan covers what is still missing. It brings each missing piece back **without restoring the second system**: no native tool packs, no fixed pipeline, and no "Verified" that the model can set.

Read first, in this order:
1. [tool-philosophy.md](tool-philosophy.md)
2. [scan-as-a-thread.md](scan-as-a-thread.md)
3. [fix-verification.md](fix-verification.md)
4. [extension-architecture.md](extension-architecture.md)
5. [architecture.md](architecture.md)

## Rules every workstream follows

1. **No new native tools.** The tool list in `packages/engine/src/agent/tools/index.ts` (`TOOL_REGISTRY_ORDER`) stays as it is.
   - New capability goes in as an **extension**: MCP servers plus skills, pinned to a commit and approved per revision.
   - Or as a **skill**: method as text, plus scripts run through `bash`.
   - Or as **harness code** that the model cannot call.
   - The code-index tools (#664) show the pattern: loaded only through a skill.
2. **Only harness code sets Verified or Reproduced.**
   - The model proposes. A verifier spec (`packages/engine/src/verifier/spec.ts`) or the reproduction harness (`packages/engine/src/reproduction/harness.ts`) decides.
   - The command comes from a skill or extension the operator approved, never from the repository, the finding or the model.
3. **Never run model-authored commands as proof.** The archived replay runner (`verify/replay-runner.ts` at `5787484d`) ran the finding's `pocSteps` through `/bin/sh`. Don't bring that back. Follow `reproduction/path-traversal.ts` instead:
   - the recipe is built into the harness
   - the model supplies one parameter
   - success is a canary that the harness plants fresh inside the container
4. **Containers stay as locked down as they are now:**
   - digest-pinned images
   - `--network none` unless the spec declares otherwise
   - `--cap-drop ALL`, `no-new-privileges`, a read-only root, and capped tmpfs, pids and memory
   - see `verifier/docker-runner.ts` and `REPRODUCTION_LIMITS`

   Anything that loosens this (a device, a network) is a declared field. It shows up in the approval prompt and is recorded in the result.
5. **Port method, not machinery.** Archived code is reference material. Read it with `git show 5787484d:<path>`. Copy a function only when a test here needs it. Most of the kernel engine comes back as skill text.
6. **`enterprise/` holds the paid parts.** Workstream 3 lives there and needs a licence feature flag. Everything else is open core. "Features already in the open core will not move into `enterprise/`" (server-mode docs), so put each piece in the right place the first time.
7. **Checks before every PR.** Run `pnpm lint`, `pnpm check:architecture`, `pnpm build` and `pnpm test`. Container and VM tests are `*.integration.test.ts`. Run them on a machine with Docker or podman, and say in the PR whether you did.
8. **Docs move with code.** Use the plain style of `docs/src/content/docs`. Every limit gets written down where the feature is described.

## Order and dependencies

```
W0 extension verify specs ──┬──> W4 kernel extension
                            ├──> W3 first-party extensions (attack-path, recon verify)
W1 more reproduction classes ┴──> W2 pentest pack (enterprise)
W5 improvement loop          (independent; needs scripts/bench only)
W6 CVSS 4 + advisory output  (independent)
```

W0, W1, W5 and W6 can start in parallel. Give each one its own worktree and branch.

---

## W0. Extensions can declare a verifier that runs

**Why.** An extension can already declare `verify` (`plugins/extensions/core/manifest.ts:26,50,140`). But the path is only shown in the capabilities list (`core/capabilities.ts:31,48,74`) and nothing ever runs it. `packages/cli/src/web/thread-verifier.ts:4,24-30` only resolves **built-in** skills. W4 (proving a kernel patch removes the crash) and any third-party "prove it" pack need this.

**Do:**
1. Define the file format.
   - `verify` in `extension.json` points to a YAML or JSON file inside the extension tree.
   - Its content is a `VerifySpec`, parsed by the same parser as skill frontmatter (`verifier/spec.ts`).
   - Reject a spec that fails `isPinnedImage` or exceeds `MAX_TIMEOUT_SEC` or `MAX_COMMAND`.
2. Change how a verifier is resolved.
   - Change `resolveThreadVerifier(id)` to accept `builtin/<skill>` (unchanged) or `ext/<extension>/<skill>`.
   - For the extension form, load the spec only from an **installed, enabled extension at its approved revision**, after the tree-hash check passes (`plugins/extensions/adapters/fs-store.ts` and `git-source.ts`).
   - Store the extension name and the 40-character commit in `VerifierResult`. Add optional fields with `schemaVersion` kept at 1.
3. Add a `devices` field for KVM.
   - Add an optional `devices: ["kvm"]` to `VerifySpec`. The only value allowed now is `kvm`, which maps to `--device /dev/kvm` in `docker-runner.ts`.
   - Require an operator opt-in: env `ZERO_VERIFY_ALLOW_DEVICES=kvm`, or a CLI flag.
   - Show it in the extension's approval text (`capabilities.ts`, "adds rules: verifier (…), needs /dev/kvm").
   - Without the opt-in, the result is `not-run` with reason `device-not-allowed`.
4. Make it reachable from where threads start. `missions.ts` and the console gateway (`console-gateway.ts`, the `verifySkill` path) should accept the new id form. Sentinels use the same path.
5. Docs: update `docs/src/content/docs/extensions.md` and `skills.md`, which says "Today only built-in skills run their check".

**Acceptance:**
- A test extension with a `verify` spec runs end to end through a thread and prints `Verified by: … passed` or `Not verified: …`.
- Changing the extension's tree (a new commit, not yet approved) means the verifier does not run.
- `devices: ["kvm"]` without the opt-in gives `not-run`.
- Unit tests cover parse and resolve. One integration test uses a real container.

---

## W1. More reproduction classes in `findings reproduce`

**Why.** `findings reproduce` (#619, #673) covers only one class: path traversal on a Node app started with `node server.js`. Everything else carries "Proposed steps, not run". This is the gap behind any "proves each bug" claim, and W2 builds on it.

**Current shape** (keep it):
- `packages/engine/src/reproduction/harness.ts` (`reproduceFinding`, `REPRODUCTION_LIMITS`)
- `reproduction/path-traversal.ts` (built-in recipe, `CANARY_PLACEHOLDER`, a control request)
- `packages/cli/src/commands/findings-reproduce.ts`
- result type in `packages/engine/src/shared/reproduction.ts`
- bench fixtures in `scripts/bench/repro-fixtures`, scored by `scripts/bench/verify-score.mjs`

**Do:**
1. Split the harness into a **class registry**. Each class owns four things:
   - which part of the finding's proof it reads (one parameter)
   - the canary it plants
   - the attack request plus a control request
   - the success rule

   Path traversal becomes the first entry. Each class is one file in `reproduction/`.
2. Add classes, in this order. Each needs a canary that the app cannot produce without the bug:
   - **Command injection (HTTP).** The harness picks a random marker path. The proof's payload has a placeholder that is replaced with `touch <marker>`, or a platform-safe equivalent. Success: the marker exists after the request and not after the control.
   - **SSRF.** The harness starts a loopback listener inside the container on a random port and path with a random token. Success: the listener saw the token. The container keeps no outside network.
   - **SQL injection** for apps on SQLite or a seeded Postgres sidecar on the internal network only. The harness seeds a canary row unreachable by the normal query. Success: the response holds the row's token and the control does not.
   - **Authorisation / IDOR.** The harness creates two users through a start hook the operator gives (`--seed <cmd>`, never read from the repo), then plants a canary resource owned by user B. Success: user A's request returns B's token.
   - **Reflected or stored XSS.** Only if a headless browser image fits the limits. Otherwise leave it as proposed.
3. Not only Node.
   - `--start` is already from the operator; keep that.
   - Add `--port`, and document Python, Java and Go images (digest-pinned) with examples in `docs/src/content/docs/findings.md` under "Proof by reproduction".
4. Running it from a scan.
   - Add `0 scan --reproduce` (and the Action input `reproduce: true`). After the scan, it runs `reproduceFinding` for each finding whose class has a recipe and whose proof parses.
   - It never runs against a live URL. The app is always started from a snapshot of the commit.
   - Report columns and SARIF properties: `reproduction.status` and `reproduction.class`.
5. Archive reference, for ideas only:
   - `verify/replay-runner.ts`: the assertion vocabulary `exit-zero`, `http-status`, `body-contains` and `body-matches`
   - `verify/reproducer-minimize.ts`
   - `disclose/canary.ts`
   - `shared/verification.ts`: the `VerificationResult` schema, still on `main`

   Do not port the shell step runner.

**Acceptance:**
- Each class has a vulnerable fixture and a fixed fixture under `scripts/bench/repro-fixtures/<class>/`. The vulnerable one is `reproduced`, the fixed one `not-reproduced`, and the control never hits.
- `verify-score.mjs` reports per-class results.
- A run outside a container is `unisolated` and is never `reproduced`; this is the existing rule, so keep its test.

---

## W2. Pentest pack (enterprise)

**Why.** SBB, Perk and IBS want managed pentesting. Vattenfall's top pain is knowing which external services are really exploitable. What exists today:
- declared scope (`SECURITY.md` scope section, the scope interview, per-finding labels)
- `scan --scanner nuclei --target-url … --acknowledge-host … --scope-file`
- public and metadata hosts refused unless confirmed (#615)
- evidence bundles signed with a customer key (#589), and a hash-chained audit log (#575)

What's missing is **enforcement at the network layer** and the controls around live testing. Today the sandbox network is all or nothing (`runtime/smolvm-workbench.ts`, `ZERO_OFFLINE`; `workbench.ts`).

**Do** (code in `enterprise/`, behind a licence feature such as `pentest`, checked the way `evidence-signing` is):
1. **Egress allowlist.**
   - Live-target runs (threads or Sentinels with a target) get a container network whose only exit is an allowlisting proxy (an HTTP CONNECT and DNS sidecar), built from the declared scope file.
   - Anything else is dropped and logged to the audit log.
   - On SmolVM, do the same at the VM's network.
   - Archive reference: `scope/enforcement.ts`, `scope/scope-guard.ts`, `scope/rate-limit.ts`, `scope/waf-detect.ts`, and the bridge-with-scope-policy branch of the archived `DockerRunner`.
2. **Rate limit per host,** enforced in the proxy, not the prompt.
3. **Approval gate before exploitation.**
   - Steps the run marks as exploitation (anything past discovery, such as sending a payload) wait for operator approval through the existing approval path (`ask_operator` or "ask before running commands").
   - The approval is recorded with the request.
   - Ship a skill (`pentest-engagement`) that defines discovery and exploitation steps and uses this gate.
4. **Kill switch.**
   - `0security pentest stop` and a button in the console stop every live-target container and cut the proxy.
   - It works even when the model is mid-turn, and the stop is recorded in the audit log.
5. **Report.**
   - A pentest report export built on the signed evidence folder: scope, timeline, every request through the proxy (redacted), findings with their reproduction (W1) and CVSS 4 (W6), and the approval records.
6. **Continuous re-test.** A Sentinel preset `pentest-retest` that re-runs reproduction for open live-target findings on a schedule and re-opens or closes them.

**Acceptance:**
- In an integration test, a request to a host outside the scope file fails at the network and shows in the audit log.
- Without the licence feature, live-target runs keep today's behaviour and the command tells you what is missing.
- The kill switch stops a running container within 5 s in a test.
- Docs: a new page `docs/src/content/docs/pentest.md`, plus the "Free and paid" section of `server-mode.md`.

---

## W3. First-party security extensions

**Why.** Users expect the tools as extensions they can install. Today the only built-in extension is `github` (`plugins/extensions/core/builtins.ts`). The only security extension anywhere is `foxguard` in `0sec-labs/hackstore`, last updated 2026-09-15 with `minCoreVersion` 0.16.0. No other repository has an extension catalogue.

**Do:**
1. **Decide the home.** Revive `0sec-labs/hackstore` as the catalogue, or add `extensions/` to this repository. Write the choice in `docs/src/content/docs/extensions.md`, and list the catalogue there with each commit pin.
2. Build each extension as MCP server(s) plus skill(s), following the extension rules:
   - an exact `npx`/`uvx` version
   - each tool sha256-pinned
   - scripts under `node --permission` or the sandbox (#511, #580)
3. **AD / Entra attack paths.**
   - Port the analysis from `identity/` (`analyzers.ts`, `hybrid/`, `entra-graph/`) and `adgraph/` at `5787484d` into an MCP server that reads BloodHound or AzureHound exports offline.
   - Tools: `ad_attack_paths`, `entra_attack_paths`.
   - The server image already ships AzureHound, bloodhound-ce, impacket and certipy (`scripts/docker/Dockerfile`).
   - Keep the live Graph API posture check (`entra_posture`) out unless scope enforcement (W2) is on.
4. **Recon.**
   - Thin MCP wrappers over nmap and httpx for hosts in the declared scope.
   - They refuse targets outside the scope file and public hosts without `--acknowledge-host`, matching #615.
5. **0verse.** It is already reachable over MCP (`ZERO_MCP` auto-detect, `packages/cli/src/console-mcp.ts`). Package it as an extension so it installs like the others. Keep the existing gate flags.
6. **Foxguard.** Update the hackstore entry to the current foxguard release, or retire it if foxguard stays a built-in scanner (`--scanner foxguard`). Don't ship two paths.

**Acceptance:**
- Each extension installs with `0security skills add <source>@<sha>` and passes `doctor`.
- Each has one skill showing its use and one end-to-end test with a fixture.
- Nothing in core changes, except W0 when an extension wants a verifier.

---

## W4. Kernel extension (the source lane)

**Why.** Our 34 public Linux kernel findings came from the source lane: mining fix commits, variant hunting, finding incomplete fixes, running reproducers in a VM, and proving the patch removes the crash. That lane was removed. What survives is 0verse's **binary** kernel lane (`0verse/docs/KERNEL-INTEGRATION.md`: closed `.ko`, firmware, XNU), plus the syzkaller lane scripts in `0verse/scripts/linux/`.

**Depends on:** W0, for an extension verifier with `devices: ["kvm"]`.

**Do:**
1. **The `kernel` extension** (MCP server plus skills plus verify spec). It ships these MCP tools:
   - **`kernel_build`:** build a tree at a commit with a given config, in a pinned image.
     - Port from: `triage/kernel-vm/Dockerfile`, `Dockerfile.local-tree`, `build.sh`, `build-from-tree.sh`.
   - **`kernel_run`:** boot the built kernel in QEMU with KASAN on, run a program (64 KiB max), and return the console and the parsed KASAN or oops report.
     - Port from: `agent/tools/kernel-run.ts`.
   - **`syscall_boundary_map`:** map syscalls to handlers.
     - Port from: `kernel/syscall-boundary-map.ts`.
   - **`repro_run`:** run a syzkaller C reproducer or `.syz` program and report crash or no crash with the report signature.
2. **Skills carry the method.** Port it from `kernel/` as text, keeping only the parts the tools above don't cover:
   - `kernel-fix-commit-mining`: `fix-commit-intel.ts`, `syzbot-queue-mine.ts`
   - `kernel-variant-hunt`: `variant-hunt.ts`, `bug-templates.ts`, `dirty-frag-patterns.ts`
   - `kernel-incomplete-fix`: `incomplete-fix-hunt.ts`, `patch-gap*.ts`
   - `kernel-patch-to-poc`: `patch-to-poc.ts`

   Each skill tells the agent to use the existing `variant-hunting` technique and the root-cause record from #665.
3. **The verify spec,** in the extension's `verify` file:
   - build with the patch
   - run the reproducer
   - succeed when the crash signature from the baseline run is **gone**: `success.baseline: "improves"`, `metric` = crash count
   - `devices: ["kvm"]`, `network: none` after setup
   - port the logic from `verify/kernel-verify.ts`, `verify/patch-validate.ts` (`validatePatchRemovesCrash`) and `verify/reproducer-minimize.ts`
4. **Stays archived:** `kernel/exploit/` (weaponisation) and `cve_adapt`. This is research only, not a product feature.
5. Mailing-list work stays manual: a human signs off every upstream patch. The skill says so and never sends mail.

**Acceptance:**
- A fixture kernel bug (a small out-of-tree module with a known out-of-bounds bug, so CI doesn't build a full kernel) gives:
  - `kernel_run` → KASAN report
  - the agent's patch → verifier `Verified by: crash gone`
  - a wrong patch → `Not verified`
- Without `/dev/kvm` the verifier says `not-run: device-not-allowed`, or warns about slow TCG if the operator allowed TCG. It is never Verified by default.
- Docs: a new page `docs/src/content/docs/kernel.md`, saying clearly that source and binary go through different lanes, with a link to 0verse.

---

## W5. Improvement loop: Sentinel → pull request → held-out CI → pin

**Why.** The archived `improvement/` package (about 5.6k lines) edited four kinds of artifact (source, skill, router, lens). It scored each candidate against the current version on separate development, held-out and negative-control lanes, in a sandbox, with a registry for pin, promote, rollback and canary.

It can't be a skill alone. A skill runs inside the agent's own thread, so the agent would see the cases it's graded on, and it would be editing the instructions that steer it. Skills are pinned and approved, and memory has a taint guard (#413), for exactly that reason.

Most of the machinery now exists elsewhere:
- **Bench:** `scripts/bench/` (fix-score, triage-score, verify-score, real-apps, second-opinion)
- **Sentinels:** schedules
- **Extensions:** pinned revisions, rollback by re-pinning
- **GitHub:** pull requests and human merge

**Do:**
1. **Only skills are artifacts.** Skills are built-in YAML under `packages/engine/src/agent/skills/` or skills in an extension. No source or router edits.
2. **A development-lane runner.** `scripts/bench/run.mjs --lane development` runs the cases a proposer may see.
   - Split the existing cases into `development`, `held-out` and `negative-control` through a manifest file.
   - The held-out answers are **not in the repository the Sentinel can read.** Use a private repo, or a CI secret store mounted only in the CI job.
   - Port from: `improvement/evaluation.ts` (lane separation, paired comparison, evaluator identity), `improvement/safety.ts` (`holdoutExposureIdentity`, comparison identities) and `improvement/miss-harvest.ts` (turn misses on a scorecard into new development cases).
3. **A Sentinel preset `skill-tuner`.**
   - On a schedule, it runs the development lane, reads the misses and proposes edits to one named skill.
   - It opens a **pull request** with the edit plus the development-lane before and after. It never pushes to `main` and never edits skills in place.
   - Uses the github-pr / `gh` plumbing Sentinels already have.
4. **A CI job.**
   - On pull requests labelled `skill-tuner`, CI runs held-out and negative-control on the base and on the PR head, and posts the paired comparison.
   - It fails if held-out drops or negative control raises false positives.
   - The job, not the agent, holds the held-out answers.
5. **Promotion.**
   - A human merges.
   - For an extension skill, promotion means approving the new commit pin, and rollback means pinning the previous commit. Both already exist.
   - Record the comparison in the PR, and do not build a separate registry.
6. **Per-customer variant** (later, document only now). The same loop, inside a customer deployment:
   - reviewer decisions (real, false positive, accepted risk) become development cases
   - the proposal is a pull request in the customer's own skills repo
   - the customer's held-out set stays theirs

   This is the "feedback loop" Roche asked for.

**Acceptance:**
- A dry run on one skill (for example `scan` or `verify-finding`) opens a PR with the development scores.
- The CI job posts held-out scores, and fails a planted regression.
- The Sentinel has no read access to held-out answers. Add a test that it can't find them in its folder or environment.

---

## W6. CVSS 4 and advisory output

**Why.** Today CVSS only passes through the `cvssScore` field. Pentest reports (W2) and disclosure need a scored vector and an advisory text.

**Do:**
1. Port `disclose/cvss.ts` (`suggestCvss4`) and `disclose/cwe.ts` from `5787484d` into `packages/engine/src/shared/`, with their tests.
   - It suggests a vector from the finding's category, location and reproduction status.
   - It is labelled **suggested**, and the operator confirms it. There is no `--cvss` option on `findings update` yet, so add one.
2. Add an `advisory` export format (`findings export --format advisory`), ported from `disclose/template.ts` and `writeup.ts` (`renderAdvisoryMarkdown`).
   - Add the built-in skill `advisory-disclosure.yaml` back from the archive (`agent/skills/techniques/advisory-disclosure.yaml`), checked against today's tool names.
3. Remove the statuses left over from the deleted pipeline, or give them meaning again:
   - `scored` can mean "has a confirmed CVSS vector"
   - `reported` can mean "advisory exported"

   Today they are listed in `docs/src/content/docs/findings.md` and `commands.md` but nothing sets them.

**Acceptance:** CVSS 4 vectors round-trip against the published FIRST examples, the advisory export renders for a fixture finding, and the docs list the statuses that are set.

---

## Not coming back

These stay on `archive/security-engine`:
- the fixed scan pipeline (`stages/`)
- the triage routers (`triage/learned-router.ts`, `hybrid-router.ts`). The router was off by default, and the exploitability predictor's metrics (F1 0.999, AUC 1.0) look overfit.
- the research campaigns (`research/`)
- the per-language review profiles (`review/`)
- the workflow graph
- `packages/bench` (replaced by `scripts/bench/`)
- kernel weaponisation (`kernel/exploit/`)
- the prompt-injection red-team (`redteam/`)

To revisit one, open an issue with a bench comparison showing the gap, as [scan-as-a-thread.md](scan-as-a-thread.md) asks.

## Brief for an agent picking up a workstream

> You are implementing workstream W<n> of `docs/design/security-engine-return.md` in the `0sec-labs/0security` repository.
> - Read the "Rules every workstream follows" section and the design docs it lists before writing code.
> - Read archived code only with `git show 5787484d:<path>`. Never check out or merge the archive branch.
> - Do not add a native tool. Do not let the model set Verified or Reproduced. Do not run model-authored commands as proof.
> - Work on your own branch, keep the pull request to this one workstream, and meet its acceptance list.
> - Run `pnpm lint`, `pnpm check:architecture`, `pnpm build` and `pnpm test`, plus the integration tests if Docker or podman is available. Say in the PR which ones ran.
> - Update the user docs in `docs/src/content/docs` in the same PR.
> - If a step here turns out wrong against the code, change this document in your PR and say why.
