# Real-model measurement: code-index tools, variant hunting, executed PoC

Measured on 2026-11-26 with the CLI built from `main` (0.45.0, `fc29c3fee`) and Foxguard built from `crates/foxguard` in the same checkout. Harness: `scripts/bench/code-index/` (`run.mjs`, `poc-probe.mjs`, fixtures, raw results). Method and scoring follow [benchmark.md](benchmark.md).

## Connection

Every run used provider `chatgpt-codex`, model `gpt-6-luna` (read from the saved thread of each run: `consoleState.configuration.runtime`, medium reasoning). The credential was never read by the harness: each run gets a fresh `HOME` and the CLI is told only where the existing Codex login file is (`ZERO_CODEX_AUTH_JSON_PATH`). One tiny call (`-p "Reply with the single word: pong"`) answered before anything else ran. No rate limit appeared in any run (0 of 42 scan and variant runs, so the stop-on-rate-limit rule never fired). The model is included in the subscription, so nothing was billed; the CLI's own estimate was $0.007 to $0.19 per run.

## Result in one paragraph

On these fixtures the code-index tools did **not** measurably help, and the shipped way of loading them (`--skill seedless-depth-review`) was **worse** on recall than a plain scan. The baseline already found every planted authorization and multi-step logic bug in every run, so there was no headroom. Variant hunting from a recorded finding did measurably better than a plain scan on the same folder: 6 of 6 siblings in 3 of 3 runs, no false variants, about 5 times fewer tokens. Executed PoC labelling could not be exercised: Docker works, but the model's findings carry no proposed steps, so `findings reproduce` answers "inconclusive".

## Design

Fixtures (all with an answer key, planted bugs and correctly guarded decoy routes; `match.mjs` scores them, one new family `business-logic` was added for the state and amount checks):

| fixture | where | what | planted | decoys |
|---|---|---|---|---|
| `ts-shop` | new, `scripts/bench/code-index/fixtures/` | TypeScript/Express, 10 files: order read without ownership, role change under `/admin` without the role guard, refund without owner or amount check (route and service), invite acceptance not bound to the invited email | 4 | 6 (guards live in middleware and services: cancel, admin list/delete, self-profile, team invite, own-order list) |
| `java-bank` | new, same folder | Spring, 8 files: account read without owner check, transfer approval by the creator (no maker-checker), admin report export without the class-level `@PreAuthorize` its sibling has, password reset that trusts a customer id from the body | 4 | 5 |
| `medium-app` | existing, `scripts/bench/fixtures/` | Express/Flask/Go, about 40 files, 71 entry points, written for the batch benchmark; two of its ten planted bugs are authorization (order read, role route) | 10 (2 authz) | 4 |
| `variants-docs` | new, `scripts/bench/code-index/variants/` | Express: the owner check was added to `GET /docs/:id`; six sibling routes (update, delete, export, versions, bulk delete, and share in a second router) are unfixed; six look-alikes are guarded or intentionally public | 6 | 6 |

The two new scan fixtures and the variant fixture were written before any model ran on them and were not changed after seeing results. `medium-app` was reused unchanged; the harness reports its authz subset separately.

Scan arms (fresh `HOME`, answer key not in the copy, `--prepass off`, `--model gpt-6-luna`, `--budget 1`, `--timeout 1200`, 3 repeats, 2 runs in parallel):

- `baseline`: plain `0 scan`. It runs in batches (one thread per group of entry points).
- `index-full`: the same prompt with `ZERO_TOOLSET=full`, so `callers_of`, `callees_of`, `routes` and `trace_to_sink` are advertised without a skill. Checked with a direct `-p` call that the four names appear in the tool list in this mode and not in `core`; not checked inside a scan thread.
- `index-skill`: `--skill seedless-depth-review`, the product path that loads the pack.
- `baseline-single`: plain scan with `--batches off`. Added after round 1, because any `--skill` other than `scan` forces one thread, so `index-skill` has to be compared with a one-thread control.

Variant arms (3 repeats): `variants` imports the fixed bug as a finding from SARIF and runs `0 findings variants <id>` (the root cause is derived by the thread, since no earlier verify run recorded one); `plain-scan` is a plain scan of the same folder with no knowledge of the seed, scored on the same six siblings. Caps: at most 27, 9 and 6 runs per round, 150, 90 and 45 minutes. Raw per-run results (findings, counts, tool calls, tokens, seconds): `scripts/bench/code-index/results/*.json`.

## Scan results

Planted bugs found out of planted (per run, 3 runs per cell), false positives (decoy hits; one by-hand reading below), turns, tokens and seconds as mean with the range over the three runs.

| fixture | arm | found per run | false pos. (sum of 3) | turns | tokens | time (s) | index tool calls (sum of 3) |
|---|---|---|---|---|---|---|---|
| ts-shop | baseline | 4, 4, 4 of 4 | 0 | 20 (19-20) | 187k (179k-192k) | 133 (125-137) | 0 |
| ts-shop | index-full | 4, 4, 4 of 4 | 0 | 19 (17-21) | 194k (164k-216k) | 127 (113-148) | 0 |
| ts-shop | index-skill | 3, 3, 3 of 4 | 0 | 13 (11-17) | 232k (193k-299k) | 69 (63-74) | 3 |
| ts-shop | baseline-single | 3, 4, 3 of 4 | 0 | 9 (8-10) | 86k (79k-100k) | 62 (58-67) | 0 |
| java-bank | baseline | 4, 4, 4 of 4 | 0 | 19 (19-20) | 191k (186k-197k) | 139 (121-157) | 0 |
| java-bank | index-full | 4, 4, 4 of 4 | 0 | 18 (16-21) | 180k (158k-211k) | 118 (101-128) | 0 |
| java-bank | index-skill | 3, 4, 4 of 4 | 0 | 15 (11-20) | 365k (267k-460k) | 84 (70-97) | 1 |
| java-bank | baseline-single | 4, 3, 4 of 4 | 0 | 9 (8-11) | 95k (80k-125k) | 70 (64-82) | 0 |
| medium-app | baseline | 10, 10, 10 of 10 | 0 | 85 (65-111) | 2264k (1197k-4095k) | 595 (460-788) | 0 |
| medium-app | index-full | 10, 10, 10 of 10 | 2 | 89 (65-108) | 2796k (1688k-3433k) | 672 (611-785) | 2 |
| medium-app | index-skill | 6, 7, 8 of 10 | 0 | 15 (13-16) | 447k (414k-486k) | 102 (76-121) | 3 |
| medium-app | baseline-single | 10, 5, 10 of 10 | 1 | 22 (14-29) | 835k (249k-1479k) | 155 (93-199) | 0 |

Pooled over the three fixtures (9 runs per arm; 54 planted items each): baseline 54 found, index-full 54, index-skill 41, baseline-single 46.

- **Authorization subset** (the class the tools are for): every arm found both authz bugs of `medium-app` in every run (2 of 2 in all 12 arm runs, with the caveat below); `ts-shop` and `java-bank` are entirely authorization or logic items and are in the table above. The only authz-class losses were in `index-skill` (`ts-invite-hijack` in 3 of 3 runs, `jb-report-export` in 1 run) and `baseline-single` (one miss each in `ts-shop` twice and `java-bank` once).
- **index-full versus baseline** (the clean test of "are the tools available"): identical recall (54 of 54 both), no difference in turns, tokens or time beyond the spread. The model called an index tool twice in 9 runs, both `callers_of` on `medium-app`. It essentially ignored the tools. So this arm says "advertising the tools without telling the model to use them changes nothing", not "the tools do not help when used".
- **index-skill versus baseline-single** (the fair pair, both one thread): 41 versus 46 of 54 found, inside the spread on every fixture. The skill used `routes` once in 7 of 9 runs and then delegated through `spawn_agent` (26 calls in 9 runs). Its recall cost is mostly on classes the skill does not look at: on `medium-app` it missed the XSS, hardcoded secret, MD5 and SSRF items (`ma-xss` 2 of 3, `ma-secret` 2 of 3, `ma-md5` 3 of 3, `ma-ssrf` 1, `ma-traversal` 1) while still finding both authz bugs.
- **Batched baseline versus single thread**: the default batched scan found 54 of 54, the one-thread scan 46 of 54, at 2 to 5 times the tokens and time. That is the largest effect in the data and it has nothing to do with the index.
- **Speed**: `index-skill` was the fastest arm (about 70 to 100 s) because it stops early, which is the same reason it misses items.
- **False positives**: 0 on the two new fixtures in every arm. Three decoy hits on `medium-app`, all line-proximity hits: `baseline-single` run 2 reported unauthenticated order search two lines from the parameterised-search decoy (a note other runs also filed as a real unplanted issue); two `index-full` hits sit next to the cancel and avatar decoys (one says cancellation ignores payment status, a defensible logic note; the other was not read in detail). The same `baseline-single` run also reported that the cancel route allows cross-user cancellation, which is wrong (it checks the owner), yet the matcher credited it to the order-read item three lines away, so that run's authz credit is probably too generous; the matcher's 5-line tolerance allows this. Many "unmatched" findings are real unplanted issues (negative transfer amounts, unauthenticated order search, tokens never invalidated on logout); they were not counted either way.

## Variant hunting

| arm | siblings found (of 6) | false variants | turns | tokens | time (s) |
|---|---|---|---|---|---|
| `findings variants` from the fixed finding | 6, 6, 6 | 0 (and 0 look-alike decoys flagged) | 4 | 31k (30k-32k) | 40 (39-43) |
| plain scan, not told about the seed | 3, 2, 3 | 0 | 18 (17-19) | 167k (160k-179k) | 122 (109-135) |

- The hunt found all six unfixed sibling routes in all three runs, including the one in a second router and the bulk route, and flagged none of the six look-alikes (inline owner-or-shared checks, a middleware guard, an intentionally public route). The plain scan always missed delete, export and version history (and bulk delete once).
- The comparison is not like for like: the hunt is told the bug class and the fixed site, the scan has to discover everything. It shows the feature does what it is for; it does not show it beats a scan that was given the same hint.
- The plain scan also reported one unplanted real flaw in my fixture (`x-user-id` is trusted as the identity); I left the fixture as it was.
- The root cause was derived by the thread (`rootCauseSource: derived`); the variant of the flow where `findings verify` or `findings fix` records the root cause first and then hunts was not measured.

## Executed PoC (Docker)

Docker is available (server 29.2.1 through Colima). A digest-pinned image was pulled (`node:24-bookworm-slim@sha256:873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530`). `poc-probe.mjs` scanned `scripts/bench/repro-fixtures/path-traversal/vulnerable` with the real model twice (47 s each). Both runs found the path traversal. In both, `findings reproduce` answered `inconclusive: no-proposed-steps`, and `findings verify` with `ZERO_POC_IMAGE` set left `executedPoc` empty. Nothing was labelled `executed-proven` or `executed-failed`, so the container run itself was not exercised with a model finding. This is 2 runs on one tiny app, and reproduce supports only path traversal on a Node HTTP route.

## What this does not show

- Ceiling: baseline found 54 of 54 on the three scan fixtures, so a tool or prompt that adds recall had nothing to add. The fixtures were deliberately not hardened after the result. A harder, larger authorization benchmark with bugs the baseline misses is needed before the tools can be judged.
- Three runs per cell. A difference of one planted item is inside the spread. The `index-skill` loss (41 versus 46) is suggestive, not established; the loss against the batched baseline (41 versus 54) is large enough that three of three runs agree on `ts-shop` and `medium-app`.
- One model (`gpt-6-luna`), medium reasoning, fixtures written by the team, answer keys ours. Fixture bugs are shaped like the skill text describes them.
- Java: `index-skill` and `index-full` called an index tool once in `java-bank` across 6 runs, so the Foxguard Java graph backend was effectively not measured.
- Tokens and turns for `index-skill` count the saved main thread only; threads started with `spawn_agent` were not in the saved sessions, and I did not check whether the CLI's token total includes them.
- Two runs in parallel, so times include contention (the same for all arms, interleaved).

## Follow-up issues

1. **The scan skill never points at the index tools.** With the tools advertised (`ZERO_TOOLSET=full`) the model called them twice in 9 runs. Either add one line to the `scan` skill, or load the pack in batch threads, then re-measure. Without that the tools cost prompt space and give nothing.
2. **`--skill seedless-depth-review` silently becomes a one-thread, coverage-less scan.** `singleThread: options.skill !== "scan"` turns off batching and the coverage statement, so recall fell from 54 to 41 of 54 and `ts-invite-hijack` (invite acceptance not bound to the invited email) was missed 3 of 3 times. The report should say that batching is off, and the skill should be usable on top of batches.
3. **`seedless-depth-review` reviews authorization and routing, not the rest.** It missed the XSS, hardcoded secret, MD5 and SSRF items of `medium-app` in 3 of 3 runs. Add a line that other bug classes still need a pass, or run it as an addition to `scan`.
4. **The skill stops early.** 11 to 20 turns and 60 to 120 s, with `spawn_agent` children that are hard to see. Decide whether the early stop is intended; today it is the cause of both the speed and the misses.
5. **Child threads are not observable.** `spawn_agent` threads are absent from `console-sessions`, and the scan report carries no tokens, turns or tool counts. The harness had to read `metrics.ndjson` and the saved sessions. Put tokens, turns and tool-call counts per thread, children included, in the JSON report.
6. **Scan findings carry no `poc_steps`.** Both real-model path-traversal findings ended in `no-proposed-steps`, so `findings reproduce` and the `ZERO_POC_IMAGE` verify path never ran a container. Ask for steps in the `scan` and `verify-finding` skills, or say plainly that executed labels need a separate step.
7. **CLI details found on the way.** `findings list --all --format json` is rejected (`--all` and `--format` do not combine), the JSON listing omits `variantOf`, and `findings variants --format json` returns only ids of created variants, so a caller has to list again to get locations.
8. **Batched baseline cost.** On `medium-app` the default scan used 1.2M to 4.1M tokens and 460 to 788 s, against 0.25M to 1.5M and 93 to 199 s for one thread (recall 10 of 10 versus 5, 10, 10). Worth deciding what the default should be for folders of this size.
9. **Variant flow still to measure.** Hunt with a root cause recorded by `findings verify` or `findings fix`, on a second fixture where the plain scan finds fewer siblings with a hint, and with siblings in another language.

## Reproduce

```bash
node scripts/bench/code-index/run.mjs --dry-run
node scripts/bench/code-index/run.mjs --run --mode scan --repeat 3 --max-runs 27 --max-minutes 150 --concurrency 2
node scripts/bench/code-index/run.mjs --run --mode scan --arms baseline-single --repeat 3 --max-runs 9
node scripts/bench/code-index/run.mjs --run --mode variants --repeat 3 --max-runs 6
node scripts/bench/code-index/poc-probe.mjs --image node:24-bookworm-slim@sha256:<digest>
```

The harness needs a built CLI (`pnpm build`) and Foxguard (`bash scripts/build-foxguard.sh`, picked up from `target/foxguard-bin`). Results are written to `scripts/bench/code-index/results/`.
