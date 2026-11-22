# Planted-bug benchmark

A small benchmark to measure whether scans and skills help: tiny apps with known planted bugs, an answer key, and a runner that scans each one and scores the findings. Code: `scripts/bench/`. It is plain Node ESM, not a pnpm package, with no dependencies.

## How it works

- `scripts/bench/fixtures/<name>/` is one app (under 150 lines, except `medium-app`, which has about 40 files in folders) plus `answer.json`. The answer key lists `items` (planted bugs: `id`, `path`, `startLine`, `endLine`, `category`, `description`, and optionally `alsoAt`: other places the same flaw shows, such as the helper that holds the sink and the route that reaches it; a finding at any of them finds the item) and `decoys` (code that looks risky but is safe). `skill` names the skill the fixture is meant for, or `null`. `clean: true` marks the app with no bugs at all.
- Fixtures: `node-express` (SQL injection, command injection, path traversal, hardcoded secret), `python-flask` (SSRF, pickle, `yaml.load`, MD5), `go-http` (SQL injection, `template.HTML` XSS, hardcoded key), `llm-app` (prompt injection into a shell tool, secrets in the prompt, unescaped model output; skill `llm-app-review`), `crypto-app` (RSA, SHA-1, ECB, weak key derivation; skill `crypto-migration`) `iac-app` (a Terraform module, a Kubernetes manifest, a Dockerfile and a GitHub Actions workflow with nine planted issues, two of them across resources, and seven decoys; skill `iac-review`) and `clean-app` (the same shapes as `node-express`, written safely).
- Fixtures: `node-express` (SQL injection, command injection, path traversal, hardcoded secret), `python-flask` (SSRF, pickle, `yaml.load`, MD5), `go-http` (SQL injection, `template.HTML` XSS, hardcoded key), `llm-app` (prompt injection into a shell tool, secrets in the prompt, unescaped model output; skill `llm-app-review`), `crypto-app` (RSA, SHA-1, ECB, weak key derivation; skill `crypto-migration`) `clean-app` (the same shapes as `node-express`, written safely) and `clean-python` (a Flask app with different safe patterns: allow-listed SSRF, `safe_load`, scrypt, a SHA-1 cache validator) and `medium-app` (about 40 files: an Express shop backend with a small Flask service and a Go webhook receiver, ten planted bugs spread over routes and helper files, four decoys; large enough that `0 scan` reviews it in batches).
- `run.mjs` copies each fixture without `answer.json` into a temporary folder, so the model cannot read the key. It runs `node packages/cli/dist/index.js scan <copy> --budget <n> --format json -o <out>` with a fresh `HOME` (and XDG directories) per run, then parses the findings.
- Configurations: `generic` (`--prepass off`), `skill` (`--skill <id>`, only for fixtures that name one), `foxguard` (`--prepass auto --scanner foxguard`, needs foxguard installed). For the infrastructure fixture only: `checkov-prepass` (`--prepass auto --scanner checkov`) and `checkov`, which runs Checkov alone, with no model and no cost, and scores its SARIF with the same matcher. `single` (`--batches off`) and `batched` (`--batches on --batch-size <n>`) compare one thread with one thread per batch of entry points; they are meant for `medium-app`. The default is `generic,skill`.
- Matching (`match.mjs`, pure, unit tested): a finding finds a planted item when the path agrees (suffix match), its line range is within 5 lines of the item's, and it belongs to the item's category family (from the finding's category, then title, then description). Matching is one-to-one, so a single finding never credits two items. A finding on a decoy (within 2 lines), or any finding in the clean app, is a false positive. A finding that is neither is reported as "unmatched" (a real extra issue or noise; read them) and is not counted as a false positive.
- The report is Markdown and JSON in `scripts/bench/results/` (git-ignored apart from `example.md`): recall, false positives, unmatched, cost and time per fixture and configuration, as mean with min-max over repeats.

## Running it

```bash
node --test scripts/bench/match.test.mjs
node scripts/bench/run.mjs --dry-run                       # validates fixtures and the matcher; no model, no cost
node scripts/bench/run.mjs --run --repeat 2 --budget 0.2   # really scans; prints the worst-case cost first
```

`--run` is required to spend money; each scan stops at `--budget`, and the estimate printed is runs times budget. Other options: `--configs generic,skill,foxguard`, `--fixtures a,b`, `--model <id>`, `--out <dir>`, `--timeout <s>`, `--batch-size <n>` and `--concurrency <n>` (both for the `batched` configuration). The dry run is part of `node scripts/run-checks.mjs static`.

## Batched scans on `medium-app`

`medium-app` (40 source files, 71 entry points, 10 planted bugs) is the check that a batched scan reviews as much as one thread (issue 525). Measured on 2026-11-22 with the default model, a fresh `HOME` per run, `--budget 1`:

| configuration | runs | planted bugs found | cost per run | time per run | coverage reported |
|---|---|---|---|---|---|
| single thread (`--batches off`) | 3 | 8, 8, 9 of 10 | $0.11 to $0.22 (mean $0.15) | 233 to 503 s | none |
| batched, 8 batches, 1 at a time | 1 | 8 of 10 | $0.27 | 1072 s | 61 of 71 entry points; 10 not reached (thread failed) |
| batched, 8 batches, 3 at a time | 3 | 10, 10, 9 of 10 | $0.23 to $0.32 (mean $0.28) | 379 to 617 s | 71 of 71 (2 runs); 61 of 71 with one failed batch (1 run) |

- Both configurations missed the same two logic flaws most often: the order read without an ownership check, and the role route without the admin guard. A pattern-based inventory does not make a model notice a missing check.
- A failed batch was a provider connection error (`UND_ERR_SOCKET`). It stayed pending with the reason, the report said so, and the run exited 3. In the run that lost one batch the other 7 still found 10 of 10, so recall and coverage are separate facts: the report gave the coverage, and the key gave the recall.
- Batching cost about twice as much (probably because each thread loads the skill and rereads shared files). Run one batch at a time it took about 3 times as long in the one run; at 3 at a time about 1.4 times as long as one thread. Provider speed varied a lot between runs.
- Resume: a scan with `--budget 0.1` reviewed 21 of 71 entry points (6 of 10 bugs found, 50 not reached: budget 39, thread failed 11). `--resume latest --budget 1` ran only the pending units and reached 66 of 71 (9 of 10 found; one batch failed again, 5 not reached). A second `--resume` ran one batch for the last 5 and finished at 71 of 71 for $0.015. The three runs cost about $0.45 together, and none repeated a reviewed unit.
- Recall is not worse than one thread in these runs (batched 8 to 10, single 8 to 9), but 3 to 4 runs per arm cannot show a difference of one planted bug.

## Latest run

The wording change to the scan skill that this run measured (require an exploit path, name weak hashes) is not in the product. With the foxguard pre-pass, which is the default when foxguard is installed, recall fell on two fixtures, and the false-positive gains were small. It stays on the `agent/scan-quality` branch until a larger run settles it. The numbers below say "after" for that edit.

2026-11-22, default model (gpt-6-luna), configs generic and foxguard, 3 repeats, budget $0.5 per scan, cost about $0.2 per full run. Full table: `scripts/bench/results/example.md`.

- Generic scan, mean recall over the five bug fixtures: 88% before and 90% after the scan.yaml edit; foxguard pre-pass: 82% before and 79% after. The foxguard pre-pass did not beat the generic scan on recall (crypto-app and llm-app lower, others equal) and cost slightly more.
- False positives on the clean apps (generic): clean-app 1.0 to 0.7, clean-python 1.3 to 0.3 per scan. All of them were one class, missing authentication or ownership on read routes, which is a defensible note on apps that really have no auth.
- The edit also names MD5 and SHA-1 explicitly; python-flask generic recall went 83% to 100% (the weak-hash item).
- With 3 repeats and these fixtures, only differences larger than the min-max range mean anything. The edit was written after reading clean-app findings, so clean-app is partly tuned on; clean-python was added to give a second sample, but it too shares the unauthenticated-read shape.

## What it does not prove

- Seven tiny, synthetic apps with obvious bugs. A high recall here says the scan is not blind, not that it finds bugs in a real codebase; the planted bugs are textbook shapes models have seen.
- The answer key is ours. Findings that are real but unplanted are listed as unmatched, not credited; false positives are only counted on decoys and the clean app, so precision on real code is not measured.
- A repeat count of 2 to 3 gives a range, not a confidence interval. Treat differences smaller than the spread as noise. Model output varies between runs and between model versions.
- The category-family and line-proximity matching is heuristic: a correct finding with an unusual category or wrong line can be missed, and a vague one nearby can be credited.
- Cost and time depend on the model, the provider and load on the day. Compare configurations from the same run.
- Skill fixtures are written by the same team as the skills; a skill that scores well on its own fixture may have been tuned to it.

## Infrastructure as code

Run on `iac-app`, 3 repeats, `--budget 0.5`, one model (the default). Mean over repeats, min-max in brackets:

| config | recall | false pos. | cost per scan |
|---|---|---|---|
| generic | 56% (44-67%) | 0 | $0.009 |
| skill (`iac-review`) | 67% (56-78%) | 0 | $0.016 |
| checkov alone | 56% (56%) | 32 (see below) | $0 |
| generic with `--scanner checkov` | 70% (56-89%) | 0 | $0.019 |

The differences between the model configurations are inside the spread, so none beats another on this fixture. No configuration found `iac-db-via-edge` (a database group that trusts an open group) on its own, and the private-subnet route was found in 1 of 3 skill runs and 2 of 3 Checkov pre-pass runs. Treat the skill as experimental.

Rule scanners report a whole resource as one region, so the matcher credits a Checkov finding when any rule on the resource overlaps a planted line (for example a missing-description rule on the database group). Checkov's `iac-db-via-edge` credit comes from a missing-description rule on that group, not from seeing the exposure, so read its recall as an upper bound of about 4 of 9; the false-positive count is mostly hygiene rules on the decoy Deployment, which Checkov also reports on a hardened container.

## Adding a fixture

1. Create `scripts/bench/fixtures/<name>/` with a small app (under 150 lines) in its own language. Keep each bug on a few lines and add at least one decoy: safe code shaped like a bug.
2. Write `answer.json` with `"fixture": "<name>"` equal to the folder, `skill` or `null`, `items` and `decoys`. Paths are relative to the fixture folder; lines are 1-based and inclusive; `category` is one of the families in `match.mjs` (`FAMILIES`). Add a new family there, with a pattern and a test, if none fits.
3. Run `node scripts/bench/run.mjs --dry-run`. It checks that every path exists, that line ranges are inside the file, that categories are known, and that synthetic findings placed on the key score as expected.
4. Never put the answer in the app's comments or file names: the model sees the whole folder except `answer.json`.
