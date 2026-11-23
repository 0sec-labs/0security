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

The fix and triage scorecards run the same way, each with `--dry-run` and `--run`:

```bash
node scripts/bench/fix-score.mjs --dry-run                 # every exploit check fails before a fix and passes with the reference fix
node scripts/bench/fix-score.mjs --run --repeat 2 --budget 0.5 --total-budget 4
node scripts/bench/triage-score.mjs --run --fixtures clean-app,python-flask,node-express
```

`--total-budget` stops the fix scorecard from starting new fixes once that much is spent.

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

## Second-pass verification (`0 findings verify`)

Measured with `node scripts/bench/verify-score.mjs --run --repeat 2`. For each fixture it scans a copy with a fresh home (`--budget 0.5`), runs `0 findings verify --apply` on every finding, and classifies each finding with the matcher: a planted bug, a false positive (a decoy hit, or any finding in a clean app) or neither. Six fixtures (clean-app, clean-python, python-flask, go-http, node-express, llm-app), 2 repeats, default model. Total cost of both rounds about $0.2.

The number to watch is real bugs that the verifier called false-positive, and real bugs that `--apply` would have suppressed.

First round, skill text as first written: 1 of 25 planted-bug findings was called false-positive, and `--apply` suppressed it (a medium finding: unsalted MD5 on `/register`, dismissed because the code shown does not store the hash). Nothing in that reasoning was a control.

The skill was then tightened: the absence of a caller, a write or a route in the folder is not a control, an argument that the impact is small is not a control, and weak primitives and hardcoded secrets are not dismissed because the folder does not show where they are used. Second round, same fixtures:

| Group | Findings | true-positive | false-positive | uncertain |
| --- | --- | --- | --- | --- |
| Planted bugs | 25 | 21 | 0 | 4 |
| Decoy or clean app | 4 | 4 | 0 | 0 |
| Neither | 6 | 3 | 0 | 3 |

- Real bugs called false-positive: 0 of 25. Real bugs suppressed by `--apply`: 0. The first round had 1 of 25 and 1, so the small sample moved by one finding; do not read 0 as a guarantee.
- Precision gain: none measured. All 4 findings the benchmark counts as false positives (missing authentication on read routes in the clean apps) were called true-positive, because the thread built a concrete unauthenticated request for each. The first round had 5 such findings, 4 true-positive and 1 uncertain. Those findings are a defensible reading of the code, so the benchmark's "clean" label may be too strict for them; either way the verifier did not remove them.
- Uncertain was used for 4 planted bugs, 3 other findings and 0 false positives: a hardcoded signing key that no code in the folder uses (go-http), and llm-app findings whose entry point is not in the folder. It answers uncertain rather than guessing, which costs recall in a triage workflow but suppresses nothing.
- Cost: about $0.001 to $0.002 per finding at the default model, in a thread of its own.
- This is 25 real-bug findings, 4 false positives and 6 others over 12 scans. It shows the verifier did not dismiss real bugs here and was cautious. It does not show that it removes false positives, because the sample has almost none it could remove. `--apply` has no severity guard: it was not needed in the second round, and it would be added if a real high or critical finding is ever suppressed.

## Fix quality (`0 findings fix`)

Measured with `node scripts/bench/fix-score.mjs --run --repeat 2`. It uses ten small projects under `scripts/bench/fix-cases/`, each with one planted vulnerability: SQL injection, path traversal, command injection, unsafe `eval` of pasted settings, MD5 password hashing, an open redirect, a missing authorization check, a hardcoded signing key, an allowlist bypass in a URL check and prototype pollution. All ten are plain Node with `node --test` and no installs.

A case has the project and its tests, a SARIF file with the finding, a note on what a correct fix must do, a hidden exploit script and a reference fix. The reference fix is used only by `--dry-run`, which proves each exploit check fails on the vulnerable code and passes on a correct fix, with the tests green both times. A run copies the project to a fresh git repository and a fresh home, imports the finding, runs `0 findings fix <id> --no-pr --budget 0.5` with the project's tests as the check, then scores the committed branch in the copy. The tests are the original files, restored before they run. A fix counts when it committed, the original tests pass and the exploit check exits 0.

2026-11-23, default model (gpt-6-luna), 2 repeats, `--budget 0.5` per fix, total cost $0.05:

- Fix rate 90% (18 of 20 attempts; 90% in both repeats). All 20 attempts committed and kept the tests green. 18 blocked the exploit.
- Both failures were the hardcoded-secret case. The model moved the key to `SESSION_SECRET` but kept a fallback to a default key. The case requires failing closed, so the exploit check counts that as not fixed. It is a strict reading, and the answer note for the case says so.
- Every fix touched the expected source file and added or edited a test; 7 to 43 lines changed in total. Cost per fix $0.0017 to $0.0035, 21 to 40 seconds.
- A first pass of the same run scored the open-redirect case 0 of 2 because the exploit check treated `/%2f/` paths as unsafe. Browsers do not decode that sequence in a redirect, so the check was wrong, not the fixes. It was removed and the run repeated; the table above is the second run.

What it shows: on single-bug textbook cases the fix flow commits a working change that keeps the tests passing. What it does not show: how it behaves in a repository with many files, a build, or a vulnerability that spans modules. The exploit scripts are ours and test the cases we thought of. A fix that blocks our payloads and misses another one would pass. The cases are also small enough that the model may have seen close variants of them.

## Agent triage (`0 findings verify`)

Measured with `node scripts/bench/triage-score.mjs --run`. It scans each fixture with a fresh home, runs `0 findings verify --apply` on every finding and scores the verdicts against the answer keys. It shares the scan, verify and classification steps with `verify-score.mjs` and adds precision and recall per verdict. Pass `--scans <dir>` to verify saved scan reports (`<fixture>.json` from `0 scan --format json -o`) instead of scanning again; the run keeps its own scan reports under its output folder for that.

The number to watch is real bugs that verify called false-positive. Real means the finding matches a planted bug. Noise means it is on a decoy or anywhere in a clean fixture. Findings that are neither are left out of the rates.

2026-11-23, default model, 1 repeat, two runs of three fixtures (clean-app, python-flask, node-express and clean-python, llm-app, go-http), total cost $0.06:

| Verdict | on real bugs | on noise | on neither | Precision | Recall |
| --- | --- | --- | --- | --- | --- |
| true-positive | 12 | 1 | 3 | 92% | 92% |
| false-positive | 0 | 0 | 0 | n/a | 0% |
| uncertain | 1 | 0 | 1 | - | - |

- Real bugs called false-positive: 0 of 13. Real bugs suppressed by `--apply`: 0.
- Noise removed: 0 of 1. The one noise finding (clean-python) was called true-positive.
- Precision of the list before triage 93%, and the same after dropping false-positive verdicts, because verify dropped nothing.

This run had a single noise finding, so it says almost nothing about how much noise verify removes. It only repeats the earlier result: verify did not drop real bugs. A harder test needs fixtures that produce more false positives, and the OWASP Benchmark ground truth and the hand-labelled Java findings that the original issue asks for are not done.

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

## Second opinion with `--known`

`scripts/bench/second-opinion.mjs` measures whether `0 scan --known <sarif>` finds planted bugs that a baseline tool misses (issue 516). For each fixture with planted items it runs the baseline tool, scores that tool's own SARIF against the answer key with the same matcher, then scans the fixture with and without `--known <that SARIF>`. The generic scan is the same two runs for both tools. `--prepass off`, the default model, a fresh `HOME` per run, `--budget 0.5`.

Measured on 2026-11-22. Baselines: foxguard and Semgrep (`p/default`). 2 repeats per arm, except `medium-app` with foxguard only and 1 repeat (a scan of it takes 15 to 25 minutes). Semgrep was not run on `medium-app`. Total model cost about $0.8 as reported by the scans, plus one `medium-app` scan that was stopped and rerun.

What the baselines miss on these fixtures (planted items of 4 to 10 per fixture):

| fixture | foxguard misses | Semgrep misses |
|---|---|---|
| node-express | 1 of 4 | 1 of 4 |
| python-flask | 0 of 4 | 0 of 4 |
| go-http | 2 of 3 | 1 of 3 |
| crypto-app | 4 of 6 | 3 of 6 |
| llm-app | 4 of 4 | 4 of 4 |
| iac-app | 9 of 9 | 5 of 9 |
| medium-app | 5 of 10 | not run |

Items the baseline missed that the scan found, summed over runs (the denominator is the missed items times the repeats):

| baseline | generic scan | scan with `--known` |
|---|---|---|
| foxguard, 7 fixtures | 26 of 45 (58%) | 31 of 45 (69%) |
| Semgrep, 6 fixtures | 13 of 28 (46%) | 12 of 28 (43%) |

Share of the reported findings that are new (not matching a known item by file, 5 lines and category family):

| baseline | generic scan | scan with `--known` |
|---|---|---|
| foxguard | 33 of 61 (54%) | 44 of 54 (81%) |
| Semgrep | 12 of 43 (28%) | 16 of 25 (64%) |

- With foxguard as the baseline, recall of the missed items rose from 58% to 69%, and most of the gain is `iac-app` (9 to 13 of 18) plus one item on `medium-app`. With Semgrep as the baseline it did not rise (46% to 43%). The samples are small and the spread between two repeats is larger than these differences, so this does not show that `--known` finds more of what a baseline misses.
- What the data does show: the share of new findings goes up a lot, because the scan stops re-reporting what the baseline already found. On the same fixtures the scan found fewer planted items overall with the flag (foxguard runs 48 of 70 without, 36 of 70 with; Semgrep runs 40 of 60 without, 17 of 60 with), as intended. The flag is for a team that already collects the baseline's findings, not a replacement for them.
- In the reports I read, every match with a known item also carried the scan's own analysis, so it was marked `confirmedIndependently`. `already-known` without that mark did not appear.
- Which items count as missed comes from the benchmark matcher applied to the tool's SARIF, so a tool finding that the matcher does not credit counts as a miss. A generic run failed on `crypto-app` and one on `llm-app` (the thread's answer was not backed by its checks), and the `medium-app` run with the flag stopped partial; they are included.
- The same limits as above apply: tiny synthetic fixtures with textbook bugs, an answer key we wrote, and a model that varies between runs.

## Real applications

The synthetic fixtures are small and textbook-shaped. This section measures `0 scan` on three public, intentionally vulnerable applications whose bugs their own projects document. Code: `scripts/bench/real-apps.mjs`, keys in `scripts/bench/real-apps/`.

The apps are untrusted. The harness clones them as text at a pinned commit, never installs or runs them, and scans a scratch copy.

### Run it

The clones stay outside the repository. The dry run needs them, so it is not part of `node scripts/run-checks.mjs static`.

```bash
node scripts/bench/real-apps.mjs --clone                  # network; clones each app at its pinned commit into /tmp/realbench
node scripts/bench/real-apps.mjs --dry-run                # no model: checks every key item against the clones
node scripts/bench/real-apps.mjs --run --repeat 3 --budget 2 --total-budget 6 --apps dvna
node scripts/bench/real-apps.mjs --run --configs lean --apps dvna --repeat 6   # --batches off --prepass off, the cheapest config
node scripts/bench/real-apps.mjs --report --out <dir>     # summarises saved scans again, after a key correction
```

`--run` writes one JSON file per scan (findings, status, coverage, cost) so findings can be read by hand afterwards. `--total-budget` stops new scans once that much is spent.

### Apps, commits and answer keys

| app | commit | items | key source |
|---|---|---|---|
| DVNA (Node, Express, Sequelize) | `9ba473add536f66ac9007966acb2a775dd31277a` | 17 | `docs/solution/*.md`: one page per OWASP category with the vulnerable snippet and its file name |
| NodeGoat (Node, Express, MongoDB) | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 17 | `app/views/tutorial/*.html`: the "Source Code Example" of each page names a file and function |
| VAmPI (Flask API) | `f16052dce83f05847133ec98f01c5193a41de7d8` | 9 and 6 decoys | `README.md`, "List of Vulnerabilities": nine classes, no locations |

Each item records its file, line range, family, the doc page it comes from and whether the docs or we located it. DVNA: all 17 located by the docs (file and function). NodeGoat: 16 by the docs, 1 by us (the missing CSRF middleware, an absence). VAmPI: all 9 located by us, because the README names classes only.

VAmPI switches each bug with a `vuln` flag, and the other branch is the project's own safe version. Those six safe branches are the decoys, so VAmPI is the only app with documented-safe code.

The scanned copy leaves out the answer source: DVNA `docs/`, `views/vulnerabilities/` and `config/vulns.js`; NodeGoat `app/views/tutorial/` and `test/`; the VAmPI README and Postman collection. It also blanks comments that name the flaw, keeping every line number. NodeGoat's code carries comments such as "Fix for A1" and commented-out fixed code; without the blanking the scan would read the answer (391 lines blanked there, 16 in DVNA, 16 in VAmPI). The app names, the `vuln` flag and the VAmPI docstring in `app.py` stay, so the model knows these are intentionally vulnerable apps.

Not in the keys:
- Absences with no line to match: DVNA insufficient logging and the `X-Powered-By` header, NodeGoat missing security headers.
- Anything the docs do not discuss. A real bug found there is "unmatched", not a false positive. It has no credit.
- One NodeGoat correction: I first read the tutorial's plaintext password and plaintext SSN bugs as already fixed, because the bcrypt and encryption code was there. That code is inside comments. Both are bugs and are in the key now.

### How scans were scored

The automatic matcher is the one from the fixtures: same file, lines within 5, and the finding's label in the item's category family. Matching is one-to-one. I added families for XXE, CSRF, open redirect, ReDoS, vulnerable dependency, authentication weaknesses, plain HTTP, misconfiguration, rate limiting and mass assignment, and let an item list several categories. I widened the authorization family after the first VAmPI scan showed the model writing "Authenticated user can reset another user's password" under the label "missing-validation". That change followed seeing scan output.

The automatic recall is too low for another reason: the model often words a correct finding in a way no family recognises (for example "predictable password-reset token"). So the matcher also reports near misses (a finding on an item's lines whose label fits no family), and I read every near miss and every credited title by hand. The "after review" column counts an item when a finding sits on it and I did not reject the wording. The reject lists are in the keys (`nearMissIgnore`, `nearMissReject`). The strict number is a lower bound and the reviewed number is an upper bound. I rejected, for example, a finding about TLS that the matcher had credited to DVNA's query-logging item.

The engine now files each finding under a class with the same rules, so the label no longer depends on the model's wording (see Finding categories in the findings page). The matcher maps those categories to families directly. The saved scans hold titles and labels only, not descriptions, so scoring them again uses the title and the label. Run `node scripts/bench/real-apps.mjs --report --out <dir>` to score saved scans again with the current rules, or add `--stored-families` for the families the scan was scored with.

On the 60 saved scans, averaged over the three apps, the strict score was 58.0 percent with the families stored at scan time (which could also read the description) and 55.0 percent when scored again from title and label with the old rules. The hand-reviewed score is 72.0 percent. With the new rules the strict score is 67.7 percent and the gap to the reviewed score falls from 14.0 points (17.0 with the old rules on title and label) to 4.4. Per app the strict score is 68.2 percent for VAmPI, 60.1 for NodeGoat and 74.7 for DVNA, and the gaps are 0.4, 2.5 and 10.4 points. Part of the new patterns, such as the NoSQL `$where` match and the cookie-flag wording, were added after reading these scans, so this measures the answer keys these three apps already had. It is not a result on other applications. What is left is mostly findings that a person credits but whose class differs from the key's (a password-hash listing credited to the missing admin check).

### Results

Default model (gpt-6-luna), fresh `HOME` per scan, `--budget 2`. Strict is the automatic matcher, reviewed is after my review, each as mean with min-max over the repeats. Scans ran up to six at a time on one machine, so times are inflated and not comparable with other sections.

DVNA (17 items):

| config | scans | strict | reviewed | unmatched findings | cost per scan | time (s) | status and coverage |
|---|---|---|---|---|---|---|---|
| default (foxguard pre-pass on) | 3 | 73% (71-76) | 86% (82-88) | 6.7 | $0.229 | 971 (607-1228) | 1 partial: 27 of 43 entry points, 16 not reached after a thread failure; others complete |
| `--prepass off` | 4 | 69% (65-71) | 85% (82-88) | 5.3 | $0.227 | 789 (648-917) | complete, 43 of 43 |
| `--scanner foxguard,semgrep` | 4 | 69% (59-82) | 84% (70-88) | 8.3 | $0.230 | 848 (729-941) | complete, 43 of 43 |
| `--batches on --batch-size 8` | 3 | 61% (53-76) | 82% (76-88) | 7.0 | $0.175 | 340 (329-354) | 1 partial, others 43 of 43 |
| `--batches off` | 3 | 65% (59-76) | 86% (82-88) | 3.7 | $0.076 | 182 (129-208) | 1 failed, others complete |

NodeGoat (17 items):

| config | scans | strict | reviewed | unmatched findings | cost per scan | time (s) | status and coverage |
|---|---|---|---|---|---|---|---|
| default | 3 | 45% (35-53) | 59% (47-70) | 12.3 | $0.306 | 1120 (728-1505) | 1 timed out at 1500 s with 0 of 7 other-file groups reviewed; 27 of 27 entry points |
| `--prepass off` | 4 | 44% (41-53) | 62% (52-70) | 14.5 | $0.297 | 1113 (751-1394) | 1 partial, others complete |
| `--scanner foxguard,semgrep` | 3 | 53% (41-65) | 63% (58-64) | 13.0 | $0.300 | 970 (653-1509) | 1 timed out |
| `--batches on --batch-size 8` | 2 | 44% (41-47) | 68% (64-70) | 18.0 | $0.341 | 408 (299-517) | complete |
| `--batches off` | 2 | 53% (53) | 65% (58-70) | 7.5 | $0.128 | 299 (275-323) | complete |

VAmPI (9 items, 6 decoys):

| config | scans | strict | reviewed | unmatched findings | decoy hits | cost per scan | time (s) |
|---|---|---|---|---|---|---|---|
| default | 5 | 58% (33-67) | 67% (66) | 2.4 | 0.2 raw, 0 real | $0.012 | 116 (95-139) |
| `--prepass off` | 6 | 67% (56-78) | 74% (66-77) | 1.5 | 0.3 raw, 0 real | $0.010 | 98 (89-131) |
| `--scanner foxguard,semgrep` | 6 | 54% (44-67) | 67% (66) | 3.7 | 0.7 raw, 0 real | $0.013 | 126 (98-158) |
| `--batches on --batch-size 8` | 6 | 57% (56-67) | 69% (66-77) | 2.5 | 0.2 raw, 0 real | $0.018 | 109 (91-131) |
| `--batches off` | 6 | 59% (44-67) | 67% (66) | 1.7 | 0.2 raw, 0 real | $0.010 | 86 (68-100) |

What the tables say:

- No configuration is better than another on any app. Every difference between configs is smaller than the spread between repeats of one config. The foxguard pre-pass, the foxguard and Semgrep pre-pass and batching did not change recall measurably, as on the synthetic fixtures.
- Reviewed recall is about 85% on DVNA, 60 to 68% on NodeGoat and 67 to 74% on VAmPI. Strict recall is 10 to 25 points lower. The gap is wording, not misses.
- The default scan already splits a folder with more than 8 entry points into batches (`--batches auto`). On DVNA (43 entry points) and NodeGoat (27) the default and the explicit batched config therefore differ only in concurrency (1 against 3 batches at a time), which is why the batched config is 2 to 3 times faster. The only single-thread config is `--batches off`. It was the cheapest on both (about a third of the cost) and its recall is inside the range of the others. On VAmPI the inventory finds one entry point (Connexion takes its routes from the OpenAPI file), so there was nothing to split and all five configs are single-thread in effect.
- Decoy hits on VAmPI are 9 over 29 scans. I read all nine. Each is a correct finding on the vulnerable branch whose line range reaches the safe branch (for example a finding on lines 60 to 66 against a safe branch starting at 67). None is a false positive on safe code. The count that matters is therefore 0 of 29 scans, but the matcher's raw number is not 0.
- The foxguard pre-pass gave the scan 4 to 10 leads per app. Its leads covered the SQL injection, command injection, `eval`, deserialization, hardcoded secrets and one ReDoS (NodeGoat), and none of the authorization, CSRF, XSS or logic bugs.
- Cost per scan is $0.01 to $0.34. The whole run is $7.58 over 60 scans that wrote a report, plus up to about $1 for scans I killed after a launch mistake and whose cost was not recorded. The cap was $18.

### Unmatched findings, read by hand

For the 10 highest severity distinct unmatched clusters per app (deduplicated across scans), by reading the code:

| app | real and exploitable | real, low value | not a useful finding |
|---|---|---|---|
| DVNA | 4: the open redirect and SQL injection reported at their route, CSRF on session routes, stored XSS in the product list, logout CSRF (these are variants of key items or a documented class at another place) | 1: unbounded session store | 5: unquoted environment variable in the entrypoint (operator-set, not attacker-reachable), plain-HTTP port, MySQL without TLS, two cookie hygiene duplicates, synchronous bcrypt |
| NodeGoat | 8: hardcoded session secret, stored XSS in the benefits table, seeded admin password in the reset script (two reports), reflected XSS in login, profile and signup, benefits changes by any user (a variant of a key item), HTML relayed by the research route | 0 | 2: shell injection in a Grunt task whose argument comes from the developer's command line (one issue reported twice) |
| VAmPI | 6: public database reset, seeded admin with a known password, plaintext passwords (two reports), debugger on, mutable CI action tags, container runs as root | 1: public book list | 1: example token in the API spec |

Most of what the scan reports beyond the key is real. NodeGoat's key lists one XSS item but the same root cause (template autoescape off) shows in many views, and the scan reports each. The weak findings are infrastructure hygiene and operator-controlled input.

### What the scan missed and why

Misses that happened in every or almost every repeat. "Pointed at" means foxguard reported that file on the scanned copy (run by hand with the same copy). "Opened" means a tool call in the scan's saved transcript names the file. That is evidence of looking, not of reading the right lines.

DVNA:
- Query logging (`models/index.js`, no `logging: false`). A configuration omission, not a code pattern. The pre-pass did not point at it. The file was named in tool calls in 18 of 19 scans on this app, so the model saw it and did not report it. A scan that credited it was a TLS finding on the same lines, which I rejected.
- Stack trace in the calculator (`core/appHandler.js`). The route was reviewed and reported as code execution through the old mathjs. The missing error handling was never reported as its own issue. The pre-pass had no hit there.
- CSRF on the forms. No line holds an absence. Scans reported missing CSRF protection in a few runs at other lines, and reported the authorization problems on the same forms.

NodeGoat:
- Password policy, username enumeration and cookie flags (`session.js`, `server.js`). All three are weak-rule or absent-flag issues. The pre-pass hit only the session store flags (`saveUninitialized`, `resave`). Scans found "one-character passwords" and "unknown user versus wrong password" in some runs under other wording, which the review counts. The files were opened in 16 of 16 scans.
- The old `marked` version (`package.json`). Never reported as a vulnerable dependency, and the pre-pass did not hit it. The scan reported the memo CSRF and XSS instead.
- Plaintext SSN and date of birth (`profile-dao.js`). The file was named in tool calls in only 12 of 16 scans, the one clear case of a file that was often not opened. The comment blanking leaves the plain assignments looking like ordinary code.

VAmPI:
- ReDoS in the email check. Missed in every scan of every config. The pre-pass has no regex rule for Python. The file was opened every time, so the model read the regex and did not judge it exploitable.
- Rate limiting. An absence, never reported as such.
- Username enumeration. Found in most configs, missed in every repeat of four of five. Where it was found the finding was filed as information disclosure.

The pattern across the three apps: the scan opens the files, and the misses are judgement calls on configuration, absent controls and regexes, not unread code. A pre-pass that hits only well-known sink patterns does not point at them.

### Scan skill variants for missing controls

The misses above are missing controls, configuration, regexes and logging. I tested whether more instructions in the scan skill fix them. Date 2026-11-23, default model (gpt-6-luna), 6 repeats per arm and app, `--batches off --prepass off` (the `lean` config), fresh `HOME` per scan. Arms ran in the same time window, one scan per arm at a time. Total spend $3.63 over 48 scans.

The arms add text to the scan skill, before the "Prove from the code" step:
- base: the skill as shipped.
- A: a per-entry-point control table (authentication, ownership, validation, output encoding, rate limit, session and token handling, secrets and config, error and log exposure, crypto and randomness). Each absent or weak control is a finding.
- BC: a pass over bootstrap, middleware order, debug settings and manifests, and a pass over every regex applied to input, judged for backtracking.
- ABC: all of the above.

I tuned on DVNA only. Then I ran base and ABC on NodeGoat and VAmPI, which I did not read while tuning. The p value is a two-sided permutation test on the mean of 6 against 6.

DVNA (17 items), tuning app:

| arm | strict found (min-max) | reviewed found (min-max) | unmatched findings | cost per scan | p strict, reviewed |
|---|---|---|---|---|---|
| base | 10.0 (9-12) | 13.8 (13-14) | 2.8 | $0.077 | - |
| A | 9.3 (8-11) | 13.0 (12-15) | 3.5 | $0.079 | 0.48, 0.25 |
| BC | 9.7 (8-11) | 14.2 (13-15) | 3.5 | $0.085 | 0.80, 0.71 |
| ABC | 10.0 (8-11) | 14.3 (12-16) | 5.2 | $0.074 | 1.00, 0.59 |

The three classes the arms target did not move. Query logging and the calculator stack trace were found 0 of 6 times in every arm. The unprotected users API was found 0 of 6 (base), 2 of 6 (A), 2 of 6 (BC) and 0 of 6 (ABC). The reset token hash was found 3, 1, 3 and 0 of 6 times. ABC raised unmatched findings from 2.8 to 5.2 (p 0.04).

Validation, base against ABC:

| app | arm | strict found (min-max) | reviewed found (min-max) | unmatched findings | cost per scan |
|---|---|---|---|---|---|
| NodeGoat (17) | base | 6.8 (4-8) | 9.8 (5-14) | 6.0 | $0.102 |
| NodeGoat (17) | ABC | 7.2 (6-9) | 10.0 (8-13) | 9.7 | $0.154 |
| VAmPI (9) | base | 6.2 (5-7) | 6.7 (6-7) | 1.7 | $0.019 |
| VAmPI (9) | ABC | 6.5 (6-8) | 7.8 (7-9) | 2.3 | $0.014 |

NodeGoat shows no change (p 0.83 strict, 1.00 reviewed), more unmatched findings, and 51 percent more cost per scan. VAmPI shows no strict change (p 0.73) and one more reviewed item (p 0.03). The reviewed column uses the harness's automatic adjudication with the reject lists of the earlier runs. I did not re-read near misses by hand for these scans, so treat reviewed numbers as approximate.

Result: no variant was kept. None improved recall on DVNA beyond the spread between repeats, and ABC did not improve NodeGoat, the second validation app. The shipped skill is unchanged. The synthetic fixtures were not rerun, because nothing changed.

Marking a unit reviewed only when the model opened its files is not reliable. The scan reads files through `bash` (cat, sed, grep) and delegates to helper threads through `spawn_agent`. A saved thread lists those tool calls, but whether a command opened a file can only be guessed from the command text, and helper threads are separate. The earlier DVNA check found the missed files were opened in 18 of 19 scans, so a gate on opening would not have caught those misses.

### What this does not prove

- Three apps, 9 to 17 items each, 2 to 6 scans per cell. A cell's range is two or three runs, so differences of one or two items are noise.
- These apps are famous. Models may have seen the code, its tutorial or its solutions, so recall may be higher than on a private codebase. The comment blanking removes the in-code answers but not memory of the project.
- The answer keys follow the projects' documents, but the line ranges are mine, and VAmPI's are all mine. Ranges are whole functions, so a wrong finding in the same function can be credited. The "reviewed" number is an upper bound that depends on my reading, and I wrote the reject lists after seeing the findings.
- The matcher families were extended after the first scans. The strict numbers are not comparable with the earlier sections.
- Precision is barely measured. Only VAmPI has documented-safe code, and its six safe branches produced no real false positive. The hand-read unmatched sample is 10 clusters per app by severity, not a random sample, and I judged them from the code without running anything.
- Scans ran in parallel, one run killed by a launch mistake, and the model, provider and load vary. Time and some failures (one timeout, one failed thread, one failed scan) belong to that run.
- Nothing here measures fixes, severity or the quality of the reports.

## Adding a fixture

1. Create `scripts/bench/fixtures/<name>/` with a small app (under 150 lines) in its own language. Keep each bug on a few lines and add at least one decoy: safe code shaped like a bug.
2. Write `answer.json` with `"fixture": "<name>"` equal to the folder, `skill` or `null`, `items` and `decoys`. Paths are relative to the fixture folder; lines are 1-based and inclusive; `category` is one of the families in `match.mjs` (`FAMILIES`). Add a new family there, with a pattern and a test, if none fits.
3. Run `node scripts/bench/run.mjs --dry-run`. It checks that every path exists, that line ranges are inside the file, that categories are known, and that synthetic findings placed on the key score as expected.
4. Never put the answer in the app's comments or file names: the model sees the whole folder except `answer.json`.
