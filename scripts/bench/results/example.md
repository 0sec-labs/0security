# Planted-bug benchmark

> Sample output of one real run with the edited scan skill (generic and foxguard configurations). Illustrative only, not a result to rely on; see docs/design/benchmark.md. The before/after comparison for the scan.yaml edit is at the end.
- Date: 2026-11-22
- Model: default (gpt-6-luna)
- Repeats: 3
- Per-run budget: $0.5
- Total cost: $0.2152

Recall is planted bugs found / planted bugs. False positives are findings on a decoy, or any finding in the clean app. Unmatched are findings that are neither (real extra issues or noise; read them). Cells show mean, with the min-max range over repeats in brackets.

| fixture | config | recall | found/planted | false pos. | unmatched | cost | time (s) | not complete |
|---|---|---|---|---|---|---|---|---|
| clean-app | generic | n/a (n/a) | 0.0/0 | 0.7 (0-1) | 0.0 | $0.0037 ($0.0024-$0.0045) | 53 (28-83) | - |
| clean-app | foxguard | n/a (n/a) | 0.0/0 | 0.7 (0-1) | 0.0 | $0.0041 ($0.0032-$0.0049) | 59 (35-92) | - |
| clean-python | generic | n/a (n/a) | 0.0/0 | 0.3 (0-1) | 0.0 | $0.0037 ($0.0022-$0.0056) | 60 (25-122) | - |
| clean-python | foxguard | n/a (n/a) | 0.0/0 | 1.0 (1) | 0.0 | $0.0045 ($0.0035-$0.0052) | 67 (37-122) | - |
| crypto-app | generic | 83% (83%) | 5.0/6 | 0.0 (0) | 0.0 | $0.0062 ($0.0061-$0.0064) | 80 (73-88) | - |
| crypto-app | foxguard | 56% (50%-67%) | 3.3/6 | 0.0 (0) | 0.0 | $0.0054 ($0.0052-$0.0058) | 72 (64-81) | - |
| go-http | generic | 100% (100%) | 3.0/3 | 0.0 (0) | 0.0 | $0.0062 ($0.0051-$0.0077) | 79 (57-107) | - |
| go-http | foxguard | 100% (100%) | 3.0/3 | 0.0 (0) | 1.0 | $0.0054 ($0.0049-$0.0057) | 73 (67-81) | - |
| llm-app | generic | 67% (50%-75%) | 2.7/4 | 0.0 (0) | 0.3 | $0.0047 ($0.0046-$0.0048) | 63 (58-67) | - |
| llm-app | foxguard | 42% (25%-75%) | 1.7/4 | 0.0 (0) | 2.0 | $0.0056 ($0.0054-$0.0058) | 72 (64-77) | - |
| node-express | generic | 100% (100%) | 4.0/4 | 0.0 (0) | 0.0 | $0.0055 ($0.0052-$0.0060) | 70 (55-91) | - |
| node-express | foxguard | 100% (100%) | 4.0/4 | 0.0 (0) | 0.0 | $0.0065 ($0.0055-$0.0081) | 96 (81-108) | - |
| python-flask | generic | 100% (100%) | 4.0/4 | 0.0 (0) | 0.0 | $0.0054 ($0.0041-$0.0068) | 74 (51-102) | - |
| python-flask | foxguard | 100% (100%) | 4.0/4 | 0.0 (0) | 0.0 | $0.0049 ($0.0040-$0.0055) | 74 (52-112) | - |

Recall by configuration over the fixtures it ran on (mean of fixture means, so it is not weighted by planted count):

- generic: 90% over 5 fixtures
- foxguard: 79% over 5 fixtures

Before and after the scan.yaml edit (same model, 3 repeats, budget $0.5; before cost $0.19 plus $0.03 for clean-python, after $0.22). Mean over repeats, recall as found/planted, false positives per scan:

| fixture | config | recall before | recall after | false pos. before | false pos. after |
|---|---|---|---|---|---|
| clean-app | generic | n/a | n/a | 1.0 | 0.7 |
| clean-app | foxguard | n/a | n/a | 1.3 | 0.7 |
| clean-python | generic | n/a | n/a | 1.3 | 0.3 |
| clean-python | foxguard | n/a | n/a | 1.3 | 1.0 |
| crypto-app | generic | 89% | 83% | 0.0 | 0.0 |
| crypto-app | foxguard | 78% | 56% | 0.0 | 0.0 |
| go-http | generic | 100% | 100% | 0.0 | 0.0 |
| go-http | foxguard | 89% | 100% | 0.0 | 0.0 |
| llm-app | generic | 67% | 67% | 0.0 | 0.0 |
| llm-app | foxguard | 58% | 42% | 0.0 | 0.0 |
| node-express | generic | 100% | 100% | 0.0 | 0.0 |
| node-express | foxguard | 100% | 100% | 0.0 | 0.0 |
| python-flask | generic | 83% | 100% | 0.3 | 0.0 |
| python-flask | foxguard | 83% | 100% | 0.0 | 0.0 |

Every clean-app and clean-python false positive in both runs was one finding class: "unauthenticated reads with a client-chosen owner lack an ownership check". The apps really have no authentication on those routes, so this is a defensible note, not a hallucination; the edit asks the model to say why the data is meant to be private. The foxguard drops on crypto-app and llm-app are within or at the edge of the repeat spread.

What this does not show: see docs/design/benchmark.md. Few tiny fixtures and few repeats; differences smaller than the spread are noise.

---

# Fix-quality scorecard

> Real run of `node scripts/bench/fix-score.mjs --run --repeat 2`, 2026-11-23, default model (gpt-6-luna), `--budget 0.5` per fix. Illustrative; see docs/design/benchmark.md.
- Date: 2026-11-23
- Model: default (gpt-6-luna)
- Repeats: 2
- Per-fix budget: $0.5
- Total cost: $0.0467
- Cases: 10

Fix rate: 90% of 20 attempts (range over repeats 90%). A fix counts when 0 committed a change, the project's own tests still pass and the hidden exploit check no longer succeeds.

Committed 100%, tests pass 100%, exploit blocked 90%, only the expected files touched 100% of committed changes. Cost per fixed case $0.0026.

Cells for fixed, committed, tests, exploit and expected files count attempts over the repeats. Lines are added plus removed; cost and time show the mean with min-max over the repeats.

| case | fixed | committed | tests pass | exploit blocked | expected files only | files | lines | cost | time (s) | not complete |
|---|---|---|---|---|---|---|---|---|---|---|
| command-injection | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 16 (15-16) | $0.0029 ($0.0022-$0.0035) | 33 (25-40) | - |
| hardcoded-secret | 0/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2 | 13 (13) | $0.0024 ($0.0022-$0.0025) | 30 (27-32) | - |
| missing-authz | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 15 (15) | $0.0022 ($0.0022-$0.0022) | 24 (22-25) | - |
| open-redirect | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 16 (15-16) | $0.0027 ($0.0025-$0.0030) | 35 (34-36) | - |
| path-traversal | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 32 (20-43) | $0.0027 ($0.0025-$0.0029) | 31 (27-34) | - |
| prototype-pollution | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 11 (11) | $0.0022 ($0.0021-$0.0023) | 27 (27-28) | - |
| sqli | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 8 (7-8) | $0.0018 ($0.0018-$0.0018) | 22 (21-22) | - |
| ssrf-allowlist | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 11 (9-13) | $0.0020 ($0.0019-$0.0022) | 22 (22-22) | - |
| unsafe-eval | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 12 (11-12) | $0.0020 ($0.0017-$0.0022) | 23 (21-25) | - |
| weak-password-hash | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2 | 36 (30-41) | $0.0025 ($0.0024-$0.0026) | 28 (27-29) | - |

Test files were added or edited in: command-injection, hardcoded-secret, missing-authz, open-redirect, path-traversal, prototype-pollution, sqli, ssrf-allowlist, unsafe-eval, weak-password-hash. They are not counted as unexpected files, and scoring runs the original test files.

What this does not show: see docs/design/benchmark.md. Small single-bug repositories and few repeats; differences smaller than the range are noise.

---

# Agent-triage measurement

> Real runs of `node scripts/bench/triage-score.mjs --run`, 2026-11-23, default model (gpt-6-luna), 1 repeat. Two runs of three fixtures each, added together below. Illustrative; see docs/design/benchmark.md.

- Fixtures: clean-app, python-flask, node-express (first run); clean-python, llm-app, go-http (second run)
- Findings checked: 18 (13 real, 1 noise, 4 neither)
- Spend: $0.0598 (verify $0.0286)

Real bugs that verify called false-positive: 0 of 13. Real bugs that --apply suppressed: 0.

| verdict | on real bugs | on noise | on neither | precision | recall |
|---|---|---|---|---|---|
| true-positive | 12 | 1 | 3 | 92% | 92% |
| false-positive | 0 | 0 | 0 | n/a | 0% |
| uncertain | 1 | 0 | 1 | - | - |

The sample has one noise finding (clean-python), and verify called it true-positive, so noise removed is 0 of 1. The triage did not drop real bugs here and did not remove noise either.


---

# Scan skill variants on real applications

> Real runs of `node scripts/bench/real-apps.mjs --run --configs lean`, 2026-11-23, default model (gpt-6-luna), 6 repeats per arm and app, `--budget 1` per scan, $3.63 spent over 48 scans. Arms changed only the scan skill text. Illustrative; see docs/design/benchmark.md, "Scan skill variants for missing controls".

| app | arm | strict found (min-max) | reviewed found (min-max) | unmatched | cost per scan |
|---|---|---|---|---|---|
| DVNA (17) | base | 10.0 (9-12) | 13.8 (13-14) | 2.8 | $0.077 |
| DVNA (17) | control table | 9.3 (8-11) | 13.0 (12-15) | 3.5 | $0.079 |
| DVNA (17) | config and regex pass | 9.7 (8-11) | 14.2 (13-15) | 3.5 | $0.085 |
| DVNA (17) | all | 10.0 (8-11) | 14.3 (12-16) | 5.2 | $0.074 |
| NodeGoat (17) | base | 6.8 (4-8) | 9.8 (5-14) | 6.0 | $0.102 |
| NodeGoat (17) | all | 7.2 (6-9) | 10.0 (8-13) | 9.7 | $0.154 |
| VAmPI (9) | base | 6.2 (5-7) | 6.7 (6-7) | 1.7 | $0.019 |
| VAmPI (9) | all | 6.5 (6-8) | 7.8 (7-9) | 2.3 | $0.014 |

No variant was kept. Reviewed numbers use the automatic adjudication, not a fresh hand review.
