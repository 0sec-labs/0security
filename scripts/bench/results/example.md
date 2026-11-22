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
