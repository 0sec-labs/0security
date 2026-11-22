# Planted-bug benchmark

> Sample output of one real run (generic and skill configurations). Illustrative only, not a result to rely on; see docs/design/benchmark.md.

- Date: 2026-11-22
- Model: default (gpt-6-luna)
- Repeats: 2
- Per-run budget: $0.15
- Total cost: $0.0852

Recall is planted bugs found / planted bugs. False positives are findings on a decoy, or any finding in the clean app. Unmatched are findings that are neither (real extra issues or noise; read them). Cells show mean, with the min-max range over repeats in brackets.

| fixture | config | recall | found/planted | false pos. | unmatched | cost | time (s) | not complete |
|---|---|---|---|---|---|---|---|---|
| clean-app | generic | n/a (n/a) | 0.0/0 | 1.0 (1) | 0.0 | $0.0040 ($0.0034-$0.0047) | 45 (37-54) | - |
| crypto-app | generic | 83% (67%-100%) | 5.0/6 | 0.0 (0) | 0.0 | $0.0053 ($0.0052-$0.0054) | 70 (63-77) | - |
| crypto-app | skill | 83% (83%) | 5.0/6 | 0.0 (0) | 0.0 | $0.0081 ($0.0070-$0.0092) | 94 (84-105) | - |
| go-http | generic | 100% (100%) | 3.0/3 | 0.0 (0) | 0.0 | $0.0048 ($0.0046-$0.0049) | 63 (61-66) | - |
| llm-app | generic | 75% (75%) | 3.0/4 | 0.0 (0) | 1.0 | $0.0064 ($0.0051-$0.0077) | 77 (71-84) | - |
| llm-app | skill | 38% (25%-50%) | 1.5/4 | 0.0 (0) | 1.0 | $0.0044 ($0.0040-$0.0048) | 58 (50-67) | - |
| node-express | generic | 100% (100%) | 4.0/4 | 0.0 (0) | 0.0 | $0.0051 ($0.0048-$0.0054) | 70 (65-75) | - |
| python-flask | generic | 75% (75%) | 3.0/4 | 0.0 (0) | 0.0 | $0.0045 ($0.0041-$0.0049) | 63 (59-66) | - |

Recall by configuration over the fixtures it ran on (mean of fixture means, so it is not weighted by planted count):

- generic: 87% over 5 fixtures
- skill: 60% over 2 fixtures

What this does not show: see docs/design/benchmark.md. Few tiny fixtures and few repeats; differences smaller than the spread are noise.
