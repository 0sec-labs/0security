# Planted-bug benchmark

A small benchmark to measure whether scans and skills help: tiny apps with known planted bugs, an answer key, and a runner that scans each one and scores the findings. Code: `scripts/bench/`. It is plain Node ESM, not a pnpm package, with no dependencies.

## How it works

- `scripts/bench/fixtures/<name>/` is one app (under 150 lines) plus `answer.json`. The answer key lists `items` (planted bugs: `id`, `path`, `startLine`, `endLine`, `category`, `description`) and `decoys` (code that looks risky but is safe). `skill` names the skill the fixture is meant for, or `null`. `clean: true` marks the app with no bugs at all.
- Fixtures: `node-express` (SQL injection, command injection, path traversal, hardcoded secret), `python-flask` (SSRF, pickle, `yaml.load`, MD5), `go-http` (SQL injection, `template.HTML` XSS, hardcoded key), `llm-app` (prompt injection into a shell tool, secrets in the prompt, unescaped model output; skill `llm-app-review`), `crypto-app` (RSA, SHA-1, ECB, weak key derivation; skill `crypto-migration`) and `clean-app` (the same shapes as `node-express`, written safely).
- `run.mjs` copies each fixture without `answer.json` into a temporary folder, so the model cannot read the key. It runs `node packages/cli/dist/index.js scan <copy> --budget <n> --format json -o <out>` with a fresh `HOME` (and XDG directories) per run, then parses the findings.
- Configurations: `generic` (`--prepass off`), `skill` (`--skill <id>`, only for fixtures that name one), `foxguard` (`--prepass auto --scanner foxguard`, needs foxguard installed). The default is `generic,skill`.
- Matching (`match.mjs`, pure, unit tested): a finding finds a planted item when the path agrees (suffix match), its line range is within 5 lines of the item's, and it belongs to the item's category family (from the finding's category, then title, then description). Matching is one-to-one, so a single finding never credits two items. A finding on a decoy (within 2 lines), or any finding in the clean app, is a false positive. A finding that is neither is reported as "unmatched" (a real extra issue or noise; read them) and is not counted as a false positive.
- The report is Markdown and JSON in `scripts/bench/results/` (git-ignored apart from `example.md`): recall, false positives, unmatched, cost and time per fixture and configuration, as mean with min-max over repeats.

## Running it

```bash
node --test scripts/bench/match.test.mjs
node scripts/bench/run.mjs --dry-run                       # validates fixtures and the matcher; no model, no cost
node scripts/bench/run.mjs --run --repeat 2 --budget 0.2   # really scans; prints the worst-case cost first
```

`--run` is required to spend money; each scan stops at `--budget`, and the estimate printed is runs times budget. Other options: `--configs generic,skill,foxguard`, `--fixtures a,b`, `--model <id>`, `--out <dir>`, `--timeout <s>`. The dry run is part of `node scripts/run-checks.mjs static`.

## What it does not prove

- Six tiny, synthetic apps with obvious bugs. A high recall here says the scan is not blind, not that it finds bugs in a real codebase; the planted bugs are textbook shapes models have seen.
- The answer key is ours. Findings that are real but unplanted are listed as unmatched, not credited; false positives are only counted on decoys and the clean app, so precision on real code is not measured.
- A repeat count of 2 to 3 gives a range, not a confidence interval. Treat differences smaller than the spread as noise. Model output varies between runs and between model versions.
- The category-family and line-proximity matching is heuristic: a correct finding with an unusual category or wrong line can be missed, and a vague one nearby can be credited.
- Cost and time depend on the model, the provider and load on the day. Compare configurations from the same run.
- Skill fixtures are written by the same team as the skills; a skill that scores well on its own fixture may have been tuned to it.

## Adding a fixture

1. Create `scripts/bench/fixtures/<name>/` with a small app (under 150 lines) in its own language. Keep each bug on a few lines and add at least one decoy: safe code shaped like a bug.
2. Write `answer.json` with `"fixture": "<name>"` equal to the folder, `skill` or `null`, `items` and `decoys`. Paths are relative to the fixture folder; lines are 1-based and inclusive; `category` is one of the families in `match.mjs` (`FAMILIES`). Add a new family there, with a pattern and a test, if none fits.
3. Run `node scripts/bench/run.mjs --dry-run`. It checks that every path exists, that line ranges are inside the file, that categories are known, and that synthetic findings placed on the key score as expected.
4. Never put the answer in the app's comments or file names: the model sees the whole folder except `answer.json`.
