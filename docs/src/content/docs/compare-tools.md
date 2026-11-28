---
title: Compare tools on one repository
description: Scan one small repository with each tool, write a reviewable sheet of the findings, and judge them by hand.
---

Evaluators compare security tools by running each on the same small repository and judging the findings by hand. This recipe gives 0security's side of that comparison in one folder. It is a way to look at findings together. It is not a benchmark.

## Pin the repository

Every tool must read the same code. Check out one commit and do not edit the folder while the tools run.

```bash
git clone https://github.com/acme/small-app && cd small-app
git checkout 3f2a9c1
git status --short            # empty: the sheet records an uncommitted change as a caveat
```

## Scan and write the sheet

```bash
0security scan . --model gpt-6-luna --budget 1 --evaluation-sheet ../sheets/0security
```

The sheet folder must be new or empty and outside the repository. The command refuses a folder that already has files before it spends anything. The folder has `review.csv`, `findings.json`, `run.json` and a `README.md`. `run.json` holds the command, the CLI version, the commit, the model, the cost, the time, the version of each pattern scanner and what the scan covered.

To write the sheet again later from stored findings, for example for an older scan:

```bash
0security findings export --scan <scan-id> --format sheet -o ../sheets/0security-again --source .
```

That sheet writes `not recorded` for the cost, model, scanner versions and coverage, which the findings database does not keep.

## Bring the other tools to the same sheet

Run each other tool on the same commit and put its findings in the same columns: location, severity, title, and the tool's own explanation. Judge all of them in one spreadsheet, and where you can, hide which tool wrote which row. Keep each tool's cost, time and version next to its rows. `0security findings import` reads SARIF from tools that write it, so their findings can also be written to a sheet with `--format sheet`.

## Judge

Open `review.csv`. For each row read the code at the location and mark exactly one of `true positive`, `false positive` or `unsure`, and write why in `notes`. Two people who judge the same sheet should first check the list hash in the README. Where they disagree, read the code together and record the reason.

## What the result means

- The marks are an opinion about this repository, from these reviewers.
- A tool that reports little may have reviewed little. Read the coverage line in `run.json` before you count its findings.
- Counting the real flaws no tool found needs a labelled answer key. That is a different job from this sheet.
- The sheet says `not verified` for a finding nothing checked. A model's own explanation of a fix has not been tried.
