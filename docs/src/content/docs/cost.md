---
title: Plan the cost of a large estate
description: "Cover many repositories with three layers: the pattern scanner everywhere, a model review of each pull request, and a full model audit for chosen repositories. Includes measured cost and time."
---

Three layers keep the cost of a large estate predictable. The pattern scanner runs on everything. A model reviews the diff of each pull request. A full model audit runs only on the repositories you choose. This page shows how to set each up and what each cost in our measurements.

## Layer 1: scan everything with the pattern scanner

The scanner needs no model and costs nothing. Set `prepassOnly` in a tier to run it alone:

```yaml
version: 1
default: light
tiers:
  light: { prepassOnly: true, reason: scanner only }
```

```bash
0security scan ~/code/app --tiers ~/security/scan-tiers.yaml
```

Its hits are leads that no model reviewed, and the report says so. A pattern scanner cannot see logic bugs such as a missing ownership check. See [Set the effort per repository](/commands/#set-the-effort-per-repository) for the tier file.

## Layer 2: review the diff of each pull request

A model reviews only the files a pull request changes and the code they connect to:

```bash
0security scan . --diff origin/main --format sarif -o scan.sarif --budget 1
```

The cost follows how much changes, not how big the repository is. See [Pull request checks](/ci/) for the Action and the Bitbucket, Jenkins and Azure Pipelines templates.

## Layer 3: audit chosen repositories in full

Give a repository a tier that turns batches on and sets a budget:

```yaml
tiers:
  critical: { budget: 20, batches: on, reason: handles payments }
repositories:
  - repo: your-org/payments
    tier: critical
```

Check the size of the work before you pay for it. `--plan` lists the entry points, the batches and a rough cost range, and calls no model:

```bash
0security scan ~/code/payments --tiers ~/security/scan-tiers.yaml --plan
```

Run the audit. If it stops at the budget or the time limit, it exits with code 3 and keeps its findings. Continue it with `--resume`:

```bash
0security scan ~/code/payments --tiers ~/security/scan-tiers.yaml --concurrency 3 --timeout 1800
0security scan ~/code/payments --tiers ~/security/scan-tiers.yaml --resume latest
```

## What each layer cost

These are single runs with the model `gpt-6-luna`, priced from token usage. They are estimates, not invoices.

| Layer | Input | Cost | Time |
| --- | --- | --- | --- |
| Scanner only | Keycloak, 1,316,081 Java lines | $0 | 23.8 seconds |
| Scanner only | WebGoat, 35,209 Java lines | $0 | 2.4 seconds |
| Diff review | One changed file | about $0.002 | not measured |
| Full audit | A 3,964-line Keycloak package | about $0.023 | not measured |
| Full audit | spring-petclinic, 4.3k lines | $0.105 | not measured |
| Full audit | gson, 58.6k lines | $0.52 | not measured |
| Full audit | WebGoat, 35,209 lines | about $1.79 | about 34 minutes at concurrency 3 |

The full audits cost between $0.006 and $0.051 per 1,000 lines. Cost follows how many findings the model investigates, so a code base with fewer issues costs less per line.

The WebGoat audit hit a 1,800-second timeout after 58 batches and $1.64. `--resume` finished the rest in 224 seconds for $0.15. All 327 entry points and 149 groups of other files were opened.

## What the numbers do not tell you

- Each audit is one run. Rate limits, denser code, several passes and a more expensive model change the cost.
- No audit of a large project has been measured. Scaling these rates to 60 million lines gives roughly $3,000 and 40 days at concurrency 3. That is arithmetic, not a measurement. It shows that time limits a full audit before money does, so audit only the repositories that need it.
- Precision and recall are not measured. On spring-petclinic and gson, none of the model findings read by hand was a misread, and none was confirmed as a true positive. Of 20 scanner leads read by hand, none was real.
- A budget is a soft limit. A request already running can push the cost past it. Use a limit at your model provider for a hard cap.

Set `--budget` on every scan, and review the first audit of each repository before you plan the rest.
