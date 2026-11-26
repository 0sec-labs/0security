---
title: Enterprise evaluation flow without a model
description: A repeatable, model-free run for a self-hosted Java evaluation. Scan a pinned public Java project with the scanner, validate and import the SARIF, triage with reasons, compare two commits, export reports and build the Bitbucket Code Insights payload to a file.
---

This is the flow we use to show an enterprise Java team on Bitbucket, Jenkins and AWS what the self-hosted engine does before any model is connected. It scans a public Java project at a pinned commit with the pattern scanner only. It makes no model request and does not contact Bitbucket, AWS or an identity provider. One script runs all nine steps, prints what each step proves and stops at the first step that does not hold.

## Run it

From a checkout of this repository, with `git`, `node`, `pnpm`, a Rust toolchain and `python3` with the `jsonschema` package installed:

```bash
bash scripts/demo/enterprise-flow.sh --keep
```

It builds the CLI from `packages/cli` and the scanner from `crates/foxguard` (through `scripts/build-foxguard.sh`), then works in a temporary folder with its own `HOME`, so nothing from your machine's findings or settings leaks in. `--keep` leaves the artifacts for you to open. `--workdir <empty folder>` chooses where. The released CLI does not have `findings rollup --since` or `findings upload` yet, so the script builds the CLI from the checkout; set `ZEROSEC_BIN` to use another build.

The only network use is fetching the pinned checkout from GitHub and the pinned SARIF schema from raw.githubusercontent.com.

## The pinned inputs

- Project: [WebGoat](https://github.com/WebGoat/WebGoat), a public Maven project that is vulnerable on purpose. It is a stand-in for a large Java code base; it is not the evaluation target.
- Head commit: `4e98f1cbbf896fdd06edcc9930515ebe0ade7c69`, with 498 Java files.
- Base commit: `bf79d42ee52920b4752d9caed0e496c85d947dbb`, the commit before a new lesson was added.
- SARIF schema: the OASIS `sarif-schema-2.1.0.json` at spec commit `1742a253eb654bf8a4ed7c60eaef7412b2c23553`, checked against SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` before use.

Override the project with `DEMO_REPO_URL`, `DEMO_BASE_SHA` and `DEMO_HEAD_SHA`. A different project gives different counts; the checks that compare counts with each other still apply.

## The steps and the commands behind them

The script wraps each command in a check. The commands, as you would type them:

```bash
# 3. Scan with the pattern scanner only. The tier file turns the model off.
echo '{"default":"standard","tiers":{"standard":{"prepassOnly":true}}}' > tiers.json
0security scan ./webgoat --tiers tiers.json --format sarif -o head.sarif

# 5. Import into a findings database
0security findings import head.sarif --root ./webgoat --db-path findings.db

# 6. Triage with named reasons
0security findings accept <id> --db-path findings.db --reason "Lesson code, vulnerable on purpose" --expires 90d --approver "security-lead"
0security findings suppress <id> --db-path findings.db --note "Test fixture" --approver "security-lead"
0security findings list --db-path findings.db --expiring 200
0security findings show <id> --db-path findings.db

# 7. Opened and fixed since the earlier commit
0security findings rollup base.sarif --repository webgoat --export base.rollup.json
0security findings rollup head.sarif --repository webgoat --since base.rollup.json

# 8. Export
0security findings export --db-path findings.db --format html -o report.html

# 9. Code Insights payload, printed instead of posted
0security findings upload head.sarif --to bitbucket-cloud --repo workspace/repo --commit <sha> --print > code-insights.json
```

| Step | What it proves | What makes it fail |
| --- | --- | --- |
| 1. Build | The CLI and the scanner come from this checkout. | A build error, or a CLI without `findings rollup`. |
| 2. Fetch | The inputs are fixed by commit. | A commit that cannot be fetched. |
| 3. Scan | The scan ran with no model: the log says "no model review" and each finding is marked as a pre-pass finding. | No findings, a missing SARIF file, or a log that does not state the tier. |
| 4. Validate | The SARIF is valid 2.1.0 against a pinned schema. | Any schema error, or a schema file that does not match its hash. |
| 5. Import | The imported count equals the SARIF result count. | A different count, or an empty database. |
| 6. Triage | Accept-risk records a reason, an expiry and an approver, shows on `findings show`, and appears under `--expiring`. | A wrong count of accepted or suppressed findings, or a missing reason. |
| 7. Compare | The base count plus opened minus fixed equals the head count, and the new-only queue is smaller than the backlog. | Any difference in the arithmetic. |
| 8. Export | JSON, Markdown, SARIF and HTML are written and the exported SARIF is valid. | An empty file or a schema error. |
| 9. Code Insights | The payload has a report and annotations, each request holds at most 100 and the report at most 1000, and emitted plus dropped equals the total. | A limit exceeded or counts that do not add up. |

## Measured on one machine

Run on an Apple M1 Max with macOS 26.2, Node 26.9 and the 0.45.0 source, with Foxguard 0.14.3. These are one machine's numbers from one warm run; the compile steps were already cached.

| Measure | Result |
| --- | --- |
| Whole script | 37 seconds |
| Scan of the head commit | 3 seconds, 498 Java files |
| Scan of the base commit | 3 seconds |
| Findings at head | 144: 141 high (SARIF level error), 3 medium (level warning), 0 critical, 0 low |
| Findings at base | 131 |
| Head against base | 14 opened, 1 fixed, net +13 (131 + 14 - 1 = 144) |
| SARIF schema errors | 0 |
| Import | 144 findings, database holds 144 rows |
| Triage | 2 accepted with expiry (90 and 180 days), 1 suppressed |
| Code Insights payload | 144 annotations in 2 requests (100 and 44), 0 dropped |
| Cold builds | Foxguard release build 1 minute 23 seconds on the same machine; `pnpm install` and the CLI build about 15 seconds |

The checkout holds more than Java: the scan covers the whole folder, and some findings are in JavaScript. The script prints how many findings are in `.java` files.

Counts should repeat for the same commits and scanner build. A newer scanner can change them; compare the scanner version printed in step 1 first.

## What this does not prove

- Model-driven accuracy. Every finding here is a pattern-scanner lead. Nothing was triaged, verified or fixed by a model, so there is no precision, recall or false-positive rate for the agent layer. Do not read the 144 findings as true positives; WebGoat is vulnerable on purpose.
- Fix quality. No fix was generated, built or tested. See [Java verification](/java-verification/) for the verifier.
- A live Bitbucket. The payload was built to a file and never sent. Real annotations on a pull request, Data Center limits and token scopes are untested here; `ci/rehearsal/bitbucket-cloud.sh` is the script for that and has not been run against a live workspace.
- Jenkins, Bitbucket Pipelines or the pull request trigger. No pipeline ran.
- AWS or an identity provider. No deployment, sign-in or audit-log attribution of the named user happened. The `--approver` value is a label you type, not a login.
- Scale. 498 files and 3 seconds say nothing about a repository of a million lines with a build; `docs/qualification/enterprise-completion-status.md` records the Keycloak scanner timing.
- The Code Insights report text says "triaged findings", but in this flow they are untriaged scanner leads. Say so when you show the payload.
- PDF export. Only JSON, Markdown, SARIF and HTML are checked.

## Next steps for a real evaluation

1. Point the script at the team's repository by setting `DEMO_REPO_URL` and two commits, or run the commands above on a local clone.
2. Add a model endpoint under [Models](/models/) and repeat step 3 without the tier file to see the agent layer. Set `--budget` first.
3. Rehearse [Pull request checks](/ci/) on a real Bitbucket workspace.
