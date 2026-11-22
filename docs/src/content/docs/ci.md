---
title: Pull request checks (GitHub Action)
description: Scan only what a pull request changes with the 0 Action, and show the findings in GitHub's Security tab.
---

The 0 Action scans the files a pull request changes and uploads the result to GitHub code scanning. Add it to a workflow to see findings in the repository's **Security** tab and as annotations on the pull request.

The action needs no server. It installs a verified release of `0`, runs `0 scan --diff`, and uploads the SARIF file with `0 findings upload`.

```yaml
name: 0 security
on: pull_request

permissions:
  contents: read
  security-events: write   # upload to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 0sec-labs/0security@v0.41.0
        with:
          version: 0.41.0 # Pin the CLI
          fail-on: high
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Set the key of the provider for your model (see [Models](/models/)). The default model needs `OPENAI_API_KEY`.

## What the action does

1. Installs the release you pin in `version`. The installer refuses a download whose checksum does not match the release's `checksums.txt`.
2. Compares the pull request with its base branch and scans only the files that differ and the code they connect to. This costs a fraction of a full scan. A FoxGuard pattern scan runs first, and its hits go to the scan as leads.
3. Uploads the findings to code scanning with `0 findings upload`. Alerts match by fingerprint, so pushing again updates them.
4. Fails the job when a finding is at or above `fail-on`. The upload happens first, so the findings show either way.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | required | Release of 0 to install, for example `0.41.0`. |
| `target` | `.` | Folder to scan, relative to the workspace. |
| `diff-base` | the pull request's base branch | Git ref to compare with. Outside a pull request, empty scans the whole folder. |
| `model` | the default model | Model for the scan thread. |
| `budget` | `5` | Stop at this many USD. The findings so far are kept and the job warns that they are partial. |
| `passes` | `1` | Scan this many times and merge the findings; the budget is split between them. |
| `fail-on` | none | Fail at or above this severity: `critical`, `high`, `medium`, `low` or `info`. |
| `upload` | `true` | Upload to code scanning. Needs `security-events: write`. |
| `github-token` | the job's token | Token used for the upload. |

Outputs are `sarif` (the file path) and `exit-code`. The exit code is 0 when the scan finishes, 1 when a finding is at or above `fail-on` or the scan fails, 2 for a usage error and 3 when the scan stops at the budget.

## Limits

- Only pull requests from the same repository work. A fork's pull request has no access to your secrets, so it cannot run a model. Do not use `pull_request_target` to get around this: it runs a model on untrusted code with your key.
- Use the default checkout. On a pull request it checks out the merge commit, so comparing with the base branch gives exactly the change.
- Code scanning needs a supported plan. On private repositories it is part of GitHub Code Security.
- A clean run means the model found nothing. It does not mean the code is safe. The report says what the scan covered.

## Keep an SBOM and check it for advisories

The EU Cyber Resilience Act expects a manufacturer to keep an SBOM and check it for advisories regularly. A scheduled job can regenerate the SBOM from your lockfiles and fail when a component has a known advisory. The lookup uses the public OSV database.

```yaml
name: dependency advisories
on:
  schedule:
    - cron: "17 5 * * *"
  workflow_dispatch:

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install 0
        run: |
          VERSION=0.41.0 # Pin the CLI
          RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" INSTALL_DIR="$RUNNER_TEMP/0" sh <(curl -fsSL "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh")
          echo "$RUNNER_TEMP/0" >> "$GITHUB_PATH"
      - run: 0 sbom generate . -o sbom.cdx.json
      - run: 0 sbom check sbom.cdx.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: sbom, path: sbom.cdx.json }
```

`0 sbom check` exits 1 when it finds an advisory, which fails the job. The output is evidence for your records. It does not make a product compliant.

## Collect evidence and draft vulnerability reports

The Cyber Resilience Act (Regulation (EU) 2024/2847) requires a manufacturer to keep records of security testing and vulnerability handling, and to report actively exploited vulnerabilities to the authorities. 0 prepares the paperwork. It decides nothing and never claims a product complies.

To write the evidence into one folder, run:

```bash
0 findings evidence ./evidence --repo .
```

The folder holds:

- the findings with their triage state and timestamps, as JSON and Markdown
- a SARIF file
- a CycloneDX SBOM from the lockfiles
- the fix branches that exist in the repository
- a `manifest.json` with the 0 version, date, commit and a SHA-256 for every file
- a README that says what each file shows and does not show

Add `--check-advisories` to look the SBOM up in the public OSV database. This is the only network use. Evidence and proof-of-concept bodies stay out unless you pass `--include-evidence`.

To keep a record for each release, run the command in a job and upload the folder:

```yaml
      - run: 0 findings evidence evidence --repo . --check-advisories
      - uses: actions/upload-artifact@v4
        with: { name: security-evidence, path: evidence }
```

The folder shows what was found, how it was triaged and which components are listed. It does not show that the code has no other weaknesses, that a fix is correct or released, what is deployed, or that any obligation is met. 0 does not store pull request links, so `fixes.md` lists branches only.

### Draft a report

For an actively exploited vulnerability, write the draft text for one stage:

```bash
0 findings report-draft <finding> --stage early-warning
```

The stage is `early-warning`, `notification` or `final`. The draft takes the title, severity, location, status and timestamps from the finding. You supply the rest with `--product`, `--affected-versions`, `--exploited-since`, `--exploitation-evidence`, `--mitigation`, `--contact` or `--facts file.json`.

Anything you do not supply stays a visible `[to be completed by the manufacturer: ...]` blank. The draft never claims exploitation, user impact or a patch that you did not state. A person reviews the draft and submits it through the channel the authority designates. 0 sends nothing.

Article 14 of the Regulation is the starting point. Confirm current requirements and deadlines with the authority and your advisers.
