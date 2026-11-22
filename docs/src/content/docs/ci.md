---
title: Pull request checks (GitHub Action)
description: Scan only what a pull request changes with the 0 Action, and show the findings in GitHub's Security tab or in Bitbucket Code Insights.
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

## Add your own rules

Pass Semgrep rules you already write with `--rules`. The rules must not come from the pull request, because a change could delete the rule that catches its own bug. Check out the base branch or a separate repository and point to it:

```yaml
      - uses: actions/checkout@v4
        with:
          repository: your-org/security-rules
          path: rules
```

```bash
0 scan . --diff origin/main --scanner semgrep --rules rules/semgrep
```

See [scan](/commands/#scan) for the rule format and how findings are marked.

## Limits

- Only pull requests from the same repository work. A fork's pull request has no access to your secrets, so it cannot run a model. Do not use `pull_request_target` to get around this: it runs a model on untrusted code with your key.
- Use the default checkout. On a pull request it checks out the merge commit, so comparing with the base branch gives exactly the change.
- Code scanning needs a supported plan. On private repositories it is part of GitHub Code Security.
- A clean run means the model found nothing. It does not mean the code is safe. The report says what the scan covered.

## Bitbucket, Jenkins and Azure Pipelines

The Action is GitHub only. Elsewhere, install the same pinned release and run the same three steps: scan the change, upload, fail on severity. Every example below installs a release you pin, and the installer refuses a download whose checksum does not match that release's `checksums.txt`.

These examples were written from the products' public documentation. They have not been run on a live Bitbucket, Jenkins or Azure Pipelines instance, so try them on a branch first.

### Publish to Bitbucket Code Insights

`0 findings upload --to bitbucket-cloud` (or `--to bitbucket-dc` for Data Center) turns the scan into a Code Insights report with one annotation per finding. Scan with `--format json`: that file carries the agent's verdict, rationale and fix guidance, which a SARIF file does not.

```bash
0 scan . --diff origin/main --format json -o scan.json --fail-on high
0 findings upload scan.json --to bitbucket-cloud --repo workspace/repo
```

- With `BITBUCKET_TOKEN` set, the command sends the report and its annotations. Without it, it prints the payload (the report body and the annotation batches) so a CI step can send it. `--print` prints even when the token is set. The token is sent only in the `Authorization` header and is never written to a log.
- Cloud sends `PUT /2.0/repositories/{workspace}/{repo}/commit/{commit}/reports/{reportId}`, then `POST .../annotations` with at most 100 annotations per request. Data Center sends `PUT {url}/rest/insights/latest/projects/{project}/repos/{repo}/commits/{commit}/reports/{key}`, then `POST .../annotations`.
- Pass the Data Center server with `--url` or `BITBUCKET_URL`, and the repository as `PROJECT/repo`. Cloud reads `BITBUCKET_WORKSPACE`, `BITBUCKET_REPO_SLUG` and `BITBUCKET_COMMIT` in Pipelines.
- Findings are deduplicated by file, line and CWE, keeping the most severe. A report holds at most 1000 annotations; the most severe are kept and the count of the rest is printed and written into the report details.
- Data Center has no `CRITICAL` severity, so critical findings are sent as `HIGH`. `info` findings are sent as `LOW`.
- Each annotation carries the rule id, the CWE when the agent gave one, the verdict, the rationale and the suggested fix. Data Center has a single message field of 2000 characters, so long text is cut there.
- Use a token that is allowed to write Code Insights reports for the repository (a repository access token on Cloud, an HTTP access token on Data Center). Check the scopes Bitbucket asks for in Atlassian's documentation.

Re-running for the same commit and report id replaces the report and updates annotations with the same id. Annotations of an earlier run that no longer apply stay until the report is deleted. Reports on Data Center expire after 60 days.

### Bitbucket Pipelines

Add `BITBUCKET_TOKEN` and your model key as secured repository variables.

```yaml
image: node:22

pipelines:
  pull-requests:
    "**":
      - step:
          name: 0 security
          script:
            - VERSION=0.41.0 # Pin the CLI
            - export INSTALL_DIR="$HOME/.0/bin" PATH="$HOME/.0/bin:$PATH"
            - curl -fsSL -o install.sh "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
            - RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh
            - git fetch --no-tags --depth=1 origin "+refs/heads/${BITBUCKET_PR_DESTINATION_BRANCH}:refs/remotes/origin/${BITBUCKET_PR_DESTINATION_BRANCH}"
            - code=0
            - 0 scan . --diff "origin/${BITBUCKET_PR_DESTINATION_BRANCH}" --format json -o scan.json --fail-on high || code=$?
            - if [ "$code" -ne 2 ]; then 0 findings upload scan.json --to bitbucket-cloud; fi
            - if [ "$code" -eq 3 ]; then echo "The scan stopped at its budget; the findings are partial."; code=0; fi
            - exit "$code"
          artifacts:
            - scan.json
```

The exit codes are those of `0 scan`: 1 when a finding is at or above `--fail-on` or the scan failed, 2 for a usage error, 3 when the scan stopped at its budget.

### Jenkins

A declarative pipeline for a multibranch job. Store the Bitbucket token and model key as Jenkins credentials. Single-quoted `sh` strings keep secrets out of Groovy interpolation.

```groovy
pipeline {
  agent any
  environment {
    VERSION = '0.41.0' // Pin the CLI
    INSTALL_DIR = "${WORKSPACE}/.0/bin"
    BITBUCKET_URL = 'https://bitbucket.example.com' // Data Center only
  }
  stages {
    stage('0 security') {
      when { changeRequest() }
      steps {
        withCredentials([string(credentialsId: 'bitbucket-token', variable: 'BITBUCKET_TOKEN'),
                         string(credentialsId: 'openai-api-key', variable: 'OPENAI_API_KEY')]) {
          sh '''
            set -u
            curl -fsSL -o install.sh "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
            RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh
            export PATH="$INSTALL_DIR:$PATH"
            git fetch --no-tags --depth=1 origin "+refs/heads/${CHANGE_TARGET}:refs/remotes/origin/${CHANGE_TARGET}"
            code=0
            0 scan . --diff "origin/${CHANGE_TARGET}" --format json -o scan.json --fail-on high || code=$?
            if [ "$code" -ne 2 ]; then
              0 findings upload scan.json --to bitbucket-dc --repo PROJECT/repo --commit "$GIT_COMMIT"
            fi
            [ "$code" -eq 3 ] && code=0
            exit "$code"
          '''
        }
      }
    }
  }
  post { always { archiveArtifacts artifacts: 'scan.json', allowEmptyArchive: true } }
}
```

Use `--to bitbucket-cloud --repo workspace/repo` for Bitbucket Cloud. There is no Jenkins shared library for this yet; the pipeline above is the supported route.

### Azure Pipelines

Azure Pipelines can build a Bitbucket Cloud or GitHub repository. Keep the keys in a variable group or secret variables, and map secrets into the step's `env` because they are not exposed automatically.

```yaml
trigger: none
pr:
  branches:
    include: [main]

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    fetchDepth: 0
  - bash: |
      set -u
      VERSION=0.41.0 # Pin the CLI
      export INSTALL_DIR="$HOME/.0/bin" PATH="$HOME/.0/bin:$PATH"
      curl -fsSL -o install.sh "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
      RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh
      base="${TARGET_BRANCH#refs/heads/}"
      git fetch --no-tags --depth=1 origin "+refs/heads/${base}:refs/remotes/origin/${base}"
      code=0
      0 scan . --diff "origin/${base}" --format json -o "$BUILD_ARTIFACTSTAGINGDIRECTORY/scan.json" --fail-on high || code=$?
      if [ "$code" -ne 2 ] && [ -n "${BITBUCKET_TOKEN:-}" ]; then
        0 findings upload "$BUILD_ARTIFACTSTAGINGDIRECTORY/scan.json" --to bitbucket-cloud --repo workspace/repo --commit "$SOURCE_VERSION"
      fi
      [ "$code" -eq 3 ] && code=0
      exit "$code"
    displayName: 0 security scan
    env:
      TARGET_BRANCH: $(System.PullRequest.TargetBranch)
      SOURCE_VERSION: $(Build.SourceVersion)
      BITBUCKET_TOKEN: $(BITBUCKET_TOKEN)
      OPENAI_API_KEY: $(OPENAI_API_KEY)
  - publish: $(Build.ArtifactStagingDirectory)/scan.json
    artifact: 0-scan
    condition: always()
```

The pull request variables depend on the repository host Azure Pipelines builds, and the commit Azure builds on a pull request can be a merge commit that Bitbucket does not know. Pass the pull request's source commit with `--commit` when the report does not show up. Without a Bitbucket token the step still scans and fails on severity, and the artifact holds the findings.

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
