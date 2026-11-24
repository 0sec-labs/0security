---
title: Pull request checks (GitHub Action)
description: Scan only what a pull request changes with the 0 Action, and show the findings in GitHub's Security tab or in Bitbucket Code Insights.
---

The 0 Action scans the files a pull request changes and uploads the result to GitHub code scanning. Add it to a workflow to see findings in the repository's **Security** tab and as annotations on the pull request.

The action needs no server. It installs a verified release of `0security`, runs `0security scan --diff`, and uploads the SARIF file with `0security findings upload`. With `mode: sbom` it checks your dependencies instead.

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: 0sec-labs/0security@v0.44.0
        with:
          version: 0.44.0 # Pin the CLI
          fail-on: high
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Set the key of the provider for your model (see [Models](/models/)). The default model needs `OPENAI_API_KEY`. Put the key in a repository secret and pass it as `env` on the action step, as above. The `sbom` mode needs no key.

## What the action does

1. Installs the release you pin in `version`. The installer refuses a download whose checksum does not match the release's `checksums.txt`.
2. Checks every input. A value with a space, a newline or a leading dash is refused, and so is a path that leaves the workspace. Inputs reach the shell only as environment variables and go to `0security` as separate arguments.
3. Compares the pull request with its base branch and scans only the files that differ and the code they connect to. This costs a fraction of a full scan. A FoxGuard pattern scan runs first, and its hits go to the scan as leads.
4. Uploads the findings to code scanning with `0security findings upload`. Alerts match by fingerprint, so pushing again updates them.
5. Writes a job summary and sets the outputs.
6. Fails the job when a finding is at or above `fail-on`, or when the scan is partial and `allow-partial` is `false`. The upload happens first, so the findings show either way.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | required | Release of 0 to install, for example `0.41.0`. |
| `mode` | `scan` | `scan` reviews the code with a model. `sbom` checks dependencies (see [SBOM mode](#sbom-mode)). |
| `target` | `.` | Folder to scan, relative to the workspace. It must stay inside the workspace. |
| `diff-base` | the pull request's base branch | Git ref to compare with. Outside a pull request, empty scans the whole folder. |
| `model` | the default model | Model for the scan thread. |
| `budget` | `5` | Stop at this many USD. The findings so far are kept. |
| `passes` | `1` | Scan this many times (1 to 5) and merge the findings; the budget is split between them. |
| `fail-on` | none | Fail at or above this severity: `critical`, `high`, `medium`, `low` or `info`. |
| `scanner` | the CLI default (`foxguard`) | Pre-pass scanners, comma separated: `foxguard`, `semgrep`, `opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`. A scanner other than `foxguard` must be installed on the runner. |
| `rules` | none | Semgrep or OpenGrep rule files or folders, comma separated. Needs `scanner` to include `semgrep` or `opengrep`. |
| `tiers` | none | Tier map file. See [Set the effort per repository](#set-the-effort-per-repository). |
| `known-sarif` | none | SARIF files from other tools, comma separated. See [Get a second opinion](#get-a-second-opinion). |
| `only-new` | `false` | With `known-sarif`: leave findings that match a known item out of the report and out of `fail-on`. |
| `context` | none | Background files for the scan, such as a threat model, comma separated. |
| `scope` | none | A Markdown file whose `## Scope` section declares what is in and out of scope, usually `SECURITY.md`. See [Declare scope](#declare-scope). |
| `policy` | none | Markdown policy files or folders to check the code against, comma separated. |
| `skill` | the default skill | Skill that holds the scan method. |
| `allow-partial` | `false` | Pass the job when the scan stops before it reviews everything. |
| `licenses-preset` | none | `sbom` mode: also check licenses against `permissive` or `no-copyleft`. |
| `upload` | `true` | Upload to code scanning. Needs `security-events: write`. |
| `github-token` | the job's token | Token used for the upload. |

List inputs and path inputs use only letters, digits and `. _ / + @ = -`. A path with a space is refused. Rename the file.

## Outputs

| Output | Meaning |
| --- | --- |
| `sarif` | Path of the SARIF file. |
| `exit-code` | `0` done, `1` a finding at or above `fail-on` or the scan failed, `2` usage error, `3` not finished. |
| `status` | `complete`, `partial`, `skipped`, `prepass_only` or `failed`. |
| `coverage` | One sentence on what the scan reviewed, for example `reviewed 41 of 57 entry points; 16 not reached (budget)`. |
| `sbom` | Path of the CycloneDX file in `sbom` mode. |

`status` is `partial` when the budget or time limit stopped the scan, or when entry points were not reached. It is `skipped` when a tier map skips the repository, and `prepass_only` when the tier runs only the pattern scanners. The text in `coverage` comes from the CLI's own counts, reduced to letters, digits and basic punctuation.

The job summary lists the status, the coverage sentence, why the scan stopped when it did not finish (for example a dropped provider connection), the counts by severity, the tier and, with `known-sarif`, how many findings are new and how many were already known. It never shows text the model wrote, so a scanned file cannot put an `@mention` or an issue reference into it.

## Partial scans

A scan is partial when it stops before it reviews everything. The exit code is 3 and `status` is `partial`.

With `allow-partial: false` (the default), the action uploads the findings so far, then fails the job. A partial scan is a scan you cannot rely on, so the failure makes it visible.

With `allow-partial: true`, the action passes `--allow-partial` to `0security`. The scan exits by its findings alone, so a partial run exits 0, or 1 when a finding reaches `fail-on`. The job logs a warning, and `status` is `partial`. To finish the review, run `0security scan <folder> --resume latest` with a higher `budget`. A pull request diff is usually small enough to finish within the default budget. `fail-on` still fails the job on a finding in the part that was reviewed.

## Add your own rules

Pass Semgrep rules you already write with `rules`. Rules, tier maps, context, policies and known-result files steer the scan. Do not take them from the pull request, because a change could delete the rule that catches its own bug. Check out the base branch or a separate repository to a path of its own and point to it:

```yaml
      - uses: actions/checkout@v4
        with:
          repository: your-org/security-rules
          path: security-rules
      - uses: 0sec-labs/0security@v0.44.0
        with:
          version: 0.44.0 # Pin the CLI
          scanner: semgrep
          rules: security-rules/semgrep
```

The action enforces this when it can tell. If one of these files sits in the scanned repository and the checkout is the pull request's own code, the action fails the job for a fork pull request and for `pull_request_target`. For a same-repository `pull_request` it logs a warning. A checkout of the base branch is not refused.

See [scan](/commands/#scan) for the rule format and how findings are marked.

## Declare scope

Pass the `## Scope` section of your `SECURITY.md` with `scope`. Findings in vectors it lists as out of scope are labelled and listed apart. They do not count toward `fail-on`, and the job summary counts them on a separate line. See [Declare what is in and out of scope](/threat-model-and-policy/#declare-what-is-in-and-out-of-scope).

Use the base branch's copy, never the pull request's. A change could otherwise edit the Scope section to label its own bug out of scope:

```yaml
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.base_ref }}
          path: base
      - uses: actions/checkout@v4
      - uses: 0sec-labs/0security@v0.44.0
        with:
          version: 0.44.0 # Pin the CLI
          scope: base/SECURITY.md
          fail-on: high
```

The action fails the job when `scope` points into the pull request's own code and the pull request comes from a fork or runs as `pull_request_target`. For a same-repository `pull_request` it logs a warning.

## Set the effort per repository

A tier map decides how much a repository gets scanned, or whether it is skipped. See [scan](/commands/#set-the-effort-per-repository) for the file. In CI the tier file must not come from the pull request, because a change could lower its own tier and skip its own scan. Read it from a separate checkout:

```yaml
      - uses: actions/checkout@v4
        with:
          repository: your-org/security-config
          path: security-config
      - uses: 0sec-labs/0security@v0.44.0
        with:
          version: 0.44.0 # Pin the CLI
          tiers: security-config/scan-tiers.yaml
```

A skipped scan passes with `status: skipped` and a notice in the log. The job summary shows the tier and why it applied.

## Get a second opinion

Give the scan what another tool already found. It looks for other classes of bug and labels each finding `new` or `already-known`. Download the other tool's SARIF into the workspace first, then pass its path:

```yaml
          known-sarif: results/codeql.sarif
          only-new: true
```

`only-new` leaves matched findings out of the report and out of `fail-on`. Without it, every finding stays and carries its label.

## SBOM mode

`mode: sbom` generates a CycloneDX SBOM from the lockfiles in `target`, checks every component against the public OSV database and uploads the advisories to code scanning as `0 sbom`. It also uploads the SBOM as the `0-sbom` artifact. It needs no model key.

```yaml
      - uses: 0sec-labs/0security@v0.44.0
        with:
          version: 0.44.0 # Pin the CLI
          mode: sbom
          licenses-preset: no-copyleft
          fail-on: high
```

Advisories only warn unless `fail-on` is set, and then any advisory fails the job. A license the `licenses-preset` does not allow always fails the job. In this mode only `target`, `upload`, `fail-on`, `licenses-preset` and `github-token` apply. The package names in the SBOM go to `api.osv.dev` for the lookup.

## Examples

Each example pins the action by release. For a stricter pin, replace the tag with the release's full commit SHA and keep the tag in a comment. The permissions are the least each job needs. The model key goes in a repository secret, passed as `env` on the action step.

### Scan a pull request and fail on high

The job needs `contents: read` and `security-events: write`. It needs no other permission.

```yaml
name: 0 security
on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: 0sec-labs/0security@v0.44.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.44.0 # Pin the CLI
          fail-on: high
          budget: "3"
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Scan the whole repository every night

A nightly full scan can run out of budget on a large repository. With `allow-partial` the job stays green and the summary says what was not reached. To finish the review, run `0security scan . --resume latest` on a machine that kept the earlier scan's state in `~/.0`. A hosted runner starts clean, so resume suits a self-hosted runner or a local run. It refuses when the git HEAD changed unless you pass `--force`.

```yaml
name: 0 nightly scan
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - id: zero
        uses: 0sec-labs/0security@v0.44.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.44.0 # Pin the CLI
          budget: "20"
          fail-on: critical
          allow-partial: true
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      - if: steps.zero.outputs.status == 'partial'
        env:
          COVERAGE: ${{ steps.zero.outputs.coverage }}
        run: echo "Partial scan. $COVERAGE"
```

### Check dependencies and licenses

```yaml
name: 0 dependencies
on:
  pull_request:
  schedule:
    - cron: "17 5 * * *"

permissions:
  contents: read
  security-events: write

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: 0sec-labs/0security@v0.44.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.44.0 # Pin the CLI
          mode: sbom
          licenses-preset: no-copyleft
          fail-on: high
```

### Add a second opinion to CodeQL or Semgrep

Run the other tool first, keep its SARIF file, and pass it to 0. This example uses a SARIF file the earlier step wrote to `results/`.

```yaml
name: 0 second opinion
on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      # Your existing Semgrep or CodeQL step runs here and writes results/other-tool.sarif.
      - uses: 0sec-labs/0security@v0.44.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.44.0 # Pin the CLI
          known-sarif: results/other-tool.sarif
          only-new: true
          fail-on: high
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Scan with a tier map

The tier map comes from a separate repository, so a pull request cannot lower its own tier.

```yaml
name: 0 tiered scan
on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: your-org/security-config
          path: security-config
          persist-credentials: false
      - uses: 0sec-labs/0security@v0.44.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.44.0 # Pin the CLI
          tiers: security-config/scan-tiers.yaml
          fail-on: high
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

If the second repository is private, give its checkout a token that can read it.

## Run on a runner in your network

Run scans on a runner you host, so source code is processed where it lives. The runner needs outbound access to GitHub and to your model endpoint, and nothing else.

Install the runner on a machine in your network or cloud account, with a label such as `0-scan`. Use an ephemeral runner (`--ephemeral`) so each job starts clean. Then point the job at it:

```yaml
jobs:
  scan:
    runs-on: [self-hosted, linux, 0-scan]
    steps:
      - uses: actions/checkout@v4
      - uses: 0sec-labs/0security@v0.44.0
        with:
          version: 0.44.0
          fail-on: high
        env:
          ZERO_ENTERPRISE: "1"
          ZERO_SELECTED_PROVIDER: azure
          AZURE_OPENAI_AUTH: entra
          AZURE_OPENAI_BASE_URL: https://your-resource.openai.azure.com/openai/v1
          ZERO_MODEL: your-deployment-id
```

Keep these boundaries:

- Give the runner's machine identity access to the model, as in [Azure OpenAI](/models/#azure-openai) or an AWS role for [Amazon Bedrock](/models/#amazon-bedrock). No model key is stored in GitHub.
- `ZERO_ENTERPRISE` keeps everything off except the model endpoint you configured. The action's SARIF upload goes to GitHub with the job's token. See [Data flow](/data-flow/).
- Install `cosign` on the runner image, so the installer verifies the release [signature](/self-hosting/#verify-the-signature). Or put a pinned, verified binary in the runner image and skip the install.
- Only run the job on trusted events. Do not run a self-hosted runner for pull requests from forks.

This pattern is not tested on a real self-hosted runner yet.

## Limits

- Only pull requests from the same repository work. A fork's pull request has no access to your secrets, so it cannot run a model. Do not use `pull_request_target` to get around this: it runs a model on untrusted code with your key.
- Use the default checkout ref. On a pull request it checks out the merge commit, so comparing with the base branch gives exactly the change.
- With `fetch-depth: 0` the checkout already has the base branch, so you can set `persist-credentials: false`. With a shallow checkout the action fetches the base branch itself and needs the persisted credentials.
- Code scanning needs a supported plan. On private repositories it is part of GitHub Code Security.
- A clean run means the model found nothing. It does not mean the code is safe. The report says what the scan covered.

## Bitbucket, Jenkins and Azure Pipelines

The Action is GitHub only. Elsewhere, install the same pinned release and run the same three steps: scan the change, upload, fail on severity. Every example below installs a release you pin, and the installer refuses a download whose checksum does not match that release's `checksums.txt`.

These examples were written from the products' public documentation. They have not been run on a live Bitbucket, Jenkins or Azure Pipelines instance, so try them on a branch first.

### Secrets and untrusted pull requests

The scan runs a model agent over the pull request's code, and the text in that code is written by the pull request's author. Treat everything in the scan step's environment as readable by that author, and assume a pipeline file that comes from the pull request can be changed by them too.

- Run the scan only for pull requests from people you trust: branches in the same repository by users with write access. Do not run it for forks, and check your CI's setting for who can trigger a build.
- Give the scan step only the model key, and make that key cheap to lose: a key for your own gateway with a spend cap, or a short-lived one. Never put the Bitbucket token in the scan step.
- Publish in a separate step that holds only the Bitbucket token and never runs the pull request's code. Install the CLI again there, outside the checkout, and read only `scan.json`, so nothing the scan left behind runs while the token is present. Use a token that can write Code Insights reports and nothing else.
- Take the pipeline definition from a trusted place. Jenkins: use a job whose Jenkinsfile comes from the target branch or a separate repository, or a multibranch job that only trusts pipelines from users with write access. Bitbucket Pipelines runs the file on the pull request's branch, so limit who can create branches and require approval for builds that use secrets. Azure Pipelines: keep the keys in a variable group that needs approval.

### Publish to Bitbucket Code Insights

`0security findings upload --to bitbucket-cloud` (or `--to bitbucket-dc` for Data Center) turns the scan into a Code Insights report with one annotation per finding. Scan with `--format json`: that file carries the agent's verdict, rationale and fix guidance, which a SARIF file does not.

```bash
0security scan . --diff origin/main --format json -o scan.json --fail-on high
0security findings upload scan.json --to bitbucket-cloud --repo workspace/repo
```

- With `BITBUCKET_TOKEN` set, the command sends the report and its annotations. Without it, it prints the payload (the report body and the annotation batches) so a CI step can send it. `--print` prints even when the token is set. The token is sent only in the `Authorization` header and is never written to a log.
- Cloud sends `PUT /2.0/repositories/{workspace}/{repo}/commit/{commit}/reports/{reportId}`, then `POST .../annotations` with at most 100 annotations per request. Data Center sends `PUT {url}/rest/insights/latest/projects/{project}/repos/{repo}/commits/{commit}/reports/{key}`, then `POST .../annotations`.
- Pass the Data Center server with `--url` or `BITBUCKET_URL`, and the repository as `PROJECT/repo`. The command refuses to send the token to a plain `http://` URL unless the host is this machine; pass `--allow-insecure-http` only on a network you trust. Cloud reads `BITBUCKET_WORKSPACE`, `BITBUCKET_REPO_SLUG` and `BITBUCKET_COMMIT` in Pipelines.
- Findings are deduplicated by file, line and CWE, keeping the most severe. A report holds at most 1000 annotations; the most severe are kept and the count of the rest is printed and written into the report details.
- Data Center has no `CRITICAL` severity, so critical findings are sent as `HIGH`. `info` findings are sent as `LOW`.
- Each annotation carries the rule id, the CWE when the agent gave one, the verdict, the rationale and the suggested fix. Data Center has a single message field of 2000 characters, so long text is cut there.
- Use a token that is allowed to write Code Insights reports for the repository (a repository access token on Cloud, an HTTP access token on Data Center). Check the scopes Bitbucket asks for in Atlassian's documentation.

Re-running for the same commit and report id replaces the report and updates annotations with the same id. Annotations of an earlier run that no longer apply stay until the report is deleted. Reports on Data Center expire after 60 days.

### Bitbucket Pipelines

Add your model key as a secured repository variable. Store `BITBUCKET_TOKEN` as a deployment variable on an environment that only the publish step uses (here `security-report`), so the scan step cannot read it.

```yaml
image: node:22

pipelines:
  pull-requests:
    "**":
      - step:
          name: 0 security scan
          script:
            - VERSION=0.41.0 # Pin the CLI
            - export INSTALL_DIR="$HOME/.0/bin" PATH="$HOME/.0/bin:$PATH"
            - curl -fsSL -o install.sh "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
            - RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh
            - git fetch --no-tags --depth=1 origin "+refs/heads/${BITBUCKET_PR_DESTINATION_BRANCH}:refs/remotes/origin/${BITBUCKET_PR_DESTINATION_BRANCH}"
            - code=0
            - 0security scan . --diff "origin/${BITBUCKET_PR_DESTINATION_BRANCH}" --format json -o scan.json --fail-on high || code=$?
            - echo "$code" > scan.exit
          artifacts:
            - scan.json
            - scan.exit
      - step:
          name: Publish report
          deployment: security-report
          script:
            - VERSION=0.41.0 # Pin the CLI
            - tools="$(mktemp -d)" && export INSTALL_DIR="$tools" PATH="$tools:$PATH"
            - curl -fsSL -o "$tools/install.sh" "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
            - (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
            - code="$(cat scan.exit)"
            - if [ "$code" -ne 2 ]; then 0security findings upload scan.json --to bitbucket-cloud; fi
            - if [ "$code" -eq 3 ]; then echo "The scan stopped at its budget; the findings are partial."; code=0; fi
            - exit "$code"
```

The exit codes are those of `0security scan`: 1 when a finding is at or above `--fail-on` or the scan failed, 2 for a usage error, 3 when the scan stopped before it reviewed everything (not a failure; the scripts below map it to 0 after the upload). The scan step always passes so that the publish step can report; the publish step exits with the scan's code.

### Jenkins

A declarative pipeline for a multibranch job. Define it in a trusted place (see above). Store the Bitbucket token and model key as separate Jenkins credentials and bind each in its own stage. Single-quoted `sh` strings keep secrets out of Groovy interpolation.

```groovy
pipeline {
  agent any
  environment {
    VERSION = '0.41.0' // Pin the CLI
    BITBUCKET_URL = 'https://bitbucket.example.com' // Data Center only
  }
  stages {
    stage('scan') {
      when { changeRequest() }
      steps {
        withCredentials([string(credentialsId: 'openai-api-key', variable: 'OPENAI_API_KEY')]) {
          sh '''
            set -u
            export INSTALL_DIR="${WORKSPACE}/.0/bin" PATH="${WORKSPACE}/.0/bin:$PATH"
            curl -fsSL -o install.sh "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
            RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh
            git fetch --no-tags --depth=1 origin "+refs/heads/${CHANGE_TARGET}:refs/remotes/origin/${CHANGE_TARGET}"
            code=0
            0 scan . --diff "origin/${CHANGE_TARGET}" --format json -o scan.json --fail-on high || code=$?
            echo "$code" > scan.exit
          '''
        }
      }
    }
    stage('publish') {
      when { changeRequest() }
      steps {
        withCredentials([string(credentialsId: 'bitbucket-token', variable: 'BITBUCKET_TOKEN')]) {
          sh '''
            set -u
            tools="$(mktemp -d)"; export INSTALL_DIR="$tools" PATH="$tools:$PATH"
            cp scan.json scan.exit "$tools/"
            curl -fsSL -o "$tools/install.sh" "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
            (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
            code="$(cat "$tools/scan.exit")"
            if [ "$code" -ne 2 ]; then
              0 findings upload "$tools/scan.json" --to bitbucket-dc --repo PROJECT/repo --commit "$GIT_COMMIT"
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

Azure Pipelines can build a Bitbucket Cloud or GitHub repository. Keep the keys in a variable group that needs approval, and map each secret only into the step that needs it, because secrets are not exposed to steps automatically.

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
      echo "$code" > "$BUILD_ARTIFACTSTAGINGDIRECTORY/scan.exit"
    displayName: 0 security scan
    env:
      TARGET_BRANCH: $(System.PullRequest.TargetBranch)
      OPENAI_API_KEY: $(OPENAI_API_KEY)
  - bash: |
      set -u
      VERSION=0.41.0 # Pin the CLI
      tools="$(mktemp -d)"; export INSTALL_DIR="$tools" PATH="$tools:$PATH"
      cp "$BUILD_ARTIFACTSTAGINGDIRECTORY/scan.json" "$BUILD_ARTIFACTSTAGINGDIRECTORY/scan.exit" "$tools/"
      curl -fsSL -o "$tools/install.sh" "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh"
      (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
      code="$(cat "$tools/scan.exit")"
      if [ "$code" -ne 2 ] && [ -n "${BITBUCKET_TOKEN:-}" ]; then
        0 findings upload "$tools/scan.json" --to bitbucket-cloud --repo workspace/repo --commit "$SOURCE_VERSION"
      fi
      [ "$code" -eq 3 ] && code=0
      exit "$code"
    displayName: Publish report
    condition: always()
    env:
      SOURCE_VERSION: $(Build.SourceVersion)
      BITBUCKET_TOKEN: $(BITBUCKET_TOKEN)
  - publish: $(Build.ArtifactStagingDirectory)/scan.json
    artifact: 0-scan
    condition: always()
```

The pull request variables depend on the repository host Azure Pipelines builds, and the commit Azure builds on a pull request can be a merge commit that Bitbucket does not know. Pass the pull request's source commit with `--commit` when the report does not show up. Without a Bitbucket token the step still scans and fails on severity, and the artifact holds the findings.

## Keep an SBOM and check it for advisories

The EU Cyber Resilience Act expects a manufacturer to keep an SBOM and check it for advisories regularly. A scheduled job can regenerate the SBOM from your lockfiles and fail when a component has a known advisory. The lookup uses the public OSV database. The Action does the same with `mode: sbom` (see [SBOM mode](#sbom-mode)); the steps below do it without the Action.

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
      - run: 0security sbom generate . -o sbom.cdx.json
      - run: 0security sbom check sbom.cdx.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: sbom, path: sbom.cdx.json }
```

`0security sbom check` exits 1 when it finds an advisory, which fails the job. The output is evidence for your records. It does not make a product compliant.

## Collect evidence and draft vulnerability reports

The Cyber Resilience Act (Regulation (EU) 2024/2847) requires a manufacturer to keep records of security testing and vulnerability handling, and to report actively exploited vulnerabilities to the authorities. 0 prepares the paperwork. It decides nothing and never claims a product complies.

To write the evidence into one folder, run:

```bash
0security findings evidence ./evidence --repo .
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
      - run: 0security findings evidence evidence --repo . --check-advisories
      - uses: actions/upload-artifact@v4
        with: { name: security-evidence, path: evidence }
```

The folder shows what was found, how it was triaged and which components are listed. It does not show that the code has no other weaknesses, that a fix is correct or released, what is deployed, or that any obligation is met. 0 does not store pull request links, so `fixes.md` lists branches only.

### Draft a report

For an actively exploited vulnerability, write the draft text for one stage:

```bash
0security findings report-draft <finding> --stage early-warning
```

The stage is `early-warning`, `notification` or `final`. The draft takes the title, severity, location, status and timestamps from the finding. You supply the rest with `--product`, `--affected-versions`, `--exploited-since`, `--exploitation-evidence`, `--mitigation`, `--contact` or `--facts file.json`.

Anything you do not supply stays a visible `[to be completed by the manufacturer: ...]` blank. The draft never claims exploitation, user impact or a patch that you did not state. A person reviews the draft and submits it through the channel the authority designates. 0 sends nothing.

Article 14 of the Regulation is the starting point. Confirm current requirements and deadlines with the authority and your advisers.
