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
      - uses: 0sec-labs/0security@v0.46.0
        with:
          version: 0.46.0 # Pin the CLI
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
| `mode` | `scan` | `scan` reviews the code with a model. `sbom` checks dependencies (see [SBOM mode](#sbom-mode)). `agent-config` checks agent files (see [Check agent files](#check-agent-files)). `redteam` tests an agent (see [Red team an agent](#red-team-an-agent)). |
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
| `redteam-*` | see below | `redteam` mode only. See [Red team an agent](#red-team-an-agent). |
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
      - uses: 0sec-labs/0security@v0.46.0
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0
        with:
          version: 0.46.0 # Pin the CLI
          mode: sbom
          licenses-preset: no-copyleft
          fail-on: high
```

Advisories only warn unless `fail-on` is set, and then any advisory fails the job. A license the `licenses-preset` does not allow always fails the job. In this mode only `target`, `upload`, `fail-on`, `licenses-preset` and `github-token` apply. The package names in the SBOM go to `api.osv.dev` for the lookup.

## Check agent files

A pull request can change the files AI coding tools read: rules, MCP configuration and settings. `0security sbom agent-config` checks them with no model key and no network. The Action runs it with `mode: agent-config`.

```yaml
      - uses: 0sec-labs/0security@v0.45.0
        with:
          version: 0.45.0 # Pin the CLI
          mode: agent-config
          fail-on: high
```

The mode checks `target`, writes SARIF and uploads it to code scanning with the category name 0 agent-config. With `fail-on` set, a finding at or above that severity fails the job. Without it the job never fails on findings. Only `target`, `upload`, `fail-on` and `github-token` apply. Run it before any step that uses an AI tool. You can also run `0security sbom agent-config . --format sarif -o agent-config.sarif --fail-on high` in a step of your own. See [Check agent files in a repository](/extensions/#check-agent-files-in-a-repository) for the rules.

## Red team an agent

`mode: redteam` runs `0security redteam run`: it starts your agent command, gives it a honeypot tool server that returns an injected instruction, and checks whether the agent obeyed it. It needs no model key of its own, but your agent may need one.

**0 does not isolate the agent.** It runs on the runner as a normal process, with the workspace, the network and every variable you pass in `redteam-env`. A badly behaved agent can do real harm there. Use a disposable runner and give it no credentials you cannot lose. The mode fails with a clear message unless you set `redteam-unsafe-no-isolation: true`. It also refuses fork pull requests and every event except `push`, `schedule`, `workflow_dispatch`, `merge_group` and same-repository `pull_request`, because it executes code from the change under test. Exit codes: 0 clear, 1 obeyed (needs a report), 2 inconclusive (see `redteam-inconclusive`); any other code fails the step.

```yaml
name: agent-redteam
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # only needed to upload the SARIF report

jobs:
  redteam:
    # Never run the agent for a fork: it would execute the fork author's code.
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest   # Use a throwaway runner. The agent runs on it unsandboxed.
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: 0sec-labs/0security@v0.45.0
        env:
          SUPPORT_BOT_KEY: ${{ secrets.SUPPORT_BOT_TEST_KEY }} # A test key with no production access
        with:
          version: 0.45.0 # Pin the CLI
          mode: redteam
          redteam-agent: node bot/agent.js
          redteam-env: SUPPORT_BOT_KEY
          redteam-forbid: shell,send_email
          redteam-runs: "3"
          redteam-unsafe-no-isolation: "true"
```

Never use `pull_request_target`, `workflow_run` or comment triggers for this mode: they run with secrets and write access. The agent runs unsandboxed on the runner with the runner's access, so use a throwaway runner and give it only test credentials. The Action itself refuses every event except `push`, `schedule`, `workflow_dispatch`, `merge_group` and `pull_request` from the same repository.

| Input | Default | Meaning |
| --- | --- | --- |
| `redteam-agent` | required | Command that starts the agent. |
| `redteam-unsafe-no-isolation` | `false` | Must be `true`. Confirms the agent runs with no sandbox. |
| `redteam-runs` | `3` | Runs, 1 to 20. |
| `redteam-timeout` | `120` | Seconds per run. |
| `redteam-env` | none | Variable names to pass to the agent, comma separated. Set the values on the step. |
| `redteam-forbid` | none | Tools the agent must not call, comma separated. |
| `redteam-payload` | built-in | The injected instruction as text. Not with `redteam-scenario`. |
| `redteam-scenario` | none | A scenario file. Take it from the base branch or a separate checkout. |
| `redteam-max-hit-rate` | `0` | Share of runs, 0 to 1, in which the agent may obey. At the default, one obeyed run fails the job. |
| `redteam-target` | none | A name for the agent in the report. |
| `redteam-inconclusive` | `fail` | `warn` lets a run that proved nothing pass with a warning. |

`target` is the folder the agent starts in. The mode writes SARIF and uploads it as `0 redteam`. It does not use `fail-on`. The exit code decides: `0` means the agent did not obey in any conclusive run, `1` means it obeyed more often than `redteam-max-hit-rate` allows and fails the job, and `2` means the run was inconclusive, for example the agent never called the honeypot. Inconclusive fails the job by default. `status` is `complete`, `obeyed` or `inconclusive`.

A pass is not proof of safety. It shows that this agent ignored this payload in these runs. Model output varies, so a few runs can miss a weakness.

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
      - uses: 0sec-labs/0security@v0.46.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.46.0 # Pin the CLI
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
        uses: 0sec-labs/0security@v0.46.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0 # pin to the release's commit SHA for a stricter pin
        with:
          version: 0.46.0 # Pin the CLI
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
      - uses: 0sec-labs/0security@v0.46.0
        id: scan
        with:
          version: 0.46.0
          fail-on: high
          upload: "false"
        env:
          ZERO_ENTERPRISE: "1"
          DO_NOT_TRACK: "1"
          ZERO_SELECTED_PROVIDER: azure
          AZURE_OPENAI_AUTH: entra
          AZURE_OPENAI_BASE_URL: https://your-resource.openai.azure.com/openai/v1
          ZERO_MODEL: your-deployment-id
      - name: Upload to code scanning
        if: ${{ always() && steps.scan.outputs.sarif != '' }}
        env:
          GH_TOKEN: ${{ github.token }}
        run: 0 findings upload "${{ steps.scan.outputs.sarif }}"
```

`ZERO_ENTERPRISE` refuses every `gh` call, and the action uploads with `gh`. The example sets `upload: "false"` and uploads in a later step that does not set `ZERO_ENTERPRISE`. Add `security-events: write` to the job permissions.

Keep these boundaries:

- Give the runner's machine identity access to the model, as in [Azure OpenAI](/models/#azure-openai) or an AWS role for [Amazon Bedrock](/models/#amazon-bedrock). No model key is stored in GitHub.
- `ZERO_ENTERPRISE` keeps every automatic outbound call off, including telemetry and crash reports, except the model endpoint you configured and the destinations you name. `DO_NOT_TRACK` adds a second switch for telemetry. The upload step sends SARIF to GitHub with the job's token. See [Data flow](/data-flow/). A Sentinel can upload its findings the same way from your machine: see [Send findings to GitHub](/sentinels/#send-findings-to-github).
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

The templates and scripts are tested with stand-in programs. They have not been run on a live Bitbucket, Jenkins, Azure Pipelines or GitLab instance, so try them on a branch first.

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

### Use the templates

The `ci/` folder of the repository holds a template for each CI below and the two scripts they share. `0-ci-scan.sh` scans the change and records the result. `0-ci-publish.sh` sends the result to Bitbucket Code Insights and exits with the scan's code.

Each template installs a release you pin, fetches the scripts from the same release tag, and keeps the Bitbucket token in a separate step from the model key. The scripts read their settings from environment variables, and refuse a value with a space or a leading dash. The scripts need a release that contains `ci/scripts`.

The exit codes are those of `0security scan`: 1 when a finding is at or above `--fail-on` or the scan failed, 2 for a usage error, 3 when the scan stopped before it reviewed everything. Code 3 is not a failure, so the publish step maps it to 0 after the upload. The scan step always passes so that the publish step can report.

### Bitbucket Pipelines

Add your model key as a secured repository variable. Store `BITBUCKET_TOKEN` as a deployment variable on an environment that only the publish step uses (here `security-report`).

```yaml
# Scan each pull request with 0 and show the findings in Bitbucket Code Insights.
# Add OPENAI_API_KEY (or your model's key) as a secured repository variable.
# Add BITBUCKET_TOKEN as a deployment variable on the "security-report" environment, so only the publish step can read it.
image: node:22

definitions:
  scripts:
    - &install |
      VERSION=0.46.0 # Pin the CLI
      RAW="https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}"
      tools="$(mktemp -d)" && export INSTALL_DIR="$tools" PATH="$tools:$PATH"
      curl -fsSL -o "$tools/install.sh" "$RAW/install.sh"
      curl -fsSL -o "$tools/0-ci-scan.sh" "$RAW/ci/scripts/0-ci-scan.sh"
      curl -fsSL -o "$tools/0-ci-publish.sh" "$RAW/ci/scripts/0-ci-publish.sh"
      (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)

pipelines:
  pull-requests:
    "**":
      - step:
          name: 0 security scan
          script:
            - *install
            - ZEROCI_BASE_BRANCH="$BITBUCKET_PR_DESTINATION_BRANCH" ZEROCI_COMMIT="$BITBUCKET_COMMIT" sh "$tools/0-ci-scan.sh"
          artifacts:
            - scan.json
            - scan.exit
            - scan.commit
      - step:
          name: Publish report
          deployment: security-report
          script:
            - *install
            - ZEROCI_UPLOAD_TO=bitbucket-cloud sh "$tools/0-ci-publish.sh"
```

### Jenkins

A declarative pipeline for a multibranch job. Define it in a trusted place (see above). Store the Bitbucket token and model key as separate Jenkins credentials and bind each in its own stage. Single-quoted `sh` strings keep secrets out of Groovy interpolation. Use `ZEROCI_UPLOAD_TO=bitbucket-cloud` for Bitbucket Cloud.

The scan records the pull request's own commit. When Jenkins checks out the merge of the pull request with its target, the scan uses the merge's second parent, which is the pull request's head.

```groovy
// Scan each pull request with 0 and show the findings in Bitbucket Code Insights.
// Use a multibranch job and keep this file in a trusted place (the target branch or a separate repository).
// Store the model key as a Jenkins credential "openai-api-key" and the Bitbucket token as "bitbucket-token".
pipeline {
  agent any
  environment {
    VERSION = '0.46.0' // Pin the CLI
    BITBUCKET_URL = 'https://bitbucket.example.com' // Data Center server
    ZEROCI_REPO = 'PROJECT/repo'
  }
  stages {
    stage('scan') {
      when { changeRequest() }
      steps {
        withCredentials([string(credentialsId: 'openai-api-key', variable: 'OPENAI_API_KEY')]) {
          sh '''
            set -eu
            RAW="https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}"
            tools="$(mktemp -d)"; export INSTALL_DIR="$tools" PATH="$tools:$PATH"
            curl -fsSL -o "$tools/install.sh" "$RAW/install.sh"
            curl -fsSL -o "$tools/0-ci-scan.sh" "$RAW/ci/scripts/0-ci-scan.sh"
            (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
            ZEROCI_BASE_BRANCH="$CHANGE_TARGET" sh "$tools/0-ci-scan.sh"
          '''
        }
      }
    }
    stage('publish') {
      when { changeRequest() }
      steps {
        withCredentials([string(credentialsId: 'bitbucket-token', variable: 'BITBUCKET_TOKEN')]) {
          sh '''
            set -eu
            RAW="https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}"
            tools="$(mktemp -d)"; export INSTALL_DIR="$tools" PATH="$tools:$PATH"
            cp scan.json scan.exit scan.commit "$tools/"
            curl -fsSL -o "$tools/install.sh" "$RAW/install.sh"
            curl -fsSL -o "$tools/0-ci-publish.sh" "$RAW/ci/scripts/0-ci-publish.sh"
            (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
            ZEROCI_OUT_DIR="$tools" ZEROCI_UPLOAD_TO=bitbucket-dc sh "$tools/0-ci-publish.sh"
          '''
        }
      }
    }
  }
  post { always { archiveArtifacts artifacts: 'scan.json', allowEmptyArchive: true } }
}
```

### Azure Pipelines

Azure Pipelines can build a Bitbucket Cloud or GitHub repository. Keep the keys in a variable group that needs approval, and map each secret only into the step that needs it, because secrets are not exposed to steps automatically.

```yaml
# Scan each pull request with 0 and show the findings in Bitbucket Code Insights.
# Keep OPENAI_API_KEY and BITBUCKET_TOKEN in a variable group that needs approval. Each secret is mapped into one step only.
trigger: none
pr:
  branches:
    include: [main]

variables:
  VERSION: 0.46.0 # Pin the CLI

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    fetchDepth: 0
    persistCredentials: false
  - bash: |
      set -eu
      RAW="https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}"
      tools="$(mktemp -d)"; export INSTALL_DIR="$tools" PATH="$tools:$PATH"
      curl -fsSL -o "$tools/install.sh" "$RAW/install.sh"
      curl -fsSL -o "$tools/0-ci-scan.sh" "$RAW/ci/scripts/0-ci-scan.sh"
      (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
      base="${TARGET_BRANCH#refs/heads/}"
      ZEROCI_BASE_BRANCH="$base" ZEROCI_OUT_DIR="$BUILD_ARTIFACTSTAGINGDIRECTORY" sh "$tools/0-ci-scan.sh"
    displayName: 0 security scan
    env:
      VERSION: $(VERSION)
      TARGET_BRANCH: $(System.PullRequest.TargetBranch)
      OPENAI_API_KEY: $(OPENAI_API_KEY)
  - bash: |
      set -eu
      RAW="https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}"
      tools="$(mktemp -d)"; export INSTALL_DIR="$tools" PATH="$tools:$PATH"
      curl -fsSL -o "$tools/install.sh" "$RAW/install.sh"
      curl -fsSL -o "$tools/0-ci-publish.sh" "$RAW/ci/scripts/0-ci-publish.sh"
      (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
      ZEROCI_OUT_DIR="$BUILD_ARTIFACTSTAGINGDIRECTORY" ZEROCI_UPLOAD_TO=bitbucket-cloud sh "$tools/0-ci-publish.sh"
    displayName: Publish report
    condition: always()
    env:
      VERSION: $(VERSION)
      ZEROCI_REPO: workspace/repo
      BITBUCKET_TOKEN: $(BITBUCKET_TOKEN)
  - publish: $(Build.ArtifactStagingDirectory)/scan.json
    artifact: 0-scan
    condition: always()
```

The pull request variables depend on the repository host Azure Pipelines builds. For a pull request, Azure often builds a merge commit that Bitbucket does not know. The scan records the merge's second parent instead. Without a Bitbucket token the publish step still exits with the scan's code, and the artifact holds the findings.

### GitLab CI/CD

GitLab has no Code Insights target. This job scans each merge request and fails on severity. The findings stay in the job log and the `scan.json` artifact.

```yaml
# Scan each merge request with 0 and fail the job on a finding at or above ZEROCI_FAIL_ON.
# Add OPENAI_API_KEY (or your model's key) as a masked, protected CI/CD variable.
# GitLab has no Code Insights target. The findings stay in the job log and in the scan.json artifact.
stages: [scan]

zero-security:
  stage: scan
  image: node:22
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    VERSION: 0.46.0 # Pin the CLI
    GIT_DEPTH: "0"
    ZEROCI_FAIL_ON: high
  script:
    - RAW="https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}"
    - tools="$(mktemp -d)" && export INSTALL_DIR="$tools" PATH="$tools:$PATH"
    - curl -fsSL -o "$tools/install.sh" "$RAW/install.sh"
    - curl -fsSL -o "$tools/0-ci-scan.sh" "$RAW/ci/scripts/0-ci-scan.sh"
    - (cd "$tools" && RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh)
    - ZEROCI_BASE_BRANCH="$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" ZEROCI_COMMIT="$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA" ZEROCI_EXIT_WITH_RESULT=1 sh "$tools/0-ci-scan.sh"
  artifacts:
    when: always
    paths:
      - scan.json
```

### Try a recipe on your own Bitbucket Data Center and Jenkins

`ci/test-env/docker-compose.yml` starts Bitbucket Data Center 9.4.14, PostgreSQL 16 and Jenkins 2.580.2 on your machine. You need a Data Center trial license from Atlassian.

```bash
export BITBUCKET_LICENSE=...
export BITBUCKET_ADMIN_PASSWORD=...
export POSTGRES_PASSWORD=...
docker compose -f ci/test-env/docker-compose.yml up -d
```

Bitbucket answers on `http://localhost:7990` and Jenkins on `http://localhost:8080`. Create a repository and a pull request in Bitbucket, add the Bitbucket Branch Source plugin to Jenkins, and point a multibranch job at the repository with the `ci/Jenkinsfile` template.

The environment has not been started by the authors. The setup variables follow Atlassian's automated-setup properties, so check them against the Bitbucket version you run.

### Rehearse the Code Insights recipe on Bitbucket Cloud

`ci/rehearsal/bitbucket-cloud.sh` uploads a fixture report with three findings to a test repository, reads the report and its annotations back, uploads again to check nothing is duplicated, and prints the checks to make by hand on the pull request. It needs no model key.

```bash
export BITBUCKET_TOKEN=...
export REHEARSAL_REPO=workspace/test-repo
export REHEARSAL_COMMIT=...   # head commit of a test pull request
sh ci/rehearsal/bitbucket-cloud.sh
```

Run it with `--dry-run` to see the plan without sending anything. The script was run against one Bitbucket Cloud test repository on 2026-11-25 and its five automatic checks passed. That is one workspace; Data Center is not covered. Record the date and the Bitbucket plan in the issue when you run it.

## Create Jira issues from findings

`0security findings upload --to jira-cloud` (or `--to jira-dc` for Jira Data Center) creates one Jira issue for each open finding. Scan with `--format json` so the issue can carry the impact and the fix advice.

```sh
0security scan --format json -o scan.json
# See what would be created. This sends nothing and needs no token.
0security findings upload scan.json --to jira-cloud --jira-project SEC --url https://your-site.atlassian.net --dry-run
# Create the issues.
export JIRA_EMAIL=you@example.com JIRA_TOKEN=...   # Jira Cloud: account email and API token
0security findings upload scan.json --to jira-cloud --jira-project SEC --jira-issue-type Bug --jira-label team-a --url https://your-site.atlassian.net
# Data Center: a personal access token, sent as a bearer token. No email.
export JIRA_TOKEN=...
0security findings upload scan.json --to jira-dc --jira-project SEC --url https://jira.internal.example.com
```

What you get:

- One issue per finding that is still open. Findings that are false-positive, fixed or suppressed are skipped.
- Findings below `--jira-min-severity` (default `low`) get no issue, so info-level notes such as an advisory the agent judged not reached stay out of Jira. Pass `--jira-min-severity info` to create issues for them too. The dry run and the summary say how many were left out.
- The summary is the finding's title. The description holds the severity, location, weakness, description, impact, the suggested fix and the finding id.
- The labels are `0security`, the severity, `0-finding-<id>` and any `--jira-label` you add. Issue type defaults to `Task`.
- Running it again creates only what is new. Before creating, it searches the project for each `0-finding-<id>` label. An issue you closed in Jira still has its label, so it is not reopened or created again. If you remove the label, the finding gets a new issue.
- `JIRA_PROJECT` and `JIRA_URL` can replace `--jira-project` and `--url`. The token is read only from `JIRA_TOKEN`, sent only in the Authorization header and removed from error messages. A plain `http://` URL is refused unless it is this machine or you pass `--allow-insecure-http`.
- `ZERO_ENTERPRISE` blocks it. There is no exception setting. `--dry-run` still works.

The Jira search index can lag by a few seconds on Cloud. Two runs started at the same moment can create the same issue twice, so run it from one job at a time.

This has been tested only against a stand-in server on this machine that answers like Jira's published API, not against a live Jira. The project key, issue type and required fields of your Jira are not checked in advance. If your project needs extra required fields, Jira will refuse the issue and the error is shown.

## Review Bitbucket pull requests on your own machine

`0security sentinels bitbucket` reviews Bitbucket pull requests from a machine you run, on Bitbucket Cloud and Data Center. It needs no hosted service and no pipeline. Run `watch` to review pull requests as they open or change, or `review` for one. Run `doctor` first to check your setup.

Each review scans only the files the pull request changes. It then publishes a Code Insights report for the head commit, keeps one summary comment up to date, and adds up to ten inline comments on changed lines.

You need a local clone of the repository whose `origin` is the Bitbucket repository, and a token that can read pull requests, write comments and write Code Insights reports. Set it in `BITBUCKET_TOKEN`. The clone uses your own git credentials to fetch.

```bash
export BITBUCKET_TOKEN=...
export OPENAI_API_KEY=...
0security sentinels bitbucket watch --platform cloud --repo workspace/repo --checkout ~/code/repo
```

For Data Center, pass `--platform dc`, the repository as `PROJECT/repo` and `--url https://bitbucket.example.com`.

To run the same review from a Sentinel, see the [Bitbucket pull request trigger](/sentinels/#bitbucket-pull-request-trigger).

### Check your setup first

`doctor` tells you in one command whether a Sentinel will work, before it fails in the middle of a review. It prints a PASS, FAIL or SKIP line per check and ends with the exact setting or scope to fix. It exits 1 when a required check fails, and `--json` prints the same result as JSON.

```bash
export BITBUCKET_TOKEN=...
0security sentinels bitbucket doctor --platform cloud --repo workspace/repo --checkout ~/code/repo
```

For Data Center, pass `--platform dc`, `--repo PROJECT/repo` and `--url https://bitbucket.example.com`. It checks:

- `BITBUCKET_TOKEN` is set. It prints only the length, never the token.
- Bitbucket accepts the token and the repository is visible. It names a 401 (bad or expired token), a 403 (a missing permission) or a 404 (the token cannot see the repository).
- The token can list pull requests.
- The token can write Code Insights. It creates a report named `0-doctor-<random>` on the repository's newest commit and deletes it again. Pass `--read-only` to skip this and write nothing.
- The token can post and delete a pull request comment. This runs only with `--pr <number>`: it posts one marker comment and deletes it right away.
- With `--checkout <folder>`: the folder is a git clone whose `origin` is the Bitbucket repository, and `git ls-remote origin` works. Git uses your own credentials and never gets `BITBUCKET_TOKEN`.
- A model provider is configured. This reads local settings and makes no model call.
- With `BITBUCKET_WEBHOOK_SECRET` set (or `--listen <host:port>` given): the secret has at least 16 characters, and the listen address is this machine or needs a TLS proxy in front.
- `ZERO_ENTERPRISE` is not set. When it is, every Bitbucket request is refused unless `ZERO_BITBUCKET_URL` names your server.

### Use a webhook

Polling needs nothing else. For faster reviews, add a webhook and let `watch` listen for it.

```bash
export BITBUCKET_WEBHOOK_SECRET=...   # at least 16 characters
0security sentinels bitbucket watch --platform cloud --repo workspace/repo --checkout ~/code/repo --listen 127.0.0.1:7777
```

Put a TLS proxy in front of the listener and point the webhook at it. On Cloud, turn on **Pull request created** and **Pull request updated**. On Data Center, turn on **Opened** and **Source branch updated**. Set the same secret on the webhook. Bitbucket signs each delivery with it, and `watch` refuses a delivery that does not match. Polling still runs, so a missed delivery is caught on the next poll.

### What a review does

- Skips closed pull requests, drafts and pull requests from forks.
- Skips a pull request that changes more than `--max-files` files (default 50) and says so in a comment.
- Stops one scan at `--budget` USD (default 2). A scan that stops early is marked partial in the summary.
- Reviews a commit once. A new commit on the pull request is reviewed again.
- Edits its own summary comment instead of adding another, leaves inline comments that still apply, and removes the ones whose finding is gone.
- Leaves out findings in files the pull request did not change.

The Code Insights report follows the limits in [Publish to Bitbucket Code Insights](#publish-to-bitbucket-code-insights). Use `--no-comments` or `--no-insights` to post only one of the two.

### Run it safely

The scan reads code written by the pull request's author. Run `watch` on a machine that holds nothing you cannot lose, and give the clone read access only. The scan does not see `BITBUCKET_TOKEN` or `BITBUCKET_WEBHOOK_SECRET`, but it does see the model key. Use a key with a spend cap. See [Secrets and untrusted pull requests](#secrets-and-untrusted-pull-requests).

The webhook listener binds the address you give it. Use `127.0.0.1` behind a proxy. `ZERO_ENTERPRISE` makes every Bitbucket request refuse.

### What is tested

The request bodies are checked against Atlassian's published API descriptions for Cloud and Data Center 9.6, and the webhook handling against the documented payloads and signature example. The tests run against a local fake server. Nothing has run against a live Bitbucket Cloud workspace or a Data Center server. Two details are unconfirmed: the Data Center inline comment anchor sends the file path as a string, and the comment marker is plain text at the end of each comment.

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
          VERSION=0.46.0 # Pin the CLI
          RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" INSTALL_DIR="$RUNNER_TEMP/0" sh <(curl -fsSL "https://raw.githubusercontent.com/0sec-labs/0security/v${VERSION}/install.sh")
          echo "$RUNNER_TEMP/0" >> "$GITHUB_PATH"
      - run: 0security sbom generate . -o sbom.cdx.json
      - run: 0security sbom check sbom.cdx.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: sbom, path: sbom.cdx.json }
```

`0security sbom check` exits 1 when it finds an advisory, which fails the job. Add `--registry --fail-on high` to also fail on a package that looks invented or planted. The output is evidence for your records. It does not make a product compliant.

## Collect evidence and draft vulnerability reports

The Cyber Resilience Act (Regulation (EU) 2024/2847) requires a manufacturer to keep records of security testing and vulnerability handling, and to report actively exploited vulnerabilities to the authorities. 0 prepares the paperwork. It decides nothing and never claims a product complies.

[Evidence for the Cyber Resilience Act](/cra-evidence/) maps each file to the duties it supports.

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

### Sign an evidence folder

A signature shows the files are unchanged since you signed them. Signing is an enterprise feature (`evidence-signing`) and uses a key you hold. 0 never sees it. Create an Ed25519 key pair once:

```bash
openssl genpkey -algorithm ed25519 -out evidence-key.pem
openssl pkey -in evidence-key.pem -pubout -out evidence-key.pub.pem
chmod 600 evidence-key.pem
```

Sign the folder:

```bash
0security findings evidence ./evidence --repo . --sign evidence-key.pem
```

The command adds `evidence.dsse.json`. It is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope around an in-toto statement. The statement lists every file with its SHA-256, and records the signing time, the 0 version, the models, the scan ids and the git commit. DSSE is a published format that other tools can read, so an auditor does not need 0 to check it.

Check the folder with the public key. This is free, works offline and needs no license, also after your license has expired:

```bash
0security evidence verify ./evidence --pub evidence-key.pub.pem
```

The check fails when a file was changed, added or removed, when the signature was removed, or when the folder was signed with another key. Keep the private key out of the repository and out of the evidence folder.

A signature does not say the findings are right or complete. Anyone who holds your private key can sign for you. Store the public key where the auditor can get it from you directly, not from the folder.

### Draft a report

For an actively exploited vulnerability, write the draft text for one stage:

```bash
0security findings report-draft <finding> --stage early-warning
```

The stage is `early-warning`, `notification` or `final`. The draft takes the title, severity, location, status and timestamps from the finding. You supply the rest with `--product`, `--affected-versions`, `--exploited-since`, `--exploitation-evidence`, `--mitigation`, `--contact` or `--facts file.json`.

Anything you do not supply stays a visible `[to be completed by the manufacturer: ...]` blank. The draft never claims exploitation, user impact or a patch that you did not state. A person reviews the draft and submits it through the channel the authority designates. 0 sends nothing.

Article 14 of the Regulation is the starting point. Confirm current requirements and deadlines with the authority and your advisers.

## Packaged Bitbucket Pipe and Jenkins library

The repository includes a buildable Bitbucket Pipe in `ci/bitbucket-pipe/` and an exportable Jenkins Shared Library in `ci/jenkins-library/`. The Pipe installs a pinned release with its published SHA-256 verification. Both integrations use separate scan and publish execution: the untrusted scan gets the model key, and the trusted publisher gets the Bitbucket token. The Jenkins library requires separate physical nodes.

The Pipe's scan step passes these model settings when you set them: `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `ZERO_SELECTED_PROVIDER`, `ZERO_MODEL`, `ZERO_BEDROCK_MODEL`, `BEDROCK_BASE_URL` and the AWS variables Amazon Bedrock reads (`AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_BEARER_TOKEN_BEDROCK`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_SESSION_NAME`). The publish step gets none of them. A named `AWS_PROFILE` is not passed, because the Pipe has no AWS config files.

The Jenkins library takes non-secret model settings in `modelEnv`, for example `modelEnv: [ZERO_SELECTED_PROVIDER: 'bedrock', ZERO_MODEL: 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0', AWS_REGION: 'eu-central-1']`. With an instance role, leave out `modelCredential`. To bind a credential to another variable, set `modelCredentialVariable` to `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` or `AWS_BEARER_TOKEN_BEDROCK`. These changes are tested with stand-ins only, not against a real Bedrock endpoint (see [Amazon Bedrock](/models/#amazon-bedrock)).

Build, configure and qualify them with [the packaging guide](https://github.com/0sec-labs/0security/tree/main/ci/packaging). The guide includes a manual Bitbucket qualification pipeline, a Jenkins example and an actual scanner/image rehearsal with an optional paid model stage. The image and library artifacts require release publication; source files and local tests do not establish live Bitbucket, Jenkins or Azure qualification. The existing Azure Pipelines template above remains available without an extension.
