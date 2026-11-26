---
title: What 0 can do
description: Every command family in 0security with one line each and a link to where you use it.
---

0 is one program with thirteen commands and a web console. This page lists what each one does and where to read more. The [CLI reference](/commands/) has every flag.

## Find problems

- Scan code: `0security scan` reviews a folder or git repository. A pattern scanner runs first and a model reads the code. Large repositories are reviewed in resumable batches with a coverage report. `--diff` reviews only a branch's changes. See [Scan a folder](/findings/#scan-a-folder).
- Pattern scanners: foxguard, Semgrep, OpenGrep, gitleaks, Trivy, OSV-Scanner and Checkov can feed the scan as leads. Nuclei tests one running app you name. See [Use Nuclei, ZAP or Strix](/use-dynamic-scanners/).
- Threat model and scope: `0security threat-model` drafts a threat model and, with `--interview`, asks you what is in and out of scope. See [Threat model and policies](/threat-model-and-policy/).
- Policy checks: `scan --policy` checks code against Markdown policies and reports pass or fail for each.
- Dependency audit: `0security sbom` generates an SBOM, checks it for advisories, malicious packages and newer versions, and checks licenses. See [Dependency audit](/dependency-audit/).
- AI security: model file, agent configuration, LLM app, MCP server and live endpoint checks. See [AI security](/ai-security/).

## Keep one list of findings

- Findings: `0security findings` lists, shows and triages findings. You can accept a risk with a reason and an expiry, or mark a false positive. See [Findings](/findings/).
- Import: SARIF from other tools, Nuclei output and GitHub alerts become findings.
- Verify: `findings verify` re-checks findings with a fresh thread each. It is experimental.
- Export: SARIF, JSON and Markdown reports, and `findings upload` to GitHub code scanning, Bitbucket Code Insights or a shared findings server. See [Export and share](/findings/#export-and-share).
- Metrics and roll-ups: `findings metrics` shows run cost. `findings rollup` counts open findings across repositories.

## Fix

- Fix one finding: `findings fix` makes a branch and a pull request, and runs your tests, optionally in a Docker sandbox. Nothing is pushed to your base branch. See [Fix a finding](/findings/#fix-a-finding).
- Fix many: `findings burndown` works through open findings in batches within a budget. `findings export-fixes` reports what happened to the pull requests.

## Show evidence

- Evidence folder: `findings evidence` writes findings, SARIF, an SBOM and fix branches with a README that says what they do not show. `--sign` signs it with your key, and `0security evidence verify` checks it offline. See [Evidence for the Cyber Resilience Act](/cra-evidence/).
- Report drafts: `findings report-draft` writes a draft early warning, notification or final report. Nothing is sent.

## Automate

- Pull request checks: the GitHub Action and templates for GitLab, Bitbucket, Jenkins and Azure Pipelines. See [Pull request checks](/ci/).
- Sentinels: named standing jobs that run on a schedule, a pull request, a release, a check run or a signed webhook. See [Sentinels](/sentinels/).
- Threads: `0security threads` starts, follows and stops agent threads from a script. See [Threads](/threads/).

## Extend

- Skills: instructions the agent loads for a task. Bundled skills cover web and API bugs, cryptography, infrastructure as code, GitHub Actions, secrets, LLM apps and more. See [Skills](/skills/).
- Extensions: pinned git folders that bundle skills, scripts, MCP servers and connections, with a sandbox for their processes. See [Extensions](/extensions/).
- Models: any provider with your own key, including Azure OpenAI with Entra ID. See [Models](/models/).

## Run it where you need it

- Web console: run `0security` for Threads, Findings, Sentinels, Skills, Extensions, Computers and Settings in a browser on your machine. See [Threads](/threads/).
- Computers: run threads on a VM or an SSH host. See [Computers](/computers/).
- Server mode: a team workspace in Docker, Helm or Terraform, with OIDC sign-in. See [Server mode and Docker](/server-mode/) and [Self-hosting](/self-hosting/).
- No-egress and air-gapped use: `ZERO_ENTERPRISE=1` blocks every automatic outbound call, including telemetry and crash reports, except your model endpoint and the destinations you name. See [Data flow](/data-flow/).
- Configuration: `0security config` sets models, approvals, team and updates, and `config doctor` checks the setup. See [Configuration](/configuration/).

## Enterprise features

A license key unlocks a shared findings server, SAML sign-in, SCIM provisioning, custom roles, signed evidence and an audit log with a hash chain and retention. Verifying evidence and the audit log is free. See [Teams and enterprise](/server-mode/#teams-and-enterprise).

## Not tested live

Some integrations are tested against stand-in programs, not live services: Bitbucket, Jenkins, Azure Pipelines, GitLab CI, SAML and SCIM identity providers, Azure Entra ID sign-in, the Helm chart on a real cluster, and the air-gapped bundle on an isolated network. The page for each says so.
