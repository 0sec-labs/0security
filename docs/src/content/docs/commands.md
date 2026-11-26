---
title: CLI reference
description: 0 CLI commands, arguments, options, aliases, and registered defaults.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

Pick your task below, or search for a command name.

New to 0? Read the [Quickstart](/) first. Settings and environment variables are on [Configuration](/configuration/).

## Start by task

| Task | Commands | Guide |
| --- | --- | --- |
| Scan code | [scan](#scan) · [threat-model](#threat-model) | [Findings](/findings/), [Threat model and policies](/threat-model-and-policy/) |
| Audit dependencies | [sbom](#sbom) · [sbom check](#sbom-check) · [sbom licenses](#sbom-licenses) | [Dependency audit](/dependency-audit/) |
| Check AI apps and agent files | [probe](#probe) · [sbom agent-config](#sbom-agent-config) · [sbom scan-models](#sbom-scan-models) | [AI security](/ai-security/) |
| Review, fix and prove findings | [findings](#findings) · [findings update](#findings-update) · [findings fix](#findings-fix) · [evidence](#evidence) · [threads](#threads) | [Findings](/findings/), [Threads](/threads/) |
| Automate | [sentinels](#sentinels) · [api](#api) | [Sentinels](/sentinels/) |
| Set up and extend | [config](#config) · [config doctor](#config-doctor) · [models](#models) · [models connect](#models-connect) · [skills](#skills) · [computers](#computers) | [Models](/models/), [Extensions](/extensions/), [Computers](/computers/) |

## The twelve commands

`0security` with no arguments opens the web console. `0` is a short alias for it. Everything else is one of twelve commands.

| Command | What it does | Subcommands |
| --- | --- | --- |
| `0security scan` | Scan a folder or git repository for security bugs; prints the findings as a report. | none |
| `0security threat-model` | Draft the repository's threat model as a file for people to review (optionally as a pull request). | none |
| `0security probe` | Send adversarial messages to a live model or agent endpoint and report the ones it obeys. | none |
| `0security sbom` | Generate an SBOM from lockfiles, check one against known advisories, and scan model files and agent configuration. | `generate`, `check`, `licenses`, `scan-models`, `agent-config`, `java-usage` |
| `0security findings` | Browse findings and change their status. `--format` exports, `--import` loads a report. | `list`, `show`, `update`, `import`, `fix`, `burndown`, `verify`, `metrics`, `rollup`, `evidence`, `export-fixes`, `report-draft` |
| `0security evidence` | Check that an evidence folder was signed with your key and is unchanged. | `verify` |
| `0security threads` | Start, follow and stop threads. | `list`, `show`, `send`, `start`, `stop` |
| `0security sentinels` | Create, run and change Sentinels. | `list`, `run`, `set` |
| `0security skills` | Skills and extensions: list, add. | `list`, `add` |
| `0security models` | Models and provider connections. | `list`, `set`, `connect` |
| `0security computers` | Remote computers that run 0. | `list`, `add` (alias `deploy`), `stop` |
| `0security config` | Settings, API keys, team setup and `config doctor`. | `get`, `set`, `doctor` |

## Invocation and safety

Run commands as `0security <command>`. Run `0security --version` for your release and `0security <command> --help` for a command's flags.

The browser app's chat uses the same words as slash commands: `/threads list`,
`/findings list`, `/models default` and `/config get` mirror `0security threads list`,
`0security findings list`, `0security models set` and `0security config get`. See [Slash commands](/threads/#slash-commands).

Option tables show the default each flag is registered with. A dash means no default is registered: the command may read it from configuration or require a value. A `--no-*` option shows the default of the positive flag. See [Configuration](/configuration/) for environment variables.

- With no arguments, `0security` opens the browser app. No account is needed. See [Browser app](/threads/).
- `0security -p "<prompt>"` runs one headless chat prompt. `0security -c` continues the last chat and `0security --resume <id>` a saved one.
- `0security --help` lists the twelve commands.
- Use explicit commands in automation. 0 routes a recognizable bare target to a command and refuses ambiguous input.
- With the SmolVM workbench profile on, the whole CLI runs inside an online Kali guest. `workbench` and `config` stay on the host, and a failure never falls back to host execution.

## Shortcut commands

These forms run the commands documented in the sections below.

### findings update

Change a finding's status to `accepted`, `suppressed`, `open` or `false-positive`. A false positive needs `--reason`, which is saved as its note.

Accepting a risk needs `--reason` and `--expires`. `--approver` is optional. The approver is a label you type: 0 does not check who you are. See [findings accept](#findings-accept).

```text
0security findings update [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--status <status>` | — | accepted \| suppressed \| open \| false-positive |
| `--note <text>` | — | Why (optional) |
| `--reason <text>` | — | Why; required with accepted and false-positive |
| `--expires <date\|90d>` | — | Accepted: when the acceptance ends (required) |
| `--approver <name>` | — | Accepted: who approved it, a label not a login |
| `--db-path <path>` | — | Path to SQLite database |

### models set

Show or choose the default model. It takes the same arguments as `models default`.

```text
0security models set [options] [model]
```

| Argument | Required | Description |
| --- | --- | --- |
| `model` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--provider <provider>` | — | Provider of the model |

### models connect

Add a provider connection, or list, test or remove one with `--list`, `--test` and `--remove`. These run `models connections add`, `list`, `test` and `remove`.

```text
0security models connect [options] [provider]
```

| Argument | Required | Description |
| --- | --- | --- |
| `provider` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--key-env <VAR>` | — | Add: read the API key from this environment variable |
| `--stdin` | — | Add: read the API key from stdin |
| `--list` | — | List connections (the default with no provider) |
| `--test` | — | Test a connection |
| `--remove` | — | Remove a connection (with --yes) |

### config doctor

Check this machine and the engine, including which OS sandbox backends are available (`sandbox-exec`, `bwrap`, Docker). `--fix` repairs the local database. The subcommands of `doctor` also work here: `config doctor upgrade`, `config doctor workbench` and `config doctor checks`.

```text
0security config doctor [options] [checks...]
```

| Argument | Required | Description |
| --- | --- | --- |
| `checks` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--fix` | — | Repair the local database |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

## Interactive & setup

### scan

Scan a folder or git repository for security bugs and print the findings as a report.

```text
0security scan [options] [target]
```

Run it on a folder or a git URL:

```bash
0security scan ~/code/app --format sarif -o scan.sarif --fail-on high
```

A scan is a thread that follows the `scan` skill, so it appears in `0security threads` and in the web app. Findings are stored under the thread id, and `0security findings export --scan <thread id>` gives the same report later.

The scan uses the running console, or the engine named by `--engine-url` or `--computer`. With none running, it starts a headless console and stops it afterwards.

Exit codes:

- 0: done
- 1: a finding at or above `--fail-on`, or the scan failed
- 2: usage error
- 3: not finished. The scan stopped at the budget or the time limit, or entry points were not reached, so the report is partial. This is not a failure. Findings so far are kept, and `--resume` continues the scan

Add `--allow-partial` when a partial scan should not fail the job. The exit code then follows the findings alone: 0, or 1 with `--fail-on`. The report still says it is partial.

| Argument | Required | Description |
| --- | --- | --- |
| `target` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--budget <usd>` | `5` | Stop when the estimated spend reaches this many USD; partial findings are kept |
| `--format <format>` | `md` | Report format: json, md, sarif, html, pdf |
| `-o, --output <file>` | — | Write the report to a file instead of stdout |
| `--fail-on <severity>` | — | Exit 1 when a finding is at or above this severity (critical, high, medium, low, info) |
| `--passes <n>` | `1` | Scan this many times and merge the findings (a scan misses some issues that another run finds); the budget is split between them, up to 5 |
| `--diff <ref>` | — | Review only the files that differ from this git ref (for example origin/main), and what they connect to; an empty diff scans nothing |
| `--prepass <mode>` | `auto` | auto runs the pattern scanners first when they are installed and gives their hits to the scan as leads; off skips them |
| `--scanner <id>` | — | Scanner for the pre-pass (foxguard, semgrep, opengrep, gitleaks, trivy, osv-scanner, checkov); nuclei is only for --target-url; repeat or separate with commas to use several (default: foxguard). gitleaks, trivy and osv-scanner must be installed; secret values are redacted |
| `--target-url <url>` | — | With --scanner nuclei: test this running app with Nuclei, which you installed. Needs --scope-file or --acknowledge-host. 0 sends no request itself; link-local and cloud metadata addresses are always refused |
| `--scope-file <file>` | — | With --target-url: a file listing the hosts you may test, one host or host:port per line |
| `--acknowledge-host <host>` | — | With --target-url: type the exact host being tested. A public host is refused without it |
| `--rate-limit <n>` | `10` | With --target-url: Nuclei requests per second (1 to 150) |
| `--templates <path>` | — | With --target-url: a Nuclei template file or folder to run instead of the templates Nuclei has installed. 0 never downloads templates |
| `--rules <file-or-folder>` | — | Semgrep or OpenGrep rules for the pre-pass (a file or a folder); repeat for several. Replaces the default rules and needs --scanner semgrep or opengrep. Rules are never read from the scanned folder unless you name them |
| `--business-context <file>` | — | Operator-owned JSON tags and notes for investigation and work ordering; keeps technical severity unchanged |
| `--context <file>` | — | Give the scan this file (a threat model, notes on who may do what) as lower-priority background; repeat for several. It can steer what the scan weighs but cannot change how it works |
| `--policy <file-or-folder>` | — | Check the code against these Markdown policies (a file or a folder of .md files) and report pass or fail for each; repeat for several. Runs the policy-check skill |
| `--org-policy <folder>` | — | An organisation's policy folder: evaluated first, and wins when a --policy says otherwise or uses the same id; repeat for several |
| `--scope <file>` | — | Read the declared scope from the '## Scope' section of this Markdown file (usually SECURITY.md). Findings that match a vector it lists as out of scope are labelled, listed apart and left out of the counts, --fail-on and the exit code; none are removed. In CI pass the base branch's copy |
| `--repo-scope` | — | Read SECURITY.md from the scanned folder as the declared scope. Off by default: a change under review can edit that file; in CI pass the base branch's copy with --scope instead |
| `--scope-sarif <mode>` | `label` | With --scope: label (default) writes the scope as result properties; suppress also marks out-of-scope results suppressed, which GitHub code scanning then dismisses |
| `--repo-context` | — | Also read .0/threat-model.md from the scanned folder as context. Off by default: a change under review can edit that file; in CI pass the base branch's copy with --context instead |
| `--repo-ignores` | — | Also let the pre-pass scanners read their configuration and ignore files from the scanned folder (.foxguard.yml, .semgrepignore, .gitleaks.toml, .gitleaksignore, .trivyignore, osv-scanner.toml, .checkov.yaml). Off by default: a change under review can use them to hide findings. Inline suppressions such as nosemgrep always apply |
| `--skill <id>` | `scan` | Skill that holds the scan method |
| `--model <model>` | — | Model for the scan thread (default: gpt-6-luna) |
| `--provider <id>` | — | Explicit model provider for this scan (use with --model) |
| `--reasoning <effort>` | — | Reasoning effort for a model that supports it |
| `--batches <mode>` | `auto` | auto reviews a large folder in batches, one thread per group of entry points, and records what each batch covered; on always does; off keeps one thread |
| `--codeowners <file>` | — | Group batches by an operator-provided CODEOWNERS file as well as build module; reads no ownership file automatically and never skips unowned code |
| `--batch-size <n>` | `8` | Entry points one batch reviews (1 to 50); a folder with more than this many is split under --batches auto |
| `--retries <n>` | `2` | Run a batch again when it fails for a reason that may pass: a dropped connection, a provider timeout, rate limit or server error (0 to 5; 0 turns it off). A thread that is not a batch is asked once to continue. The cost of every attempt counts against --budget |
| `--coverage-rounds <n>` | `1` | After a thread ends, send it a follow-up that names the source files it never opened, up to this many times (0 to 5; 0 turns it off). Each round counts against --budget |
| `--batch-timeout <seconds>` | `900` | Longest one batch may run before it is cancelled and left pending (the scan goes on with the next batch); --timeout still limits the whole scan |
| `--concurrency <n>` | `1` | Batches that run at the same time (1 to 3). With --target-url: Nuclei templates that run at once (1 to 25, default 5) |
| `--resume <scan>` | — | Continue the units an earlier batched scan of this folder did not reach (a scan id from its report, or latest); refuses when the git HEAD changed unless --force |
| `--force` | — | With --resume: continue even though the folder's git HEAD changed |
| `--coverage [scan]` | — | Print the coverage ledger of a batched scan of this folder (the latest, or the id given) and exit; --format json for JSON |
| `--allow-partial` | — | Exit by the findings alone (0, or 1 with --fail-on) when the scan stops before it reviews everything; the report still says it is partial |
| `--plan` | — | List the entry points, the batches and a rough cost range for the folder, then exit; calls no model and writes nothing |
| `--tiers <file>` | — | An operator's tier map (YAML or JSON) that sets the budget, batches and skill for this repository, or skips it. Default: scan-tiers.yaml\|yml\|json in the 0 state folder. Never read from the scanned folder on its own; in CI read it from the base branch |
| `--fail-on-skip` | — | Exit 1 when the tier map skips this scan (default: exit 0, with the skip stated in the report) |
| `--known <sarif>` | — | SARIF from other tools: the scan is told what is already known and looks for what they missed; findings are labelled new or already-known (confirmedIndependently when the scan analysed it itself). Repeat for several |
| `--only-new` | — | With --known: leave findings that match a known item out of the report |
| `--timeout <seconds>` | `3600` | Maximum seconds for the whole scan; what it reviewed so far is reported as partial |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

#### When the model provider fails

A dropped connection, a provider timeout, a rate limit or a server error stops one thread, not the code you scan. A batch that fails for one of these reasons runs again, up to 2 times, after a short wait. Set `--retries <n>` to change that, or `--retries 0` to turn it off. Budget stops, refused keys, invalid requests and cancelled threads are never retried. The cost of every attempt counts against `--budget`.

A scan without batches has no batch to run again. When its thread fails for one of these reasons, 0 asks the same thread once to continue. The findings it recorded stay in the report.

`--timeout` limits the whole scan. `--batch-timeout <seconds>` (default 900) limits one batch. A batch that passes it is cancelled and stays pending with the reason `timeout`, and the scan goes on with the next batch. A scan that passes `--timeout` stops and reports what it reviewed as partial.

When a scan fails or stops early, the error says why, in plain words. The JSON report has the same text in `failure`, with a `cause` such as `provider_connection`, `provider_timeout`, `provider_rate_limit`, `provider_server`, `provider_auth`, `provider_invalid_request`, `no_model`, `budget`, `timeout`, `batch_timeout` or `console_lost`. SARIF has it in the run properties. Keys and tokens are removed from the text.

#### Files the model did not open

A model does not always open every source file. After a thread ends, 0 checks which files it read, from the tool calls in the thread. If some source files were never opened, 0 sends the same thread a follow-up that names them and asks it to open and review each one. It does this once. Set `--coverage-rounds <n>` (0 to 5) to allow more rounds, or `--coverage-rounds 0` to turn it off.

Each round counts against `--budget` and is logged on stderr. A round does not start when little of the budget or time is left, after a failure, a time limit or a budget stop, or after two rounds in a row that opened none of the named files. Files over 200 KB, binary files, and vendored or generated files are not part of the check.

In a batched scan, a unit counts as reviewed only when its files were opened. A unit whose files stayed unopened stays pending with the reason `not opened`, and `--resume` runs it again. The report says so, for example `reviewed 41 of 57 entry points; 16 not reached (not opened); 3 files never opened`, and the exit code is 3. The JSON `coverage` has `opened`, `unopened` (the first 100 paths) and `rounds`. A scan with one thread has the same fields in `fileCoverage`.

The check reads shell commands such as `cat`, `sed`, `head` and `grep` on a file, a read tool, globs, and `find ... | xargs cat`. It can miss a file that was read some other way, so a follow-up may name a file the model did read.

To see what a scan involves before you run it, use `--plan`. It lists the entry points, the batches and a rough cost, and calls no model:

```bash
0security scan ~/code/app --plan
```

To review a change instead of the whole folder, pass `--diff <ref>`, for example in a pull request job:

```bash
0security scan . --diff origin/main --format sarif -o scan.sarif
```

0 reviews the files that differ from the ref (committed or not) and the code they connect to. The folder must be a git work tree. An empty diff starts no thread and writes an empty report.

If FoxGuard is installed, the scan runs it first. It takes seconds and costs nothing. The thread treats its hits as leads, checks each against the code, records only the real ones and says which it rejected. A pattern scanner cannot see logic bugs such as a missing ownership check, so the thread still reviews the entry points itself.

FoxGuard ships next to `0security`; set `ZERO_FOXGUARD_PATH` to use another copy. Pass `--prepass off` to skip it. `--scanner` chooses the scanners (`foxguard`, `semgrep`, `opengrep`, `gitleaks`, `trivy`, `osv-scanner`); repeat the flag or separate ids with commas to run several. A scanner that is not installed is skipped, and 0 says how to install it. A Semgrep rule pack such as `p/default` is downloaded when it runs.

```bash
0security scan ~/code/app --scanner foxguard,gitleaks,trivy
```

The default stays FoxGuard alone. The other scanners are not installed with 0. Set `ZERO_GITLEAKS_PATH`, `ZERO_TRIVY_PATH` or `ZERO_OSV_SCANNER_PATH` to use a binary outside your path.

| Scanner | Finds | Reaches the network |
| --- | --- | --- |
| `gitleaks` | Secrets in the files of the folder | No |
| `trivy` | Vulnerable dependencies, misconfigurations such as Terraform and Kubernetes, and secrets | Downloads its databases on first run |
| `osv-scanner` | Vulnerable dependencies in lockfiles | Sends package names and versions to osv.dev and deps.dev |

Each scanner runs without a shell, on the folder as an absolute path, with a time limit (2 minutes; 5 for trivy, 3 for osv-scanner). One that fails or runs out of time is skipped with a note.

A change under review can edit files in the folder to hide findings. So the scanners do not read the folder's own configuration or ignore files: `.foxguard.yml`, `.semgrepignore`, `.gitleaks.toml`, `.gitleaksignore`, `.trivyignore` and `osv-scanner.toml`. Inline suppressions such as `gitleaks:allow`, `nosemgrep` and `trivy:ignore` still apply, because they sit next to the code. Pass `--repo-ignores` to let the scanners read the folder's files; 0 prints a warning.

Checkov reads `.checkov.yaml` and `.checkov.yml` from the folder and has no option to ignore them. 0 skips Checkov when the folder has one of those files, unless you pass `--repo-ignores`.

Secret values stay out of the prompt and the findings. gitleaks runs with `--redact`, and trivy masks values by default. 0 also drops the snippet and any `Match:` line from a secret lead, so the thread sees the rule, the file and the line. The thread can still read the file itself, as it reads any file in the folder. `0security findings import` is unchanged.

To test a running app with Nuclei, pass the target and say what you may test. 0 starts Nuclei, which you installed. Nuclei sends the requests, not 0.

```bash
0security scan --scanner nuclei --target-url http://127.0.0.1:8080 --scope-file scope.txt
```

`scope.txt` lists one host or `host:port` per line. Or type the host with `--acknowledge-host`. A public host needs `--acknowledge-host` with the exact host, and refuses to run without it. Link-local and cloud metadata addresses are always refused. With `ZERO_ENTERPRISE` set, only loopback targets run.

When you give a name, 0 resolves it once, checks every address, and starts Nuclei on that address with the name in the Host header. Findings then show the address.

Nuclei runs at 10 requests per second and 5 templates at once. Change them with `--rate-limit` and `--concurrency`. Only http templates run, no redirect is followed, and those tagged `intrusive`, `dos` or `fuzz` are skipped. Out-of-band callbacks and update checks are off. Nuclei must be on your path, or set `ZERO_NUCLEI_PATH`. A template is code you chose: 0 checks the target, not what a template sends, so run only templates you trust. 0 never downloads Nuclei or its templates: run `nuclei -update-templates` yourself, or pass `--templates <file-or-folder>`.

The report says what authorised the run. The findings are saved for triage as unverified, and no model reviews them. See [Use Nuclei, ZAP or Strix](/use-dynamic-scanners/).

FoxGuard ships next to `0security`; set `ZERO_FOXGUARD_PATH` to use another copy. Pass `--prepass off` to skip it. `--scanner` adds or replaces scanners (`foxguard`, `semgrep`, `opengrep`, `checkov`); repeat the flag for several. A scanner that is not installed is skipped. A Semgrep rule pack such as `p/default` is downloaded when it runs.

`--rules <file-or-folder>` gives Semgrep or OpenGrep your own rules for the pre-pass. Repeat it for several. The scanner runs only those rules, not its default pack, so add `--scanner semgrep` or `--scanner opengrep`. FoxGuard has its own rule format and does not read them, so `--rules` alone is a usage error.

A rule file is standard Semgrep YAML:

```yaml
rules:
  - id: no-debug-backdoor
    languages: [javascript]
    severity: ERROR
    message: debugBackdoor skips the login check.
    pattern: debugBackdoor(...)
```

```bash
0security scan ~/code/app --scanner semgrep --rules ~/rules/company.yml
```

A hit from your rules is a lead like any other. The scan checks it against the code and records it only when it is real. A finding at the rule's lines gets `ruleSource: "custom"` in JSON and in the SARIF properties, and its description names the rule id. Semgrep prefixes the id with the rule file's folder.

0 never looks for rules in the scanned folder. A `.semgrep` folder there is ignored unless you name it with `--rules`. See [Add your own rules](/ci/#add-your-own-rules) for CI.

| Argument | Required | Description |
| --- | --- | --- |
| `target` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--budget <usd>` | `5` | Stop when the estimated spend reaches this many USD; partial findings are kept |
| `--format <format>` | `md` | Report format: json, md, sarif, html, pdf |
| `-o, --output <file>` | — | Write the report to a file instead of stdout |
| `--fail-on <severity>` | — | Exit 1 when a finding is at or above this severity (critical, high, medium, low, info) |
| `--passes <n>` | `1` | Scan this many times and merge the findings (a scan misses some issues that another run finds); the budget is split between them, up to 5 |
| `--diff <ref>` | — | Review only the files that differ from this git ref (for example origin/main), and what they connect to; an empty diff scans nothing |
| `--prepass <mode>` | `auto` | auto runs the pattern scanners first when they are installed and gives their hits to the scan as leads; off skips them |
| `--scanner <id>` | — | Scanner for the pre-pass (foxguard, semgrep, opengrep, gitleaks, trivy, osv-scanner, checkov); repeat or separate with commas to use several (default: foxguard). gitleaks, trivy and osv-scanner must be installed; secret values are redacted |
| `--rules <file-or-folder>` | — | Semgrep or OpenGrep rules for the pre-pass (a file or a folder); repeat for several. Replaces the default rules and needs --scanner semgrep or opengrep. Rules are never read from the scanned folder unless you name them |
| `--context <file>` | — | Give the scan this file (a threat model, notes on who may do what) as lower-priority background; repeat for several. It can steer what the scan weighs but cannot change how it works |
| `--policy <file-or-folder>` | — | Check the code against these Markdown policies (a file or a folder of .md files) and report pass or fail for each; repeat for several. Runs the policy-check skill |
| `--org-policy <folder>` | — | An organisation's policy folder: evaluated first, and wins when a --policy says otherwise or uses the same id; repeat for several |
| `--repo-context` | — | Also read .0/threat-model.md from the scanned folder as context. Off by default: a change under review can edit that file; in CI pass the base branch's copy with --context instead |
| `--repo-ignores` | — | Also let the pre-pass scanners read their configuration and ignore files from the scanned folder (.foxguard.yml, .semgrepignore, .gitleaks.toml, .gitleaksignore, .trivyignore, osv-scanner.toml, .checkov.yaml). Off by default: a change under review can use them to hide findings. Inline suppressions such as nosemgrep always apply |
| `--skill <id>` | `scan` | Skill that holds the scan method |
| `--model <model>` | — | Model for the scan thread (default: gpt-6-luna) |
| `--batches <mode>` | `auto` | auto reviews a large folder in batches, one thread per group of entry points, and records what each batch covered; on always does; off keeps one thread |
| `--batch-size <n>` | `8` | Entry points one batch reviews (1 to 50); a folder with more than this many is split under --batches auto |
| `--retries <n>` | `2` | Run a batch again when it fails for a reason that may pass: a dropped connection, a provider timeout, rate limit or server error (0 to 5; 0 turns it off). A thread that is not a batch is asked once to continue. The cost of every attempt counts against --budget |
| `--batch-timeout <seconds>` | `900` | Longest one batch may run before it is cancelled and left pending (the scan goes on with the next batch); --timeout still limits the whole scan |
| `--concurrency <n>` | `1` | Batches that run at the same time (1 to 3) |
| `--resume <scan>` | — | Continue the units an earlier batched scan of this folder did not reach (a scan id from its report, or latest); refuses when the git HEAD changed unless --force |
| `--force` | — | With --resume: continue even though the folder's git HEAD changed |
| `--coverage [scan]` | — | Print the coverage ledger of a batched scan of this folder (the latest, or the id given) and exit; --format json for JSON |
| `--allow-partial` | — | Exit by the findings alone (0, or 1 with --fail-on) when the scan stops before it reviews everything; the report still says it is partial |
| `--plan` | — | List the entry points, the batches and a rough cost range for the folder, then exit; calls no model and writes nothing |
| `--tiers <file>` | — | An operator's tier map (YAML or JSON) that sets the budget, batches and skill for this repository, or skips it. Default: scan-tiers.yaml\|yml\|json in the 0 state folder. Never read from the scanned folder on its own; in CI read it from the base branch |
| `--fail-on-skip` | — | Exit 1 when the tier map skips this scan (default: exit 0, with the skip stated in the report) |
| `--known <sarif>` | — | SARIF from other tools: the scan is told what is already known and looks for what they missed; findings are labelled new or already-known (confirmedIndependently when the scan analysed it itself). Repeat for several |
| `--only-new` | — | With --known: leave findings that match a known item out of the report |
| `--timeout <seconds>` | `3600` | Maximum seconds for the whole scan; what it reviewed so far is reported as partial |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

#### Infrastructure as code

To review Terraform, CloudFormation, Kubernetes manifests, Dockerfiles and GitHub Actions workflows, run Checkov as the pre-pass and load the `iac-review` skill:

```bash
0security scan ~/code/infra --scanner checkov --skill iac-review
```

Checkov flags single settings, such as an open port. The skill follows references between resources: a subnet named private whose route table reaches an internet gateway, a database group that trusts an open group, an `iam:PassRole` on `*`, a workflow that runs pull request code with secrets. Checkov hits are leads, and the thread keeps one only when it can show how it is exploitable.

Install Checkov with `brew install checkov` or `pipx install checkov`, or set `ZERO_CHECKOV_PATH`. Checkov runs with `--skip-download`, so it needs no network. The `iac-review` skill is experimental: on one small benchmark fixture it is not yet shown to beat the plain scan (see the [benchmark](https://github.com/0sec-labs/0security/blob/main/docs/design/benchmark.md)).

`--context <file>` gives the scan a file as lower-priority background, usually the repository's threat model (see [Threat model and policy checks](/threat-model-and-policy/)). The scan checks the rules it states.

0 never reads that file from the scanned folder on its own, because a pull request could edit it to blind the scan. In CI, pass a copy from the base branch. `--repo-context` reads `.0/threat-model.md` from the folder anyway and prints a warning.

`--scope <file>` reads the `## Scope` section of a Markdown file, usually SECURITY.md, and labels findings in vectors it lists as out of scope. They are listed apart and left out of the counts, `--fail-on` and the exit code. 0 does not read SECURITY.md on its own, because a pull request could edit it. `--repo-scope` reads it from the scanned folder and prints a warning. In CI, pass the base branch's copy with `--scope`. `--scope-sarif suppress` also marks the labelled SARIF results suppressed, which GitHub code scanning dismisses. See [Declare what is in and out of scope](/threat-model-and-policy/#declare-what-is-in-and-out-of-scope).

`--policy <file-or-folder>` checks the code against Markdown policies with the `policy-check` skill and answers pass, fail or not-applicable for each. `--org-policy <folder>` is an organisation's policy folder. It is evaluated first and wins over `--policy` on the same id or a conflicting rule.

A folder with more than 8 entry points, or more than 150 source files, is reviewed in batches: one thread per group of entry points, each recorded in a coverage ledger. The report states what was reviewed, for example `reviewed 41 of 57 entry points; 16 not reached (budget)`, and the exit code is 3 while anything is not reached. When a scan stops early, it prints what stopped it, how much is left and the command that continues it:

```text
Stopped by the $5 budget; 16 of 57 entry points not reached.
Continue with: 0security scan /home/you/code/app --resume scan-1f3a9c
```

Run that command, or read the ledger with `--coverage`:

```bash
0security scan ~/code/app --resume latest
0security scan ~/code/app --coverage
```

`--batches off` keeps one thread. See [Large repositories](/findings/#large-repositories).

#### Set the effort per repository

Not every repository deserves the same scan. A tier map is a file you own that maps repositories to a tier: `critical`, `standard`, `light` or `skip`. Each tier sets the budget, the batches mode and the skill, and whether the pattern scanners are enough.

```yaml
version: 1
default: standard
tiers:
  critical: { budget: 20, batches: on, reason: handles payments }
  light: { prepassOnly: true, reason: scanners are enough here }
  skip: { reason: archived }
repositories:
  - repo: your-org/payments
    tier: critical
  - repo: your-org/archive-*
    tier: skip
  - path: ~/code/experiments/**
    tier: light
    reason: throwaway code
```

Name the file with `--tiers`, or save it as scan-tiers.yaml, scan-tiers.yml or scan-tiers.json in the 0 state folder (`~/.0`). 0 never reads a tier file from the folder it scans, because a change could edit its own tier.

```bash
0security scan ~/code/payments --tiers ~/security/scan-tiers.yaml
```

0 finds the target's repository from its `origin` remote (or from the git URL you pass) and its folder path. The most specific entry wins: an exact repository, then an exact path, then the first pattern in the file that matches, then `default` (`standard` when the file names none). A `*` matches inside one name or folder; `**` matches across folders.

The scan prints the tier and the reason on stderr and records them in the report: `tier` in JSON, in the SARIF run properties and in the Markdown header. Settings are chosen in this order: a flag you type (such as `--budget 2`, or one set in the environment), then the tier, then the `workflows` defaults in your operator settings, then the built-in default. 0 says when a flag overrides the tier. A tier's `skill` is resolved like `--skill`: a bare name of an installed skill becomes its full id when the scan starts. `--plan` shows the tier too.

A tier given in the file replaces only the settings it names; the others keep their built-in values: `critical` 20 USD with batches on, `standard` 5 USD with batches auto, `light` 1 USD with one thread.

A `skip` tier runs nothing. The report says `skipped by tier <name>: <reason>`, the JSON `status` is `skipped`, and the exit code is 0. Add `--fail-on-skip` to exit 1 instead, so a missing scan cannot pass for a clean one. A skipped scan and a pre-pass-only scan each write a line to the run metrics file with status `skipped` or `prepass_only`.

With `prepassOnly: true`, only the pattern scanners run, with no model and no cost. They run as in any scan, including `--scanner`, `--rules` and `--repo-ignores`. Their hits are reported as findings labelled `Pre-pass only, not reviewed by a model.` The JSON `status` is `prepass_only`. If no scanner can run, the scan fails; it does not report a clean result.

#### Get a second opinion

Code often passes other scanners before it reaches you. `--known` takes their SARIF so the scan does not repeat them. Repeat the flag for several files.

```bash
semgrep scan --sarif --config p/default -o semgrep.sarif .
0security scan . --known semgrep.sarif --format json -o scan.json
```

The thread gets a bounded list of what is known (location, rule and a one-line message) as lower-priority data. It is asked to look for other classes of bug, especially authorization and business-logic flaws, and to record a listed item only with its own evidence.

The report labels each finding with a `knownStatus`, in JSON, in the SARIF result properties and in the Markdown:

- `new`: no known item at that place.
- `already-known`: a known item in the same file, within 5 lines, of the same kind of flaw.

An already-known finding also gets `confirmedIndependently: true` when the scan recorded its own analysis of the code, not only a copy of the list. The report counts new, already-known and confirmed-independently findings. `--only-new` leaves the matched findings out of the report, the counts and the `--fail-on` check, and says how many it hid.

`--known` is not stored with a batched scan. When you continue one with `--resume`, pass `--known` again, or the remaining batches run without it.

Paths in a known file must be relative to the scanned folder, or absolute inside it. Items outside it, or with no location, are given to the scan but never matched. How much `--known` helps depends on the code and the baseline: see the [benchmark](https://github.com/0sec-labs/0security/blob/main/docs/design/benchmark.md#second-opinion-with---known).

| Argument | Required | Description |
| --- | --- | --- |
| `target` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--budget <usd>` | `5` | Stop when the estimated spend reaches this many USD; partial findings are kept |
| `--format <format>` | `md` | Report format: json, md, sarif, html, pdf |
| `-o, --output <file>` | — | Write the report to a file instead of stdout |
| `--fail-on <severity>` | — | Exit 1 when a finding is at or above this severity (critical, high, medium, low, info) |
| `--passes <n>` | `1` | Scan this many times and merge the findings (a scan misses some issues that another run finds); the budget is split between them, up to 5 |
| `--diff <ref>` | — | Review only the files that differ from this git ref (for example origin/main), and what they connect to; an empty diff scans nothing |
| `--prepass <mode>` | `auto` | auto runs the pattern scanners first when they are installed and gives their hits to the scan as leads; off skips them |
| `--scanner <id>` | — | Scanner for the pre-pass (foxguard, semgrep, opengrep, gitleaks, trivy, osv-scanner); repeat or separate with commas to use several (default: foxguard). gitleaks, trivy and osv-scanner must be installed; secret values are redacted |
| `--rules <file-or-folder>` | — | Semgrep or OpenGrep rules for the pre-pass (a file or a folder); repeat for several. Replaces the default rules and needs --scanner semgrep or opengrep. Rules are never read from the scanned folder unless you name them |
| `--context <file>` | — | Give the scan this file (a threat model, notes on who may do what) as lower-priority background; repeat for several. It can steer what the scan weighs but cannot change how it works |
| `--policy <file-or-folder>` | — | Check the code against these Markdown policies (a file or a folder of .md files) and report pass or fail for each; repeat for several. Runs the policy-check skill |
| `--org-policy <folder>` | — | An organisation's policy folder: evaluated first, and wins when a --policy says otherwise or uses the same id; repeat for several |
| `--repo-context` | — | Also read .0/threat-model.md from the scanned folder as context. Off by default: a change under review can edit that file; in CI pass the base branch's copy with --context instead |
| `--repo-ignores` | — | Also honor ignore files and scanner configuration from the scanned folder (.gitleaks.toml, .gitleaksignore, .trivyignore). Off by default: a change under review can use them to hide secrets or misconfigurations |
| `--skill <id>` | `scan` | Skill that holds the scan method |
| `--model <model>` | — | Model for the scan thread (default: gpt-6-luna) |
| `--batches <mode>` | `auto` | auto reviews a large folder in batches, one thread per group of entry points, and records what each batch covered; on always does; off keeps one thread |
| `--batch-size <n>` | `8` | Entry points one batch reviews (1 to 50); a folder with more than this many is split under --batches auto |
| `--concurrency <n>` | `1` | Batches that run at the same time (1 to 3) |
| `--resume <scan>` | — | Continue the units an earlier batched scan of this folder did not reach (a scan id from its report, or latest); refuses when the git HEAD changed unless --force |
| `--force` | — | With --resume: continue even though the folder's git HEAD changed |
| `--coverage [scan]` | — | Print the coverage ledger of a batched scan of this folder (the latest, or the id given) and exit; --format json for JSON |
| `--timeout <seconds>` | `3600` | Maximum seconds to wait for the scan |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

### threat-model

Draft the repository's threat model as a file for people to review.

```text
0security threat-model [options] [folder]
```

A thread follows the `threat-model` skill and writes `.0/threat-model.md` in the folder, or the path in `--output`. The file has a summary, what matters most, assets, actors, trust boundaries, entry points, authorization and business rules, data flows and open questions. Front matter holds the date and the commit.

```bash
0security threat-model
0security threat-model ~/code/app --pr
0security threat-model --interview
0security threat-model --output THREAT_MODEL.md
```

`--interview` asks up to 8 specific questions on the terminal after the draft and writes your answers to the `## Scope` section of SECURITY.md and to a human block of the threat model. It asks one question per class of vulnerability, from the latest scan of the folder and from the code. It needs a terminal and exits with 2 without one.

```bash
0security threat-model --interview --from-scan report.json
0security threat-model --interview --scan --scan-budget 2
```

`--from-scan` takes a report from `0security scan --format json`. `--scan` shows a rough cost estimate and asks before it scans. See [Declare what is in and out of scope](/threat-model-and-policy/#declare-what-is-in-and-out-of-scope).

The file names only what the thread saw and marks the rest `unknown: confirm with the team`. Running it again updates the file and keeps every section marked `<!-- human -->`.

With `--pr`, the file is committed alone on the branch `0/threat-model` in a separate git work tree, and `gh` opens or updates a pull request. Nothing is merged.

It writes files on this machine, so it needs the local console and rejects `--computer` and `--engine-url`. See [Threat model and policy checks](/threat-model-and-policy/).

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--pr` | — | Commit the file on the branch 0/threat-model in a separate git work tree and open or update a pull request |
| `--base <branch>` | — | With --pr: the branch to start from and open the pull request against (default: the remote's default branch) |
| `--interview` | — | After the draft, ask a few specific questions on the terminal and write your answers to the Scope section of SECURITY.md and to a human block of the threat model. Needs a terminal |
| `--interview-budget <usd>` | — | With --interview: the most each interview thread may spend (default: 0.5) |
| `--scan` | — | With --interview: run a scan of the folder first and ask about the classes of vulnerability it finds. Shows the estimated cost and asks before it runs |
| `--from-scan <report>` | — | With --interview: ask about the classes in this saved report (from 0security scan --format json). Without --scan or --from-scan, the latest scan of the folder from the last 30 days is used when there is one |
| `--scan-budget <usd>` | — | With --scan: the most the scan may spend (default: 3) |
| `--output <path>` | — | Where to write the threat model, relative to the folder, a .md file (default: .0/threat-model.md); for example THREAT_MODEL.md |
| `--format <format>` | — | json prints the outcome as JSON |
| `--budget <usd>` | `3` | Stop when the estimated spend reaches this many USD |
| `--model <model>` | — | Model for the thread (default: gpt-6-luna) |
| `--timeout <seconds>` | `1800` | Maximum seconds to wait |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

### web

Open the local browser workspace for threads and findings.

```text
0security web [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--port <port>` | `48123` | Port to bind; 0 chooses a free loopback port |
| `--host <host>` | `127.0.0.1` | Loopback host to bind (127.0.0.0/8 or ::1) |
| `--asset-dir <path>` | — | Path to the built web app |
| `--dev-url <url>` | — | Loopback Vite server for authenticated frontend hot reload |
| `--team-config <path>` | — | Enable workspace accounts, roles, and shared conversation controls |
| `--engine-token-env <name>` | — | Environment variable holding the engine bearer credential (32–4096 characters) |
| `--engine-workspace <path>` | — | Engine-owned authorized workspace for persistent workflow calls |
| `--engine-allow-apply` | — | Admit explicitly approved patch application in persistent workflow calls |
| `--engine-time-cap <ms>` | — | Server workflow deadline ceiling (default 600000 ms) |
| `--engine-cost-cap <usd>` | — | Server workflow estimated cost ceiling (default $5) |
| `--server-mode` | — | Serve the console to a network behind a TLS proxy: requires sign-in, an allowed-host list and a single node (off by default) |
| `--allowed-host <host...>` | — | Server mode: accepted Host header names (default: only the bind host); also ZERO_ALLOWED_HOSTS |
| `--trusted-proxy <cidr...>` | — | Server mode: proxy addresses or CIDRs whose X-Forwarded-* headers are trusted; also ZERO_TRUSTED_PROXY |
| `--public-url <url>` | — | Server mode: the public https URL of this console (sign-in cookies, single sign-on); also ZERO_PUBLIC_URL |
| `--access-token-env <name>` | — | Server mode: environment variable holding the access token (32+ characters); default ZERO_ACCESS_TOKEN, else one is generated |
| `--shutdown-timeout <seconds>` | — | Server mode: seconds to finish in-flight requests on SIGTERM (default 20) |
| `--ready-json` | — | Emit the bound console URL as machine-readable JSON |
| `--no-open` | — | Do not auto-open a browser |
| `--headless` | — | Serve the API only: no browser, and no web app files needed (use with `0security threads`) |
| `--engines-config <path>` | — | Trusted engine connection registry JSON (default ~/.0/engines.json) |

### api

Call an admitted HTTP API on a running engine without sending a model prompt.

```text
0security api [options] [path]
```

Pick the engine with `--engine <id>` from an operator-managed registry, or with both `--engine-url <url>` and `--engine-token-env <name>`. The path defaults to `/api/backend/handshake` and must be an admitted `/api/` route.

```bash
0security api /api/backend/handshake --engine-url http://127.0.0.1:48123 --engine-token-env ZERO_ENGINE_TOKEN
```

Before it sends the request, 0 checks the engine's identity and advertised capabilities. A missing credential, an unsupported route, a redirect or a capability mismatch fails. It never falls back to local execution.

The default method is GET. For a change, set an explicit method and `--data`. JSON can be inline or `@file`; files and serialized bodies are limited to 1 MB, and GET and HEAD reject bodies. Pass the name of an environment variable for the bearer credential, never the credential itself. The server's authentication and approval checks still apply.

Responses are JSON envelopes with `ok`, HTTP `status` and `data`. Text exports appear as strings. An error exits nonzero and prints a JSON diagnostic on stderr.

A successful request does not mean queued work has finished. Keep the returned resource ID, check its status, and cancel explicitly if needed. The command does not download binaries, stream events or complete browser OAuth consent.

| Argument | Required | Description |
| --- | --- | --- |
| `path` | No | Admitted /api/ route; defaults to /api/backend/handshake. |

| Option | Registered default | Description |
| --- | --- | --- |
| `--method <method>` | `GET` | GET, POST, PATCH, PUT, DELETE or HEAD. Mutations require an explicit method and remain subject to engine authorization and approvals. |
| `--data <json-or-@file>` | — | JSON body, or @regular-file containing JSON (at most 1 MB) |
| `--engine-url <url>` | — | Attach directly to a trusted HTTP engine; requires --engine-token-env and cannot be combined with registered-engine options. |
| `--engine-token-env <name>` | — | Name of the environment variable holding the engine bearer credential, not the credential itself. Required with --engine-url. |
| `--engine <id>` | — | Select an operator-registered HTTP engine; cannot be combined with --engine-url. |
| `--engines-config <path>` | — | Operator engine registry JSON file |

### findings reports

Import retained CI artifacts into a local browser workspace without starting an assessment.

```text
0security findings reports
```

Subcommands: [import](#findings-reports-import) · [export](#findings-reports-export).

#### findings reports import

Read a JSON report and an optional `run.json`, validate them, and keep a passive snapshot in the database you select. Stop any engine using that database first, then open `0security web --db-path <same-path>`. The same report and metadata import once.

Imported findings stay discovered and unverified. Importing does not restore execution state or authorize fixes.

```text
0security findings reports import [options] <report>
```

| Argument | Required | Description |
| --- | --- | --- |
| `report` | Yes | JSON report produced by 0; importing executes no report commands |

| Option | Registered default | Description |
| --- | --- | --- |
| `--metadata <path>` | — | Optional run.json invocation and revision metadata |
| `--db-path <path>` **required** | — | Destination engine database; stop its browser engine before importing |

#### findings reports export

Write a share-safe copy of a JSON report. The copy keeps the target, summary and, for each finding, the id, title, severity, category, status, fingerprint, CVSS, confidence and source location. It drops evidence, PoC steps, agent transcripts, triage notes, suggested code and local absolute paths, and strips credentials, query strings and fragments from URL targets.

Free-text descriptions are left out unless you pass `--include-description`. The command only writes the copy; it sends nothing.

```text
0security findings reports export [options] <report>
```

| Argument | Required | Description |
| --- | --- | --- |
| `report` | Yes | JSON report produced by 0 |

| Option | Registered default | Description |
| --- | --- | --- |
| `--include-description` | — | Include each finding's free-text description (can quote code or secrets) |
| `--output <path>` | — | Write the share-safe report to a file instead of stdout |

### doctor

Check local runtime prerequisites and suggest the next command

```text
0security doctor [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--discard-reports` | — | Delete crash reports waiting for review on this computer |
| `--json` | — | Print JSON |

Subcommands: [upgrade](#doctor-upgrade) · [workbench](#doctor-workbench).

### config

Inspect, export, and import the two-level console configuration

```text
0security config
```

Subcommands: [get](#config-get) · [set](#config-set) · [doctor](#config-doctor) · [show](#config-show) · [list](#config-list) · [reset](#config-reset) · [export](#config-export) · [import](#config-import) · [audit-log](#config-audit-log) · [audit-export](#config-audit-export) · [audit-verify](#config-audit-verify) · [audit-prune](#config-audit-prune) · [team](#config-team) · [db](#config-db) · [github](#config-github).

#### config show

Show each setting's effective value and source: default, global, or project.

```text
0security config show [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config list

Same as `config show`. Add `--json` for each key's value and source layer.

```text
0security config list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config get

Print one setting's effective value. `--json` adds the layer it comes from.

`0security config get license` shows the state of your enterprise license: customer, seats, features, expiry and grace period. It never prints the key. See [Free and paid](/server-mode/#free-and-paid).

```text
0security config get [options] [key]
```

| Argument | Required | Description |
| --- | --- | --- |
| `key` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON with the source layer |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config set

Change one setting, with the same validation as the Settings page. It writes the global layer unless `--project` is given; operator-global settings refuse `--project`. Security-sensitive settings need `--yes`. Exit code 2 means a bad key or value; 1 means the engine refused the change.

```text
0security config set [options] <key> <value>
```

```bash
0security config set compactionThreshold 85%
0security config set allowModelSelfExtension on --yes
```

| Argument | Required | Description |
| --- | --- | --- |
| `key` | Yes |  |
| `value` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project` | — | Write the override for this folder |
| `--yes` | — | Confirm a security-sensitive setting |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config reset

Reset named settings, or every engine setting when none is named, to their defaults. Safety settings never reset to a looser value; the command lists any it kept. Requires `--yes`.

```text
0security config reset [options] [keys...]
```

| Argument | Required | Description |
| --- | --- | --- |
| `keys` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm the reset |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config export

Export effective configuration as JSON. Use `--global` for the global layer. Output goes to stdout unless a file is supplied.

```text
0security config export [options] [file]
```

| Argument | Required | Description |
| --- | --- | --- |
| `file` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--global` | — | Export only the global layer instead of the effective config |

#### config import

Merge a shared config into the global (default) or --project layer

```text
0security config import [options] <file>
```

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project` | — | Import into the override for this folder instead of the global config |
| `--global` | — | Import into the global config (default) |
| `--yes` | — | Accept changes to security-sensitive settings (required to flip them) |

### models connections

Manage model provider connections, the same actions as Settings → Connections in the browser. These commands use a running `0security web` engine when there is one, and otherwise apply the change directly on this computer. Keys are never passed as an argument: use `--key-env` or `--stdin`.

```text
0security models connections
```

```bash
export OPENAI_API_KEY_FOR_0="sk-..."
0security models connections add openai --key-env OPENAI_API_KEY_FOR_0
0security models connections list
0security models connections test openai
0security models connections remove openai --yes
```

Subcommands: [list](#models-connections-list) · [add](#models-connections-add) · [test](#models-connections-test) · [remove](#models-connections-remove).

#### models connections list

List providers with their status and saved accounts. `*` marks the active account.

```text
0security models connections list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### models connections add

Verify and save an API key for a provider. Exit code 2 means no key source was given; 1 means the provider rejected it.

```text
0security models connections add [options] <provider>
```

| Argument | Required | Description |
| --- | --- | --- |
| `provider` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--key-env <VAR>` | — | Read the API key from this environment variable |
| `--stdin` | — | Read the API key from stdin |
| `--account-id <id>` | — | Name this saved account |
| `--base-url <url>` | — | Custom API endpoint |
| `--model <model>` | — | Deployment model, where required |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### models connections test

Check that a connected provider answers and lists models.

```text
0security models connections test [options] <provider>
```

| Argument | Required | Description |
| --- | --- | --- |
| `provider` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### models connections remove

Remove a provider's saved credentials, or one saved account with `--account`. Requires `--yes`. A key supplied by an environment variable cannot be removed here.

```text
0security models connections remove [options] <provider>
```

| Argument | Required | Description |
| --- | --- | --- |
| `provider` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--account <id>` | — | Remove only this saved account |
| `--yes` | — | Confirm the removal |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### models

List the models your connected providers offer and choose the default, as on the Models page.

```text
0security models
```

```bash
0security models list --provider openai
0security models default --provider openai gpt-5.4-mini
0security models recommended
```

Subcommands: [list](#models-list) · [set](#models-set) · [connect](#models-connect) · [default](#models-default) · [recommended](#models-recommended) · [connections](#models-connections) · [usage](#models-usage).

#### models list

List models offered by connected providers, with price and context size.

```text
0security models list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--provider <id>` | — | Only this provider |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### models default

Show the default model, or set it. Setting requires `--provider`, and the provider must be connected.

```text
0security models default [options] [model]
```

| Argument | Required | Description |
| --- | --- | --- |
| `model` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--provider <id>` | — | Provider that serves the model |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### models recommended

Show the recommended model for each role, chosen from your connected providers.

```text
0security models recommended [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### config github

Check or connect the GitHub account used to publish fixes, as in Settings → Git.

```text
0security config github
```

```bash
0security config github status
0security config github connect --stdin < token.txt
0security config github repos --search api
```

Subcommands: [status](#config-github-status) · [connect](#config-github-connect) · [repos](#config-github-repos).

#### config github status

Show whether GitHub is signed in and which scopes are missing.

```text
0security config github status [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config github connect

Sign in with a personal access token read from an environment variable or stdin. The token is never printed.

```text
0security config github connect [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--key-env <VAR>` | — | Read the token from this environment variable |
| `--stdin` | — | Read the token from stdin |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### config github repos

List repositories the signed-in account can reach (cached for five minutes).

```text
0security config github repos [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--search <text>` | — | Only names containing this text |
| `--refresh` | — | Bypass the five-minute cache |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### models usage

Show spend and tokens of the open threads, by model or by thread. Open threads are only tracked by a running `0security web` engine; without one the report is empty.

```text
0security models usage [options]
```

```bash
0security models usage --by thread --json
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--by <model\|thread>` | — | Group by model (default) or list each thread |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### config audit-log

Show the local log of privileged actions: connection and settings changes, extension installs and denied attempts. The log is append-only.

```text
0security config audit-log [options]
```

```bash
0security config audit-log --q connection --limit 20
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--q <text>` | — | Only events whose action, subject or actor contains this text |
| `--limit <n>` | — | Maximum events to show |
| `--before <id>` | — | Only events older than this id (pagination) |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### config audit-verify

Check that the audit log was not edited, reordered or cut. Each event stores a hash of the event before it, so a change breaks the chain from that point on. The check is free, runs offline and needs no license. It prints the first break and exits 1. See [Check the audit log for tampering](/server-mode/#check-the-audit-log-for-tampering).

```text
0security config audit-verify [options]
```

```bash
0security config audit-verify
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--file <file>` | — | Check an export made with --with-proof, or a retention archive, instead of the live log |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### config audit-prune

Write audit events older than a time to a new archive file, then remove them from the log. A rotation checkpoint keeps the rest of the log verifiable. This is retention, an enterprise feature (`retention`). Without `--yes` the command only reports what it would do. See [Keep the audit log for a set time](/server-mode/#keep-the-audit-log-for-a-set-time).

```text
0security config audit-prune [options]
```

```bash
0security config audit-prune --older-than 365d --archive audit-2025.ndjson --yes
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--older-than <time>` | — | Events older than this: a duration (365d) or a date |
| `--archive <file>` | — | New file that receives the old events before they are removed |
| `--yes` | — | Do it. Without it the command only reports what it would remove |

### config audit-export

Write the audit log as NDJSON, CEF or syslog lines for a SIEM, oldest first. Each event has a stable `eventId`. Secret-looking values are redacted again on the way out. See [Send the audit log to a SIEM](/server-mode/#send-the-audit-log-to-a-siem).

```text
0security config audit-export [options]
```

```bash
0security config audit-export --format cef --since 24h -o audit.cef
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | — | ndjson (default), cef or syslog |
| `--since <time>` | — | Only events at or after this time: a duration (24h, 7d) or a date |
| `--until <time>` | — | Only events before this time |
| `--limit <n>` | — | Keep only the newest n matching events |
| `--type <action...>` | — | Only these actions or action prefixes, for example extension (repeatable, or comma separated) |
| `-o, --output <file>` | — | Write to this file with owner-only permissions instead of stdout |
| `--follow` | — | Keep running and print new events as they are written (Ctrl+C stops) |
| `--with-proof` | — | Write NDJSON rows with their chain hashes and a trailer, checkable with audit-verify --file (needs an enterprise license) |

### doctor workbench

Set up and inspect the online SmolVM security workbench on Apple Silicon macOS. The local Linux guest contains 0, the security tools and the browser. Docker is not required.

```text
0security doctor workbench
```

Subcommands: [run-agent](#doctor-workbench-run-agent) · [console-agent](#doctor-workbench-console-agent) · [setup](#doctor-workbench-setup) · [status](#doctor-workbench-status) · [providers](#doctor-workbench-providers) · [configure](#doctor-workbench-configure) · [disable](#doctor-workbench-disable).

#### doctor workbench run-agent

Internal entrypoint for the CLI engine inside the workbench guest. Normal commands select it automatically when the workbench profile is on. Outside an admitted guest it is refused.

```text
0security doctor workbench run-agent
```

#### doctor workbench console-agent

Internal entrypoint for the chat engine inside the workbench guest. Use `0security -p` or `0security` to start a chat. Outside an admitted guest it is refused.

```text
0security doctor workbench console-agent
```

#### doctor workbench setup

Verify or provision the signed native runtime, approve a local archive by digest, and save the operator-global SmolVM profile.

```text
0security doctor workbench setup [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--image <archive>` | — | Local OCI/Docker archive to digest-pin and approve; never a mutable registry tag |
| `--state <directory>` | — | Private VM state directory (defaults to ~/.0/workbench) |
| `--workspace <directory>` | — | Explicit workspace mount; otherwise each invocation mounts its current directory |
| `--provider <id>` | — | Grant chatgpt-codex requests through the host provider broker; credentials stay on the host |
| `--github` | — | Unsupported: GitHub credential forwarding is refused |
| `--no-github` | — | Revoke the GitHub token grant |
| `--cpus <count>` | — | Guest virtual CPUs |
| `--memory <MiB>` | — | Guest RAM in MiB |
| `--storage <GiB>` | — | Guest private writable storage in GiB |
| `--sandbox-image <reference=archive>` | — | Approve an immutable image reference for brokered isolated container actions; repeat for multiple images |

The supported provider grant is `chatgpt-codex`: model requests go through the host broker and credentials stay on the host. GitHub credential forwarding is refused. The host HOME, SSH configuration and Docker socket are not mounted into the guest.

#### doctor workbench status

Show configuration, native runtime readiness, image approval, effective privacy, network mode, broker resource ceilings and retained guest admission. It does not download or launch a VM or reveal credential values.

```text
0security doctor workbench status [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable status (no credential values) |

#### doctor workbench providers

List the exact identifiers accepted by `--provider`; this does not expose credentials.

```text
0security doctor workbench providers
```

#### doctor workbench configure

Replace integration grants or operator-approved sibling image references.

```text
0security doctor workbench configure [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--provider <ids>` | — | Replace provider grants with comma-separated IDs, or none |
| `--github` | — | Enable the explicit GitHub credential grant |
| `--no-github` | — | Revoke the GitHub credential grant |
| `--current-workspace` | — | Mount each invocation's current directory instead of a fixed saved workspace |
| `--sandbox-image <reference=archive>` | — | Add or replace an operator-approved immutable sandbox image reference; repeat for multiple images |
| `--clear-sandbox-images` | — | Revoke all explicit sandbox image-reference grants |

#### doctor workbench disable

Explicitly switch to host-local execution. Approved image and guest state remain.

```text
0security doctor workbench disable
```

### doctor upgrade

Fetch and install the latest release binary for 0 (re-runs install.sh).

```text
0security doctor upgrade [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--version <tag>` | — | Pin a specific release tag (e.g. v0.10.0) |
| `--install-dir <path>` | — | Override the install directory (default: the folder of this binary, else ~/.0/bin) |

## Findings & evidence

### probe

Send adversarial messages to a live model or agent endpoint and report the ones it obeys

```text
0security probe [options] <url>
```

Probe sends ten attacks to the URL you name and reports the ones whose reply shows they worked:

- a user message that overrides the instructions
- fake system markup
- instructions hidden in a document
- instructions encoded in base64
- a role-play jailbreak
- reading out the system prompt
- asking for credentials
- asking for a command to be run
- markdown that leaks data when rendered
- raw HTML in the reply

Each attack carries a unique canary, so a hit is a check on the reply (the canary came back, a credential appeared, `uid=` came back from a command), not another model's opinion. Models vary, so each probe is sent twice by default and one hit counts.

```bash
0security probe https://api.example.com/v1/chat/completions -H "Authorization: Bearer $OPENAI_API_KEY" --format sarif -o probe.sarif
```

The request is an OpenAI-style chat body. For another shape, pass `--body` with `{{prompt}}` where the message goes. 0 finds the reply in common JSON shapes, or at `--response-path`.

Put a key in a header as an environment variable, as above, so it is not typed on the command line. If you pass `--secret` with a secret that is in the endpoint's prompt, a reply that contains it is reported as a definite leak.

Point probe only at endpoints you own or are authorized to test. Probe sends attack text, and a public service can log it or act on it.

Local and private addresses need no flag. That covers localhost, 10.x, 172.16 to 172.31, 192.168.x, 100.64.x (such as a tailnet) and private IPv6. A public host is refused unless you type its exact name:

```bash
0security probe https://chat.mycompany.com/api --i-own-this chat.mycompany.com
```

Link-local and cloud metadata addresses (169.254.x.x, fe80::, fd00:ec2::254) are always refused, even with the flag. Probe resolves the name once, checks every address, and connects to the one it checked. A name that resolves to a private address is treated as private. A name with any public address needs the flag. A redirect to another origin stops the run. Probe sends at most 200 requests at least 200 ms apart to a public host.

The report records the host, the addresses it resolved to and the `--i-own-this` value. The `--format json` report has them in `probeScope`, and each finding carries them in its evidence. `ZERO_ENTERPRISE` does not change this, because you name the target.

Requests are 300 ms apart and capped at 100 by default. Findings go into the usual reports (`--format md|json|sarif|html|pdf`). With `--save` they also appear in `0security findings list`.

A miss means the reply did not show the attack working in those attempts. It does not prove the endpoint is safe against attacks outside the list.

| Argument | Required | Description |
| --- | --- | --- |
| `url` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `-H, --header <header>` | — | Request header, `Name: value`; the value may be $ENV_VAR so a key is not typed on the command line (repeatable) |
| `--body <json>` | — | Request body as JSON with {{prompt}} where the message goes (default: an OpenAI-style chat body) |
| `--body-file <file>` | — | Read the request body from a file |
| `--model <name>` | — | Add this model name to the default chat body |
| `--response-path <path>` | — | Where the reply is in a JSON response, such as choices.0.message.content (default: tried automatically) |
| `--probes <ids>` | — | Only these probes, comma separated (direct-override, delimiter-injection, indirect-document, encoded-instruction, persona-jailbreak, system-prompt-extraction, secret-request, tool-execution, markdown-exfiltration, raw-html-output) |
| `--repeat <n>` | `2` | Times each probe is sent; models vary, and a hit in any attempt counts |
| `--delay <ms>` | `300` | Pause between requests |
| `--timeout <seconds>` | `30` | Seconds to wait for each reply |
| `--max-requests <n>` | `100` | Send at most this many requests |
| `--i-own-this <host>` | — | Confirm you own or may test a public host by typing it exactly; local and private hosts need no flag, and link-local or metadata addresses are always refused |
| `--secret <text>` | — | A secret known to be in the endpoint's prompt; a reply that contains it is a definite leak |
| `--format <format>` | `md` | Report format: json, md, sarif, html, pdf |
| `-o, --output <file>` | — | Write the report to a file instead of stdout |
| `--fail-on <severity>` | — | Exit 1 when a finding is at or above this severity |
| `--save` | — | Also store the findings, so they show in `0security findings list` |

### sbom

Generate an SBOM from lockfiles, check one against known advisories, and scan model files

```text
0security sbom
```

Subcommands: [generate](#sbom-generate) · [check](#sbom-check) · [licenses](#sbom-licenses) · [scan-models](#sbom-scan-models) · [agent-config](#sbom-agent-config) · [java-usage](#sbom-java-usage) · [reachability](#sbom-reachability).

#### sbom generate

Write a CycloneDX 1.6 SBOM from the lockfiles in a folder (npm, pnpm, yarn, Cargo, Go, Python, Ruby, PHP, .NET, Maven, Gradle, Dart, Elixir)

```text
0security sbom generate [options] [folder]
```

```bash
0security sbom generate . -o sbom.cdx.json
```

The default `builtin` generator reads these lockfiles as text, anywhere under the folder, and installs or runs nothing: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock`, `go.mod`, `poetry.lock`, `Pipfile.lock`, pinned `requirements.txt`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`, `gradle.lockfile`, `pubspec.lock` and `mix.lock`. It skips `node_modules`, build output and hidden folders.

Components are identified by package URL, sorted and de-duplicated, so the same lockfiles give the same SBOM. A component is marked `excluded` only when every lockfile that lists it says it is development-only. A folder with no supported lockfile and nothing unresolved is an error (exit 2).

It also reads Maven and Gradle declarations as text, with the same rules: nothing is run (no `mvn`, no `gradle`) unless you pass `--resolve`, nothing is downloaded, and output is sorted. Components are looked up in OSV as `pkg:maven/<groupId>/<artifactId>@<version>`.

- `pom.xml`: direct dependencies, with versions taken from the literal version, `<properties>`, `<dependencyManagement>`, and a parent POM or imported BOM, but only when that parent or BOM is in the repository (the `relativePath`, or any POM in the folder with the same coordinates and version). Every `pom.xml` under the folder is read, so a multi-module project is aggregated; a child's own properties override its parent's. Modules of the repository are not listed as third-party components, and `test` scope is marked `excluded`.
- `gradle.lockfile`, `gradle/libs.versions.toml` and the dependency lines of `build.gradle` and `build.gradle.kts`: a version is read only when it is a literal. When `gradle.lockfile` pins an artifact, the lockfile's version is used and a declared version of the same artifact is dropped. A version catalog is read as declared, so an entry the build never uses is still listed.

What is not analysed is listed as unresolved, never guessed: profiles (their dependencies and properties), a parent POM or imported BOM that is not in the repository, a version from a property that no POM in the repository defines (including `env.` and system properties), version ranges and `LATEST`/`RELEASE`, a dependency with no managed version, a declared module with no POM, and in Gradle a variable, a dynamic version (`1.+`, a range, `latest.release`), a missing version, a `platform(...)` BOM and an unknown `version.ref`. The final line of `generate` reads `resolved N, unresolved M` (components with a known version, and items skipped), followed by the first 20 skipped items. The SBOM records each as a `0:unresolved` metadata property, and `0security sbom check` prints the same line from them.

Without `--resolve` this is a declaration reader, not a build. It does not resolve transitive dependencies, private registries or mirrors, or `settings.xml`, and it makes no claim about whether vulnerable code is reachable.

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | No | Folder to read lockfiles from (default: .) |

| Option | Registered default | Description |
| --- | --- | --- |
| `-o, --output <file>` | — | Write the SBOM to a file instead of stdout |
| `--name <name>` | — | Name of the application the SBOM describes (default: the folder's name) |
| `--generator <tool>` | `builtin` | Who writes the SBOM: builtin (reads lockfiles; default), syft, cdxgen, trivy (run the installed tool; exit 2 if it is missing) |
| `--format <format>` | `cyclonedx` | Output format: cyclonedx (1.6, default) or spdx (2.3 JSON; builtin generator only) |
| `--image <reference-or-archive>` | — | Describe a container image instead of a folder: a reference such as nginx:1.25, or the path of a docker save archive or OCI layout. Needs --generator syft or trivy, which pulls the image |
| `--resolve` | — | Maven and Gradle: run the project's own mvn or gradle to resolve the full dependency tree (runs build scripts, downloads from the network; needs --allow-build-tools or a yes at the prompt) |
| `--allow-build-tools` | — | Confirm --resolve without the prompt: you trust this project to run its build |
| `--resolve-offline` | — | With --resolve, run the tool offline (mvn -o, gradle --offline): only cached artifacts resolve |
| `--resolve-from <file>` | `[]` | Maven and Gradle: read the output of mvn dependency:tree (text) or gradle dependencies that you already ran; repeat for more files. Nothing runs or downloads, so it works offline and under ZERO_ENTERPRISE |
| `--maven-settings <file>` | — | With --resolve, pass this settings.xml to mvn (-s): your mirror, proxy and credentials |
| `--gradle-init-script <file>` | — | With --resolve, pass this init script to gradle (-I): your mirror and proxy |
| `--ai` | — | Also list the AI in the folder as an ML-BOM: model files, datasets, Hub references, hosted model ids and MCP servers, found by reading files |

##### Resolve Maven and Gradle dependencies

Add `--resolve` to run your own build tool and get the full dependency tree, including transitive packages, BOMs, parent POMs and profiles.

```bash
0security sbom generate . --resolve --allow-build-tools -o sbom.cdx.json
```

With a `pom.xml`, 0 runs `mvn dependency:tree`. With `build.gradle` or `build.gradle.kts` files, 0 runs `gradle dependencies --configuration runtimeClasspath` once for each project folder, up to 25. It reads the trees, adds the transitive graph to the SBOM, and marks each component the tool resolved with the property `0:resolved` set to `true`. A resolved version replaces a declared version of the same package. Declared packages the tool did not report stay in the SBOM without the mark.

This runs the project's build, so it is off by default. The build tool evaluates the project's build files, which can run arbitrary code, and it downloads from the repositories the project names. 0 prints a warning, then asks for a yes at a terminal. Without a terminal, or in CI, pass `--allow-build-tools` to confirm. Run it only on a project you trust.

0 starts `mvn` or `gradle` from your `PATH`, without a shell, with a 10 minute limit and a 16 MB output limit. It never runs `mvnw` or `gradlew` from the project. The tool gets your `PATH`, `HOME`, `JAVA_HOME`, `MAVEN_*`, `GRADLE_*` and proxy variables, and no other variable, so your API keys stay out of the build. `--resolve-offline` adds `-o` to Maven and `--offline` to Gradle, so only cached artifacts resolve. `ZERO_ENTERPRISE` refuses `--resolve`.

If a tool is missing or the build fails, 0 exits with 2 and prints the tool's error lines. Gradle test dependencies are not listed, because only the runtime classpath is read. Maven test and provided scopes are marked `excluded`.

Parent POMs and BOMs outside the repository resolve only as far as your Maven or Gradle settings let them.

##### Use a private mirror

Your own `~/.m2/settings.xml` and Gradle configuration apply by default. To use a different file, name it. Both files are yours: 0 never reads one from the project.

```bash
0security sbom generate . --resolve --allow-build-tools --maven-settings ~/mirror/settings.xml --gradle-init-script ~/mirror/init.gradle
```

0 passes the Maven file as `mvn -s` and the Gradle file as `gradle -I`. It does not read either file itself.

##### Read a report you already ran

If you cannot run a build tool here, run it elsewhere and give 0 the output. Nothing runs, nothing is downloaded, and `ZERO_ENTERPRISE` allows it.

```bash
mvn dependency:tree -DoutputType=text -DoutputFile=tree.txt
0security sbom generate . --resolve-from tree.txt
```

For Gradle, save the output of `gradle dependencies --configuration runtimeClasspath`. Repeat `--resolve-from` for several files. Components from a report are marked `0:resolved` like the ones from `--resolve`.

To see where your source imports each package, use [sbom java-usage](#sbom-java-usage).

Tested against the real output of Maven 3.9 and Gradle 9 on small projects (saved in the repository), and with fake `mvn` and `gradle` programs for the options. A mirror was not tested against a real Nexus or Artifactory server.

Beyond name and version, the SBOM carries the following, only where the lockfile states it. Nothing is looked up or guessed.

- Hashes (`hashes`, hex): npm `integrity`, pnpm `resolution.integrity`, yarn classic `integrity`, Cargo `checksum`, Composer `dist.shasum` and Gemfile.lock `CHECKSUMS` (Bundler 2.5 and later). A Poetry package with several files or a gem with several platform builds gets no hash, because a component has one hash. Yarn Berry checksums are not reported, because they hash Yarn's cache archive and not the published package. Go, Pipfile, `requirements.txt`, NuGet, Gradle, Dart and Mix get no hash. When two lockfiles disagree on a hash, it is left out.
- Dependency graph (top-level `dependencies`): from npm lockfile v2 and v3, pnpm, yarn classic and Berry, Cargo, Poetry, Gemfile.lock and Composer (platform requirements such as `php` are skipped). A component whose lockfile records a graph and lists no dependencies has an empty `dependsOn`. A component from a lockfile that records no graph (Go, Pipfile, `requirements.txt`, NuGet, Gradle, Dart, Mix, npm lockfile v1) has no entry, which means unknown. The application itself gets no dependencies, so direct versus transitive is not recorded.
- Licenses (`licenses`): from npm lockfile v2 and v3 and Composer. A valid SPDX id is written as `id`, a valid SPDX expression as `expression`, and anything else as the `name` exactly as stated. Other lockfiles state no license, and 0 does not fetch licenses from registries.

The supplier of each component is not recorded.

Add `--ai` to also list the AI in the folder as CycloneDX 1.6 components. It lists what it saw. It does not check where anything came from.

Local model files (`.gguf`, `.safetensors`, `.onnx`, `.pt`, `.pth`, `.ckpt`, `.pkl`, `.h5`, `.keras`, `.tflite`, `pytorch_model*.bin` and others) become `machine-learning-model` components with:

- a SHA-256 hash of the file, the format and the size in bytes
- tensor count, parameter count and data types for safetensors; architecture name, tensor count and context length for GGUF; IR version, producer and opset for ONNX. Only the file header is read, as data.
- the licence, only when a `README.md` front matter `license:` or a `LICENSE` file sits in the same folder and is a recognised licence. A front matter value that is not an SPDX id is written as a name, unchanged.
- a `modelCard` with `task` from the front matter `pipeline_tag`, `architectureFamily` from the `model_type` in `config.json` or the GGUF architecture, `modelArchitecture` from `config.json` `architectures`, and the front matter `datasets` as references. A field with no source is left out.
- a risk property on pickle-based formats, which run code when loaded

A file over 2 GiB, or past 4 GiB hashed in one run, gets a `0:hash-skipped` property instead of a hash. Pickle and Keras files are hashed but never loaded.

References in code (`from_pretrained`, `pipeline(..., model=)`, `hf_hub_download`, `load_dataset`) become components with a Hugging Face Hub URL as an external reference. A commit hash in `revision=` is recorded as the version. Without one, the component has a `0:unpinned-revision` property. The URL is built from the text in the code. 0 does not contact the Hub, so the model or dataset may not exist.

Local data files (`.csv`, `.tsv`, `.jsonl`, `.parquet`, `.arrow`, `.npy` and a few more) become `data` components with a SHA-256 hash when the file is under 256 MiB. At most 200 are listed.

Hosted model ids passed to provider SDKs are listed with the provider. MCP servers from `.mcp.json` and similar files, including those under `.claude`, `.codex` and `.github`, become services, with an unpinned launcher such as `npx -y` flagged.

These fields are not filled: inputs and outputs, quantitative analysis, considerations, data governance and classification, and any provenance or signature check. The result is not a complete AI inventory and does not show compliance with any regulation.

The scan reads files as text and downloads nothing. It never follows a symlink, opens a device or FIFO, loads a model or runs code. It stops at 8000 files or 4000 folders and says so in a `0:ai-note` metadata property. A reference the patterns do not recognise is missed. It works with `ZERO_ENTERPRISE` set.

The builtin generator does not read CocoaPods, SwiftPM, C and C++ package managers, operating-system packages or compiled binaries. Use `--generator` for those, and `--generator` with `--image` for container images.

`--format spdx` writes SPDX 2.3 JSON instead (builtin generator only). It has one package for the application and one per library, each with its package URL as a `purl` external reference, its checksums, and its license when that is an SPDX id or expression. Free-text license names become `NOASSERTION`. `DESCRIBES` points at the application and `DEPENDS_ON` follows the graph above. The AI inventory is not written to SPDX, and `--ai` is refused with it.

`--generator syft`, `cdxgen` or `trivy` runs that installed tool instead and writes its CycloneDX JSON unchanged. Use it for what the builtin reader does not cover, such as transitive Maven and Gradle resolution, operating-system packages and binaries. `--ai` and `--format spdx` are not available with these tools.

To describe a container image, pass `--image` with `syft` or `trivy`. The value is a reference such as `nginx:1.25`, the path of a `docker save` archive, or the path of an OCI image layout folder. Then check the result against known advisories:

```bash
0security sbom generate --generator syft --image nginx:1.25 -o img.cdx.json
0security sbom check img.cdx.json
```

syft or trivy reads the image, from your local Docker daemon or by pulling it from a registry. 0 does not unpack layers itself, so the SBOM is only as complete as that tool's catalogue. `--image` is refused with the builtin generator and with cdxgen, with a folder argument, and with a value that starts with `-`, has spaces, or names a folder that is not an OCI layout. 0 passes the reference after `--`, so it cannot be read as an option.

0 starts the tool without a shell, on the folder as an absolute path, with a 10 minute timeout and a temporary working directory. It executes nothing from the scanned folder itself. If the tool is not installed, 0 prints how to install it and exits 2. The tool's own behaviour, such as network access, is its own. The commands are:

```text
syft dir:<folder> -o cyclonedx-json
cdxgen --lifecycle pre-build --no-install-deps -o <temp file> <folder>
trivy fs --format cyclonedx --quiet <folder>
syft -o cyclonedx-json -- <image>
trivy image --format cyclonedx --quiet -- <image>
```

The two cdxgen flags keep it from running the project's package manager. These tools write CycloneDX 1.7, not 1.5, and their component counts differ from the builtin reader, because each also walks the other trees in the folder. Whether trivy fetches its vulnerability database on a first run, and how older cdxgen versions treat those flags, is not verified.

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | No | Folder to read lockfiles from (default: .) |

| Option | Registered default | Description |
| --- | --- | --- |
| `-o, --output <file>` | — | Write the SBOM to a file instead of stdout |
| `--name <name>` | — | Name of the application the SBOM describes (default: the folder's name) |
| `--generator <tool>` | `builtin` | Who writes the SBOM: builtin (reads lockfiles; default), syft, cdxgen, trivy (run the installed tool; exit 2 if it is missing) |
| `--format <format>` | `cyclonedx` | Output format: cyclonedx (1.5, default) or spdx (2.3 JSON; builtin generator only) |
| `--image <reference-or-archive>` | — | Describe a container image instead of a folder: a reference such as nginx:1.25, or the path of a docker save archive or OCI layout. Needs --generator syft or trivy, which pulls the image |
| `--ai` | — | Also list the AI in the folder: models, datasets, hosted model ids and MCP servers, found by reading files as text |

#### sbom check

Look every component of an SBOM up in the public OSV database and list the advisories

```text
0security sbom check [options] <file>
```

Each advisory is listed under its component with its aliases, severity, the version that fixes it and a one-line summary, most severe first. Exit 0 when there are no advisories and 1 when there are, so a scheduled job can fail or open an issue.

```bash
0security sbom generate . -o sbom.cdx.json
0security sbom check sbom.cdx.json
```

```text
lodash 4.17.15  pkg:npm/lodash@4.17.15
  GHSA-35jh-r3h4-6jhm (CVE-2021-23337)  high (CVSS 7.2)  Fixed in 4.17.21.
    Command Injection in lodash
```

The fixed version is the lowest version above the installed one that the advisory names for that package. If the advisory names none, the line says `No fixed version known.` Severity comes from the database's own label, or from a CVSS 3 vector when there is no label. A record with neither, or with only a CVSS 4 vector, shows `unknown`.

A package that OSV lists as malicious (an id that starts with `MAL-`) is shown as `MALICIOUS PACKAGE` at critical severity, under a banner line. Remove it, and treat any machine or pipeline that installed it as compromised. It makes the exit code 1 like any advisory.

`--format sarif` writes one result per vulnerable component and advisory. The rule id is the advisory id, the level follows severity, and the message names the fixed version. The location is the lockfile the component came from when the SBOM records it (`0security sbom generate` does), and the SBOM file otherwise. Write it to a file and import it:

```bash
0security sbom check sbom.cdx.json --format sarif -o deps.sarif
0security findings import deps.sarif
```

Importing the same results again changes nothing. `--format json` writes the advisories with their fixed version, severity and a `malicious` flag.

Add `--outdated` to also list components that have a newer version. This looks each package up at `https://api.deps.dev`, so package names go out. It checks at most 200 components, runtime dependencies first, and says how many it skipped. Each note shows the latest version and how far behind the installed one is. A newer version is information only. It does not mean the installed one is unsafe, and it never changes the exit code.

Add `--registry` to look each npm and PyPI package up on its public registry for invented or planted names. AI coding tools sometimes write package names that do not exist, and attackers register those names ([Spracklen et al., USENIX Security 2025](https://arxiv.org/abs/2406.10279)). A code review of AI-written changes does not catch a name that looks plausible.

```bash
0security sbom check sbom.cdx.json --registry --fail-on high
```

The check reports signals, not proof. It makes no model call. These rules can appear:

- `slopsquat/nonexistent` (medium): the name is not on the public registry. If the package is private, ignore it.
- `slopsquat/new-package`: first published less than 30 days ago (change it with `--new-days`) and three releases or fewer. It is high with an npm install script, medium with under 1000 downloads last week, and low otherwise.
- `slopsquat/typosquat-candidate`: the name is one or two edits from a very popular package, and the package is new or little used. It is high when new or when it has an install script, and medium otherwise.

Each finding states the values it rests on, such as age, releases, maintainers, weekly downloads and install script, with a link to the package page. Weekly downloads are an npm signal only. The popular names come from a bundled list of 300 npm and 300 PyPI packages.

Private and local packages are skipped and listed as skipped: private or local. That covers scoped npm names outside a short list of well-known public scopes, workspace members, packages the lockfile resolves from another registry or from a path (npm, pnpm, Yarn, Poetry and Pipfile locks, and any `requirements.txt` that sets an index other than pypi.org), and anything you name with `--private` (a name or `@scope/*`, repeatable). Name your own packages so they are not looked up.

Only package names go out, to `https://registry.npmjs.org`, `https://api.npmjs.org` and `https://pypi.org`. It checks at most 200 packages, four at a time, with a 10 second timeout and an 8 MB answer limit. A lookup that fails or is too large is listed as not checked. Under `ZERO_ENTERPRISE` or `ZERO_OFFLINE` nothing is looked up, and the report says `not checked`, never a clean result. Without `--fail-on` registry findings never change the exit code. With it, a finding at or above that severity exits 1. SARIF output includes registry findings. Cargo and Go are not covered.

The network use is the lookup at `https://api.osv.dev`: package URLs go out and nothing else does.

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes | CycloneDX SBOM (JSON), for example from `0security sbom generate` |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `text` | Output: text, json or sarif (SARIF imports with `0security findings import`) |
| `-o, --output <file>` | — | Write the result to a file instead of stdout |
| `--source <folder>` | — | Attach JVM source-import and dependency-path evidence; does not suppress advisories or establish vulnerable-code reachability |
| `--outdated` | — | Also list components with a newer version (looks packages up at https://api.deps.dev; information only, not a vulnerability) |
| `--registry` | — | Also look each npm and PyPI package up on its public registry for invented or planted names (sends package names to registry.npmjs.org, api.npmjs.org and pypi.org) |
| `--new-days <days>` | — | With --registry: a package first published fewer days ago than this is new (default 30) |
| `--private <name>` | — | With --registry: a package name, or @scope/*, to treat as private and skip; repeat the option or separate names with commas |
| `--fail-on <severity>` | — | With --registry: exit 1 when a registry finding is at or above this severity: critical, high, medium, low or info |

#### sbom licenses

Check the licenses in an SBOM, or in a folder's lockfiles, against an allow or deny policy

```text
0security sbom licenses [options] [sbom-file-or-folder]
```

```bash
0security sbom licenses . --preset permissive
0security sbom licenses sbom.cdx.json --deny 'GPL-*,AGPL-*' --format sarif > licenses.sarif
0security sbom licenses . --policy license-policy.yaml --resolve
```

Pass a CycloneDX SBOM file, or a folder. For a folder, 0 reads the lockfiles as in [sbom generate](#sbom-generate) and checks the result. The output lists each component as denied, not allowed, unknown or allowed. The output and this page are information from lockfiles and registries. They are not legal advice.

Components with no license data are unknown. Only npm lockfiles (`package-lock.json` v2 and v3) and `composer.lock` state licenses. A pnpm, yarn, Cargo, Go, Python, Ruby or NuGet lockfile gives none, so a check of such a repository is mostly unknown until you add `--resolve`. 0 prints a notice when more than half the components are unknown.

`--resolve` looks up each component that states no license on [deps.dev](https://deps.dev). It sends the package name and version and nothing else, makes up to 8 requests at a time, and stops after `--resolve-limit` components (default 2000). It covers npm, Cargo, Go, PyPI, RubyGems, NuGet and Maven. Components from other ecosystems stay unknown. Looked-up components are marked `[deps.dev]`.

On this repository, a check with `--preset permissive` found 1088 of 1107 components unknown. With `--resolve` 11 stayed unknown, 30 were not allowed (LGPL, MPL-2.0, OFL-1.1, CC-BY-4.0 and Unicode-3.0 licenses) and 1066 were allowed.

| Argument | Required | Description |
| --- | --- | --- |
| `sbom-file-or-folder` | No | CycloneDX SBOM (JSON), or a folder to read lockfiles from |

| Option | Registered default | Description |
| --- | --- | --- |
| `--preset <name>` | — | Start from a preset: permissive or no-copyleft |
| `--policy <file>` | — | Policy file (JSON or YAML): allow, deny, allowByPackage (with a reason), unknown |
| `--allow <ids>` | — | Comma list of SPDX ids to allow; any license not listed is not allowed |
| `--deny <ids>` | — | Comma list of SPDX ids to deny; a trailing * matches a family, for example GPL-* |
| `--unknown <mode>` | — | What a component with no usable license data does: warn (default), fail or allow |
| `--resolve` | — | Look up the license of components that state none on deps.dev (network; sends package names and versions) |
| `--resolve-limit <n>` | — | With --resolve, look up at most this many components (default 2000) |
| `--exclude-dev` | — | Skip components that are development-only |
| `--format <format>` | `text` | Output: text, json or sarif |

##### Write a policy

A policy is an allow list, a deny list, exceptions and a rule for unknown licenses. Start from a preset, a policy file, or the `--allow` and `--deny` flags. They combine: lists are joined, and a license on the deny list is denied even if it is also allowed.

- `--preset permissive` allows MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, Unlicense, CC0-1.0, Zlib, BlueOak-1.0.0 and Python-2.0. Every other license is not allowed. Unknown is `warn`.
- `--preset no-copyleft` denies the GPL, AGPL, LGPL, SSPL and EUPL families. Every other license is allowed. Weak copyleft such as MPL-2.0, EPL-2.0 and CC-BY-SA is not denied. Unknown is `warn`.

A policy file is JSON or YAML:

```yaml
# license-policy.yaml
preset: no-copyleft
allow: []
deny:
  - SSPL-*
  - CC-BY-NC-4.0
allowByPackage:
  - package: pkg:npm/some-library
    version: 2.1.0
    reason: Dual-licensed, we use it under MIT.
  - package: internal-tool
    licenses: [LGPL-3.0-or-later]
    reason: Linked dynamically and not distributed.
unknown: warn
```

- `allow` and `deny` hold SPDX ids. Ids are case-sensitive. An id ending in `*` matches a family, for example `GPL-*`. `GPL-2.0-only WITH Classpath-exception-2.0` names a license with an exception, and it beats a rule about the license alone.
- If `allow` has any entry, every license not listed is not allowed. Without an allow list, every license not denied is allowed.
- `allowByPackage` waives one component, named by name, package URL or package URL with version. `reason` is required. With `licenses`, the entry allows only those ids for that component instead of waiving it.
- `unknown` is `warn` (listed, exit 0), `fail` (listed, exit 1) or `allow` (counted only). The flag `--unknown` overrides the file.

An unrecognised key or id is a usage error, so a typo does not weaken the policy.

##### How licenses are judged

0 evaluates SPDX expressions. In `MIT OR Apache-2.0` you choose, so one allowed side is enough. In `GPL-2.0-only AND MIT` you need both, so both must be allowed. A deny applies to an `OR` only when every side is denied. `GPL-2.0+` and `GPL-2.0-or-later` are the same license, as are `GPL-2.0` and `GPL-2.0-only`. For other licenses, `Apache-2.0+` counts as `Apache-2.0`. Operators are upper case.

A component that lists several licenses as separate entries is treated as needing all of them, because CycloneDX does not say whether they are alternatives. Write an expression with `OR` if you mean a choice.

A license `name` in free text, an `id` that is not on the SPDX list, and an expression 0 cannot parse are unknown. 0 does not match them against ids, so `{ "license": { "name": "MIT" } }` is unknown.

Use `--exclude-dev` to skip components that are development-only. A violation is a denied or not-allowed component, or an unknown one when `unknown` is `fail`. 0 exits 1 on any violation, 0 otherwise, and 2 on a usage error.

`--format json` lists every component with its verdict. `--format sarif` writes one result per violating component, and per unknown component unless `unknown` is `allow`. The rule id is `license/<spdx-id>` (`license/unknown` for unknown), the location is the lockfile that lists the component (the SBOM file when you pass one), and the fingerprint is stable between runs. Import it with `0security findings import licenses.sarif`.

#### sbom scan-models

Scan model files (pickle, PyTorch, joblib, numpy) for imports that can run code when loaded

```text
0security sbom scan-models [options] <path>
```

```bash
0security sbom scan-models ./models
```

Pickle-based model files (`.pkl`, `.pickle`, `.joblib`, `.pt`, `.pth`, `.ckpt`, `.bin`, `.npy`, `.npz`, including the `data.pkl` inside a PyTorch zip) run the callables they reference when they are loaded. This command reads the files as bytes and sorts every imported callable into three groups:

- dangerous: `os.system`, `subprocess.*`, `builtins.eval`/`exec`/`__import__`/`open`, `importlib.*`, `socket.*`, `shutil.*`, network clients, `ctypes.*`, nested `pickle.loads`/`torch.load` and similar
- expected: tensor rebuild helpers, storages, `collections.OrderedDict`, numpy array reconstruction and the like
- unrecognised: on neither list, reported at lower severity because libraries such as scikit-learn pickle their own classes

Nothing is loaded, imported or executed, and no Python is needed. The format comes from the content, not the extension, so a pickle renamed `.safetensors` is still scanned. Large payloads are skipped without being read, a zip bomb is reported and not inflated, archive member names are never extracted, and a truncated or malformed file is reported as an incomplete scan.

Each file is listed with its format, a verdict (`DANGEROUS`, unrecognised imports, no dangerous imports found, not a pickle format, not scanned) and the offending imports. Safetensors and TFLite are reported as formats that cannot execute code. GGUF and ONNX are reported as not pickle formats. Keras `.h5` and `.keras` files are not scanned, because they can embed Python code.

"No dangerous imports found" means exactly that. The scanner can miss what it cannot parse, and the result does not say a file is safe or that the weights are trustworthy.

`--format sarif` writes one result per dangerous file, located at the file. Exit 1 when any file is dangerous and 2 on a usage error. `0security sbom generate --ai` adds a `0:risk` property to a model file in the inventory when this scan finds it dangerous.

| Argument | Required | Description |
| --- | --- | --- |
| `path` | Yes | A model file, or a folder to search for model files |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `text` | Output: text, json or sarif |

#### sbom agent-config

Check the rules, MCP and settings files AI coding tools read in a repository for hidden text, unpinned launchers, secrets and broad permissions

```text
0security sbom agent-config [options] [path]
```

```bash
0security sbom agent-config .
```

This reads `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/`, `.claude/`, `.github/` instructions, prompts and agents, `.gemini/`, `.codex/`, `.windsurf/`, `.continue/`, `.clinerules`, `.vscode/mcp.json`, `.mcp.json`, `opencode.json` and `SKILL.md` files as text. It runs nothing, calls no model and makes no network request. It works with `ZERO_ENTERPRISE` set. A file over 1 MB is skipped and listed. A symbolic link is never followed and is reported as a finding. A hard-linked file is not read.

Each finding has a rule id, a severity, the file and line, a short snippet and a fix hint. Secrets are shown as their first characters and length, never in full. The wording rule is a heuristic and is marked as one. See [Check agent files in a repository](/extensions/#check-agent-files-in-a-repository) for the rules.

`--format sarif` writes one result per finding. Import it with `0security findings import agent-config.sarif`. Exit 1 when a finding is at or above `--fail-on`, and 2 on a usage error. Without `--fail-on` the exit code is 0.

| Argument | Required | Description |
| --- | --- | --- |
| `path` | No | Folder to search, or one file (default: .) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `text` | Output: text, json or sarif (SARIF imports with `0security findings import`) |
| `-o, --output <file>` | — | Write the result to a file instead of stdout |
| `--fail-on <severity>` | — | Exit 1 when a finding is at or above this severity: critical, high, medium, low or info |
| `--allow-host <host>` | — | Host a remote MCP server may use; repeat the option or separate hosts with commas. `*.example.com` allows subdomains |

#### sbom reachability

```text
0security sbom reachability [options] <file> [folder]
```

Read JVM source-import candidates and follow the SBOM's dependency graph offline. Nothing runs or is sent over the network. Main-source and test-source evidence are kept separate. Every vulnerable-code verdict stays `unknown`: imports and package dependency edges do not prove that vulnerable methods execute, and missing imports do not prove absence of use.

```bash
0security sbom reachability sbom.cdx.json . --format json
0security sbom check sbom.cdx.json --source . --format sarif -o deps.sarif
```

`sbom check --source` attaches the same evidence to advisory results in text, JSON and SARIF. It does not suppress advisories, lower severity or change the advisory exit code. Source stays local; the advisory check still sends package URLs to OSV. Source and graph limits are reported as incomplete evidence.

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `text` | Output: text or json |

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes | CycloneDX SBOM (JSON), including the resolved dependency graph when available |
| `folder` | No | Source folder to read (default: .) |

#### sbom java-usage

List which Maven components of an SBOM your Java, Kotlin, Scala or Groovy source imports

```text
0security sbom java-usage [options] <file> [folder]
```

```bash
0security sbom java-usage sbom.cdx.json .
```

This reads your `.java`, `.kt`, `.scala` and `.groovy` files as text and lists where each Maven component of the SBOM is imported. Nothing runs and nothing is sent anywhere.

Each component is `imported`, `imported (matched by group only)` or has no import. Imports in test code are marked. An import shows where a package is named, not that a vulnerable method runs, so this is evidence and not a reachability verdict. A transitive dependency has no import of its own. A library whose classes use an unrelated package name shows no import. Add `--format json` for the full list.

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes | CycloneDX SBOM (JSON), for example from `0security sbom generate` |
| `folder` | No | Source folder to read (default: .) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `text` | Output: text or json |

### evidence

Check evidence folders that were signed with `0security findings evidence --sign`. See [Sign an evidence folder](/ci/#sign-an-evidence-folder).

```text
0security evidence
```

Subcommands: [verify](#evidence-verify).

#### evidence verify

Check offline that a folder is signed by your key and that no file was changed, added or removed. It needs the public key and no license, and it never uses the network.

```text
0security evidence verify [options] <folder>
```

```bash
0security evidence verify ./evidence --pub evidence-key.pub.pem
```

The command exits 0 when the signature and every file match, 1 when something does not, and 2 for a usage error. A valid result shows the files are unchanged since the holder of the key signed them. It does not show the findings are right.

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--pub <file>` | — | Public key (PEM) that matches the signing key (required) |
| `--json` | — | Print the result as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### findings

Browse and manage persisted findings

```text
0security findings [options]
```

Triage (`new`, `accepted`, `suppressed`) and verification are separate states. Accepting a finding records your decision; reproduction and fix verification are separate steps.

Subcommands: [list](#findings-list) · [show](#findings-show) · [update](#findings-update) · [import](#findings-import) · [fix](#findings-fix) · [burndown](#findings-burndown) · [verify](#findings-verify) · [metrics](#findings-metrics) · [rollup](#findings-rollup) · [evidence](#findings-evidence) · [export-fixes](#findings-export-fixes) · [report-draft](#findings-report-draft) · [reproduce](#findings-reproduce) · [accept](#findings-accept) · [suppress](#findings-suppress) · [reopen](#findings-reopen) · [export](#findings-export) · [keys](#findings-keys) · [upload](#findings-upload) · [issues](#findings-issues) · [reports](#findings-reports).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Filter by scan ID |
| `--severity <severity>` | — | Filter by severity: critical, high, medium, low, info |
| `--category <category>` | — | Filter by attack category |
| `--status <status>` | — | Filter by status: discovered, verified, confirmed, scored, reported, fixed, false-positive |
| `--triage <triage>` | — | Filter by triage: new, accepted, suppressed |
| `--expiring <days>` | — | Only accepted risks that expire within this many days |
| `--context <file>` | — | Business context file (JSON): order findings by what matters to you, with the reason shown. See the docs |
| `--scope <scope>` | — | in: findings not labelled out of scope; out: only those the declared scope (0security scan --scope) labelled out of scope; all (default): both, each labelled |
| `--limit <n>` | `50` | Max findings/groups to show |
| `--all` | `false` | Show raw finding rows instead of grouped fingerprints |

#### findings list

List findings from the database

```text
0security findings list [options]
```

`--scope in|out|all` filters by the label a declared scope gave. A finding labelled out of scope shows `[out of scope]` and its reason.

The list shows one line per flaw: groups that cite the same file and category at overlapping lines are merged, and the line says how many. See [finding categories](/findings/#finding-categories) for the values `--category` takes.

An accepted risk shows `accepted until <date>`. Once that date passes, the finding shows as open again. `--expiring <days>` lists the accepted risks that end within that many days.

| Option | Registered default | Description |
| --- | --- | --- |
| `--all` | — | Show raw finding rows instead of grouped fingerprints |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Filter by scan ID |
| `--severity <severity>` | — | Filter by severity: critical, high, medium, low, info |
| `--category <category>` | — | Filter by attack category |
| `--status <status>` | — | Filter by status: discovered, verified, confirmed, scored, reported, fixed, false-positive |
| `--triage <triage>` | — | Filter by triage: new, accepted, suppressed |
| `--expiring <days>` | — | Only accepted risks that expire within this many days |
| `--context <file>` | — | Business context file (JSON): order findings by what matters to you, with the reason shown. See the docs |
| `--scope <scope>` | — | in: findings not labelled out of scope; out: only those the declared scope (0security scan --scope) labelled out of scope; all (default): both, each labelled |
| `--limit <n>` | — | Max findings/groups to show |

##### Business context

Supply business context in a small operator-owned JSON file. Use `scan --business-context context.json` to steer investigation and persist a separate work-priority label. Use `findings list --context context.json` to override the labels for one list:

```bash
0security findings list --context context.json
```

```json
{
  "entries": [
    { "match": "src/payments/**", "tags": ["payments", "personal-data"], "note": "card checkout" },
    { "match": "services/admin/**", "tags": ["internal-only"] },
    { "match": "examples/**", "tags": ["non-production"] }
  ]
}
```

Each entry has a `match` and a list of `tags`. The `match` is a path or glob, such as `src/payments/**` or `services/billing`, tested against the file the finding points at. An entry with no `match` applies to every finding. A finding with no file only gets entries with no `match`. `note` is optional text that is shown with the finding.

A tag moves a finding up or down in the order, in steps of severity. The tags and their default steps are:

| Tag | Steps |
| --- | --- |
| `internet-facing` | +1 |
| `payments` | +1 |
| `personal-data` | +1 |
| `operationally-critical` | +1 |
| `internal-only` | -1 |
| `non-production` | -2 |

Steps add up, and the total is held to between -2 and +2. A medium finding in `src/payments/**` with `payments` and `personal-data` ranks with the critical ones. Set `weights` in the file to change a tag, for example `"weights": { "payments": 2 }`. A weight is a whole number from -2 to 2.

A matching finding shows `Operator business context (unverified): ranked higher (+2): payments, personal-data. card checkout`. Technical severity, CVSS, verification, counts, scope and `--fail-on` remain unchanged; no finding is hidden. The tags and notes are operator declarations, not observed deployment exposure or exploitability.

`scan --business-context context.json` passes the declarations as labelled background, orders JSON/Markdown/HTML/PDF/SARIF reports within scope groups, and stores the separate declaration with each local finding. The JSON finding and SARIF result property are named `businessContext` and include `provenance: "operator"`, repository, tags, notes, shift, work score and rationale. Later list, burndown and retained exports use the stored labels without reopening the file. The console shows the declaration separately and offers a **Business priority** sort; **Severity** still sorts technical severity. A scan's ordinary model finding saves cannot set the operator declaration field.

0 reads context only from the path explicitly passed. The file is limited to 64 KB; it is never discovered automatically in a scanned repository. Use one file per scanned repository. Stored labels carry that scan's repository label; they do not establish a global multi-repository policy. Without a stored declaration or an explicit list context, ordering remains technical severity. `scan --context` continues to mean prose background and is a separate option.

| Option | Registered default | Description |
| --- | --- | --- |
| `--all` | — | Show raw finding rows instead of grouped fingerprints |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Filter by scan ID |
| `--severity <severity>` | — | Filter by severity: critical, high, medium, low, info |
| `--category <category>` | — | Filter by attack category |
| `--status <status>` | — | Filter by status: discovered, verified, confirmed, scored, reported, fixed, false-positive |
| `--triage <triage>` | — | Filter by triage: new, accepted, suppressed |
| `--expiring <days>` | — | Only accepted risks that expire within this many days |
| `--context <file>` | — | Business context file (JSON): order findings by what matters to you, with the reason shown. See the docs |
| `--scope <scope>` | — | in: findings not labelled out of scope; out: only those the declared scope (0security scan --scope) labelled out of scope; all (default): both, each labelled |
| `--limit <n>` | — | Max findings/groups to show |

#### findings show

Show detailed information about a finding

```text
0security findings show [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### findings accept

Mark a finding family as accepted

```text
0security findings accept [options] <id>
```

```bash
0security findings accept 3f2a --reason "Fix scheduled for the next release" --expires 90d --approver "security lead"
```

An accepted risk needs a reason and an expiry. `--expires` takes a date like `2026-12-31` (it ends at the end of that day, UTC) or a number of days like `90d`. The reason is at most 500 characters. `--note` works as `--reason`.

The approver is a name you type. 0 stores it and exports it, but does not check it against any login. Each change writes one entry to the audit log (`0security config get audit`) with your system user name, the reason, the expiry and the approver.

After the expiry the finding is open again in lists, exports and the next scan. Exports show the reason, expiry and approver: JSON fields, a Markdown line, and a SARIF `suppressions` entry with `kind` external and your reason as the justification. `0security findings evidence` includes them too.

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--reason <text>` | — | Why the risk is accepted (required; --note is the same) |
| `--note <text>` | — | Alias of --reason |
| `--expires <date\|days>` | — | When the acceptance ends: 2026-12-31 or 90d (required). The finding reopens after it. |
| `--approver <name>` | — | Who approved it: a label you type, not a login |

#### findings suppress

Suppress a finding family across duplicate occurrences

```text
0security findings suppress [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--note <text>` | — | Suppression reason |
| `--approver <name>` | — | Who approved it: a label you type, not a login |

#### findings reopen

Reset a finding family back to new

```text
0security findings reopen [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--note <text>` | — | Optional triage note |

#### findings import

Import findings from another scanner's SARIF 2.1.0 file (use - for stdin). Nothing in the file is executed.

```text
0security findings import [options] [file]
```

```bash
0security findings import results.sarif
0security findings import --github acme/app
```

Each result becomes a finding that keeps the scanner's name, rule, severity, CWE and file and line. A result from a web scanner keeps the HTTP method and URL instead of a file, and any proof text. Nuclei JSON Lines (`-jsonl-export`) is read as well as SARIF. See [Use Nuclei, ZAP or Strix](/use-dynamic-scanners/). The scan it creates is marked imported and unverified, and importing the same file again changes nothing. Absolute paths become repo-relative under `--root`; paths outside it are dropped. Stop a running console on the same database first.

`--github owner/repo` imports that repository's code scanning, Dependabot and secret scanning alerts instead of a file. Give a file or `--github`, not both.

It runs `gh api` with your own `gh auth login` session, so the token never reaches 0 and the 0 GitHub connector is not used. Your repository access limits the result. `--types` picks the alert kinds, `--state` the alert state (`open`, `dismissed`, `fixed` or `all`) and `--ref` narrows code scanning to a branch. A kind that is switched off for the repository is skipped with a warning.

If a later page fails, returns invalid JSON or the 20-page limit is reached, the alerts read so far are still imported, marked incomplete, with a warning on stderr. A failed fetch makes the command exit 1. Running it again imports again when an alert changed on GitHub.

Secret alerts record the type, validity and, for the first 50 alerts, the file and line of the first location. The secret value is never requested or stored. Alert text is stripped of control characters and shortened before it is stored.

| Argument | Required | Description |
| --- | --- | --- |
| `file` | No | SARIF or Nuclei JSON Lines file, or - to read standard input |

| Option | Registered default | Description |
| --- | --- | --- |
| `--github <owner/repo>` | — | Import code scanning, Dependabot and secret scanning alerts from a GitHub repository, read with your own `gh` login (gh auth login); the 0 GitHub connector is not used |
| `--state <state>` | `open` | Filter alerts by state: open, dismissed, fixed, all |
| `--types <types>` | `all` | Comma-separated alert kinds: code-scanning, dependabot, secret-scanning, all |
| `--ref <branch>` | — | Filter code-scanning alerts by branch or git ref |
| `--tool <name>` | — | Label for the scanner, overriding the name in the file |
| `--root <dir>` | — | Folder that was scanned; absolute paths under it become repo-relative (default: the current directory) |
| `--db-path <path>` | — | Destination database; stop its running console before importing |
| `--format <format>` | `text` | Output format: text or json |

#### findings fix

Fix one finding in an isolated git work tree and open a pull request for review

```text
0security findings fix [options] <finding>
```

```bash
0security findings fix 3f2a --test "pnpm test"
```

A thread follows the `fix-finding` skill in a separate git work tree, so your checkout is never touched. It makes the smallest change it can. Then the command runs each `--test` check, commits on a branch named `0/fix-<id>` and opens a pull request, as a draft when a check fails or when you gave no `--test`; the body then says "No checks were run." Pass `--ready` to open it ready for review without checks. Running it again for the same finding updates the same pull request.

Nothing is pushed to the base branch and nothing is merged. A person reviews and merges. Use `--test` for the project's tests and, to re-run the scanner that raised the finding, its own command (for example `foxguard .`). The command edits files on this machine, so it needs the local console and rejects `--computer` and `--engine-url`.

Without `--sandbox`, each `--test` command runs on this machine, in the work tree, with your privileges and your environment. A test command can do anything you can. To run the checks in a container instead, see [verified fixes](/findings/#verified-fixes).

Exit codes:

- 0: a change was committed and no `--test` check failed
- 1: no change, a failed check or a failed thread
- 2: usage error
- 3: stopped at the budget or time limit

Exit code 0 with no `--test` means nothing was checked. The pull request is then a draft, unless you passed `--ready` or your policy sets the draft rule to `never`. A draft pull request means the change is not verified, and a pull request opened without checks is not verified even when it is ready. Without a pull request (`--no-pr`), the same exit codes apply.

A fix policy (approved libraries, forbidden patterns, rules, notes; JSON or YAML) can steer the thread. It comes only from `--policy <file>` or from your own `~/.0/fix-policy.json|yaml|yml`.

A policy file inside the repository being fixed is not read unless you pass `--repo-policy`, because whoever controls the repository would then control the prompt. `--repo-policy` prints a warning, and a file that links outside the repository is refused. The policy is lower-priority guidance: the rules to never commit, push or merge override it.

| Argument | Required | Description |
| --- | --- | --- |
| `finding` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--host <host>` | — | Code host: github, bitbucket-cloud or bitbucket-dc (inferred from origin) |
| `--bitbucket-url <url>` | — | Bitbucket Data Center HTTPS base URL, including any context path (or BITBUCKET_URL) |
| `--repo <dir>` | — | Git repository the finding is in (default: the current directory) |
| `--base <branch>` | — | Branch to start from and open the pull request against (default: the remote's default branch) |
| `--test <command>` | — | Check to run after the change; repeat for several. A failing check makes the pull request a draft |
| `--ready` | — | Open the pull request ready for review even when no --test ran. Without it, a pull request with no checks is a draft |
| `--sandbox <mode>` | — | Run the --test commands in a container instead of on this machine (docker) Choices: docker. |
| `--sandbox-profile <profile>` | — | Use the pinned Maven/JDK 21 verifier: online dependency setup then offline verify (java) |
| `--sandbox-maven-settings <file>` | — | Owner-only short-lived Maven credentials outside the repository; read-only mount for online setup only; setup output withheld |
| `--sandbox-image <image>` | — | Image for --sandbox docker, for example maven:3-eclipse-temurin-21. It must hold the tools and dependencies the tests need |
| `--sandbox-network` | — | Give the sandbox network access (to download dependencies). Off by default |
| `--sandbox-setup <command>` | — | With --sandbox docker: run this once with the network on to download dependencies (for example mvn -q test), then run the --test checks with the network off; repeat for several |
| `--policy <file>` | — | Policy file (.json or .yaml) of approved libraries and fix rules; any path you name, relative to the current directory. Default: ~/.0/fix-policy.json\|yaml\|yml |
| `--ticket <key>` | — | Ticket key such as SEC-123 for the {ticket} placeholder in your policy's pull request settings |
| `--repo-policy` | — | Also read fix-policy.* or .zero/fix-policy.* from the repository being fixed (untrusted content; off by default) |
| `--no-pr` | — | Commit on the fix branch but do not push or open a pull request |
| `--budget <usd>` | `3` | Stop when the estimated spend reaches this many USD |
| `--model <model>` | — | Model for the fix thread (default: gpt-6-luna) |
| `--timeout <seconds>` | `1800` | Maximum seconds to wait for the fix |
| `--format <format>` | — | Output: text or json Choices: text, json. |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

#### Pull request conventions

Your policy file can set how fix pull requests look. Add a `pullRequest` object to `~/.0/fix-policy.json` (or the file you pass with `--policy`):

```json
{
  "pullRequest": {
    "titleTemplate": "SEC-142 {severity}: {title}",
    "commitMessageTemplate": "SEC-142 fix {id}: {title}",
    "branchPrefix": "sec/fix-",
    "labels": ["security", "needs review"],
    "draft": "on-failure",
    "bodyFooter": "Tracked in SEC-142.",
    "reviewers": ["alice", "acme/appsec"]
  }
}
```

Templates take the placeholders `{id}`, `{title}`, `{severity}`, `{category}`, `{path}` and `{ticket}`. Nothing else is evaluated, and an unknown placeholder is an error. Each value is flattened to one line, stripped of mentions, issue references and markup, and the result is cut to 200 characters.

To put a ticket key in the branch, title or commit, use `{ticket}` and pass the key with `--ticket`. A key looks like `SEC-123`.

```json
{ "pullRequest": { "branchPrefix": "sec/{ticket}/", "titleTemplate": "{ticket} {title}" } }
```

```bash
0security findings fix 3f2a --ticket SEC-123
```

The same key gives the same branch, so a second run updates the same pull request. If a setting uses `{ticket}` and you pass no `--ticket`, the run stops before it changes anything. `findings burndown` takes `--ticket` too and uses one key for every fix in the run.

To lay out the pull request body, set `bodyTemplate`. It is Markdown with these parts that 0 fills in: `{finding}`, `{details}`, `{checks}` and `{summary}`. It also takes the placeholders above. A part you leave out is left out of the body. Your own text is kept line by line, with HTML escaped and mentions and issue numbers defused. `bodyFooter` is still added at the end.

```json
{ "pullRequest": { "bodyTemplate": "Ticket: {ticket}\n\n{finding}\n\n{checks}\n\n## Review checklist\n- [ ] Tests cover the change\n- [ ] No new dependency\n\n{summary}" } }
```

0 does not read the pull request template of the repository, because that file comes from the repository you fix.

To ask the code owners for review, set `reviewersFromCodeowners` to `true`. 0 reads `.github/CODEOWNERS`, `CODEOWNERS` or `docs/CODEOWNERS` from the base branch as committed, finds the last rule that matches the finding's file, and requests those owners next to `reviewers`. Only `@user` and `@org/team` owners count. E-mail addresses are skipped, and at most 10 reviewers are requested. If no file or rule applies, 0 says so and opens the pull request without them. A section header, a negated pattern and a pattern with brackets are not supported and are skipped.

`draft` is `always`, `on-failure` (the default) or `never`. With `never`, a pull request is ready for review even when a check fails or none ran. `branchPrefix` is followed by a short hash of the finding, so a second run still updates the same pull request. Reviewers are users or `org/team`.

Labels that do not exist are created. If the host refuses, 0 prints a warning and skips that label. A refused reviewer is a warning too, because the pull request is already open. Without a `pullRequest` object nothing changes.

The settings are read only from your own policy file. A policy file inside the repository (`--repo-policy`) cannot set them, because the repository is untrusted. `0security findings evidence` lists fix branches by the default `0/fix-` prefix, so branches with another prefix are not listed there.

| Argument | Required | Description |
| --- | --- | --- |
| `finding` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--repo <dir>` | — | Git repository the finding is in (default: the current directory) |
| `--base <branch>` | — | Branch to start from and open the pull request against (default: the remote's default branch) |
| `--test <command>` | — | Check to run after the change; repeat for several. A failing check makes the pull request a draft |
| `--policy <file>` | — | Policy file (.json or .yaml) of approved libraries and fix rules; any path you name, relative to the current directory. Default: ~/.0/fix-policy.json\|yaml\|yml |
| `--repo-policy` | — | Also read fix-policy.* or .zero/fix-policy.* from the repository being fixed (untrusted content; off by default) |
| `--no-pr` | — | Commit on the fix branch but do not push or open a pull request |
| `--budget <usd>` | `3` | Stop when the estimated spend reaches this many USD |
| `--model <model>` | — | Model for the fix thread (default: gpt-6-luna) |
| `--timeout <seconds>` | `1800` | Maximum seconds to wait for the fix |
| `--format <format>` | — | Output: text or json Choices: text, json. |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

#### findings export-fixes

Report what happened to the fixes 0 proposed: counts, pull requests, checks, cost and, on request, merged or closed

```text
0security findings export-fixes [options]
```

```bash
0security findings export-fixes --check-merged -o ./fix-report
```

The report reads `~/.0/burndown.json`. Both `0security findings burndown` and `0security findings fix` record each fix there, on the machine that ran them. A fix made before this release is not in the file.

It writes `fix-outcomes.md` and `fix-outcomes.json` to the folder you pass with `-o`, or prints one to the terminal. Each fix lists the finding id, title, severity, branch, pull request link, whether the checks passed, cost and when it was recorded. The summary counts fixes attempted, proposed, pull requests opened, drafts, checks passed and failed.

Without `--check-merged` nothing leaves your machine, and merged, closed and edited are shown as not measured. With it, 0 asks GitHub about each pull request, one request each, through `gh`. The summary then counts merged, closed without merging and still open, and gives an acceptance rate: merged divided by merged plus closed. A pull request counts as edited when it has more than one commit. That is an estimate, because a person may also have rebased it.

Evidence and proof-of-concept text are never included. Titles are flattened and stripped of mentions, issue references and markup in the Markdown.

A repository is the workspace. The report gives the summary once for everything and once per repository, so you can send each team its own figures. In the summary, accepted means merged and rejected means closed without merging.

The JSON has the schema `0.fix-outcomes.v1`. A field the run could not know is `null`.

| Field | Meaning |
| --- | --- |
| `generatedAt`, `since`, `repo`, `checkedMerged` | When the report was made, the filters you passed, and whether the code host was asked |
| `summary` | `attempted`, `proposed`, `pullRequestsOpened`, `draft`, `checksPassed`, `checksFailed`, `costUsd`, `merged`, `closedWithoutMerge`, `stillOpen`, `edited`, `unknown`, `acceptanceRate` |
| `workspaces` | One entry per repository: `repo` and the same `summary` |
| `fixes` | One entry per fix: `finding`, `title`, `severity`, `category`, `repo`, `branch`, `pullRequestUrl`, `result`, `draft`, `checksPassing`, `costUsd`, `recordedAt`, `pullRequest` |
| `fixes[].pullRequest` | With `--check-merged`: `state` (merged, closed, open or unknown), `draft`, `commits`, `editedAfterOpening` |

| Option | Registered default | Description |
| --- | --- | --- |
| `--repo <dir>` | — | Only fixes recorded for this git repository (default: all) |
| `--since <date>` | — | Only fixes recorded on or after this date, like 2026-01-31 |
| `--check-merged` | — | Ask the code host whether each pull request was merged, closed or edited (one request each) |
| `-o, --output <dir>` | — | Write fix-outcomes.md and fix-outcomes.json into this folder instead of printing |
| `--format <format>` | `markdown` | Printed output: markdown or json Choices: markdown, json. |

#### findings report-draft

Write a draft early warning, notification or final report about one finding (Markdown; nothing is sent)

```text
0security findings report-draft [options] <finding>
```

Use this when a manufacturer has to tell the authorities about an actively exploited vulnerability (Article 14 of the Cyber Resilience Act, Regulation (EU) 2024/2847). Confirm the current requirements and deadlines yourself.

The text is built without a model. Each field is copied from the finding record (title, severity, category, location, status, triage state, creation time, and the attacker-impact sentence when someone assessed it), taken from a fact you pass with a flag or in a `--facts` JSON file, or left as `[to be completed by the manufacturer: ...]`. Nothing says the vulnerability is exploited, that users are affected or that a fix exists unless you supplied it.

`--evidence-file` lists a file's name, size and SHA-256 and never copies its content. `--stage all` writes the three stages one after another. The finding can be a full id, an id prefix, or `fp:` plus a fingerprint prefix from `0security findings list`.

The draft says that a person must review it and submit it through the authority's own channel. 0 submits nothing.

| Argument | Required | Description |
| --- | --- | --- |
| `finding` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--stage <stage>` **required** | — | early-warning, notification, final or all |
| `--product <name>` | — | Product name |
| `--manufacturer <name>` | — | Legal name of the manufacturer |
| `--contact <text>` | — | Who submits the report and how to reach them |
| `--affected-versions <text>` | — | Affected product versions |
| `--exploited-since <when>` | — | When exploitation is known to have started |
| `--exploitation-evidence <text>` | — | How you know it is being exploited |
| `--malicious-actor <text>` | — | Suspected malicious act or actor, if known |
| `--member-states <text>` | — | Member States where the product is available |
| `--mitigation <text>` | — | Mitigation taken or recommended |
| `--user-measures <text>` | — | What users can do now |
| `--corrective-measure <text>` | — | The fix or update available to users |
| `--corrective-measure-date <when>` | — | When the corrective measure became available |
| `--evidence-file <file>` | — | Name and SHA-256 of a supporting file (its content is never copied); repeat for several |
| `--facts <file>` | — | JSON file with the same facts (camelCase keys, for example affectedVersions); flags win |
| `-o, --output <file>` | — | Write to a file instead of stdout |
| `--db-path <path>` | — | Path to SQLite database |

#### findings evidence

Write one folder of findings, SARIF, SBOM and fix branches, with a README that says what it does and does not show

```text
0security findings evidence [options] <folder>
```

The folder holds:

- `README.md`
- `manifest.json`: version, date, commit, models and the SHA-256 of each file
- `findings.json` and `findings.md`: severity, status, triage state and note, accepted-risk expiry and approver, timestamps, location
- `findings.sarif`
- `sbom.cdx.json`, from the lockfiles in `--repo`
- `fixes.md`: the fix branches that exist in `--repo`
- `advisories.json` from the public OSV database, only with `--check-advisories`
- `evidence.dsse.json`, only with `--sign`: your signature over the SHA-256 of every other file

`--sign <key>` signs the folder with your own Ed25519 private key (PEM). It needs an enterprise license with `evidence-signing`. See [Sign an evidence folder](/ci/#sign-an-evidence-folder). That lookup is the only network use. Evidence and proof-of-concept bodies are left out unless you pass `--include-evidence`. With it, the folder can hold working exploit details.

The command writes only those file names. It refuses a folder that holds other files, a symbolic link, or a folder inside the repository, and it removes a file of its own from an earlier run that it did not write this time.

The README makes no claim of compliance. The folder is evidence for your own records, not a conformity assessment.

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--repo <folder>` | — | Repository the findings are about: adds the SBOM, the commit and the fix branches |
| `--check-advisories` | — | Look the SBOM components up in the public OSV database (the only network use) |
| `--include-evidence` | — | Also write evidence and proof-of-concept bodies (can contain working exploit details) |
| `--sign <key>` | — | Sign the folder with your Ed25519 private key (PEM file). Needs an enterprise license |
| `--scan <id>` | — | Only the findings of this scan |
| `--name <name>` | — | Name of the application the SBOM describes (default: the repository folder's name) |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print the result as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |
#### findings burndown

Work through open findings in batches: one fix branch and pull request each, then a report

```text
0security findings burndown [options]
```

Burndown selects open findings (not fixed, false positive, accepted or suppressed; one per fingerprint, worst severity first) and runs each through the same flow as [findings fix](#findings-fix): its own git work tree, a branch named `0/fix-<id>`, your `--test` checks, and one pull request, a draft when a check fails. Nothing is pushed to the base branch and nothing is merged.

Filter with `--severity`, `--category`, `--tool` (or `--source`), `--scan` and `--fingerprint`. Size a batch with `--limit`.

`--concurrency` (1 to 4) runs fixes side by side, each in its own work tree. `--budget` is the total for the run and `--per-fix` caps one fix. The cap shrinks to what is left of the total, and no fix starts once it is spent.

The run stops when `--max-consecutive-failures` fixes fail in a row, or when the share of failures goes above `--max-failure-rate` after `--min-attempts` fixes. A fix fails when the thread changes nothing, errors, or a check fails.

Run the same command again to continue: findings that already have a pull request (or, with `--no-pr`, a committed branch) are skipped. `--retry` works on them again. `--dry-run` shows the plan and changes nothing.

The report lists what was proposed, committed, opened or updated as pull requests (with links), which checks passed, drafts because a check failed, skipped findings with the reason, cost and time. `--format json` prints it as JSON. Each run also adds a row of metrics (findings attempted, fixes proposed, check result, cost, duration) that `--history` lists.

Burndown applies the same [pull request conventions](#pull-request-conventions) as `findings fix`. Pass a policy with `--policy <file>`, or keep one at `~/.0/fix-policy.json`. Use [findings export-fixes](#findings-export-fixes) to report the outcomes.

Burndown edits files on this machine, so it needs the local console and rejects `--computer` and `--engine-url`.

Exit codes:

- 0: every attempted fix is verified, or there was nothing to do
- 1: a fix failed, or the run stopped on failures
- 2: usage error
- 3: the total budget ran out

| Option | Registered default | Description |
| --- | --- | --- |
| `--severity <levels>` | — | Only these severities (critical, high, medium, low, info; comma-separated) |
| `--category <category>` | — | Only this category |
| `--tool <name>` | — | Only findings reported by this tool |
| `--source <name>` | — | Alias of --tool |
| `--scan <id>` | — | Only findings of this scan (id prefix) |
| `--fingerprint <prefix>` | — | Only findings whose fingerprint or id starts with this |
| `--limit <n>` | — | Attempt at most this many findings in this run; the next run continues with the rest |
| `--repo <dir>` | — | Git repository the findings are in (default: the current directory) |
| `--base <branch>` | — | Branch to start from and open pull requests against (default: the remote's default branch) |
| `--test <command>` | — | Check to run after each change; repeat for several. A failing check makes the pull request a draft |
| `--ready` | — | Open pull requests ready for review even when no --test ran. Without it, a pull request with no checks is a draft |
| `--policy <file>` | — | Policy file (.json or .yaml) with fix rules and pull request conventions; any path you name. Default: ~/.0/fix-policy.json\|yaml\|yml |
| `--ticket <key>` | — | Ticket key such as SEC-123 for the {ticket} placeholder in your policy's pull request settings |
| `--no-pr` | — | Commit on the fix branches but do not push or open pull requests |
| `--concurrency <n>` | `1` | Fixes at the same time, each in its own work tree (1 to 4) |
| `--budget <usd>` | `10` | Total spend for this run in USD; no new fix starts once it is used |
| `--per-fix <usd>` | `3` | Spend cap for one fix, in USD |
| `--max-consecutive-failures <n>` | `3` | Stop after this many failed fixes in a row |
| `--max-failure-rate <fraction>` | `0.5` | Stop when the share of failed fixes is above this (after --min-attempts) |
| `--min-attempts <n>` | `4` | Fixes to attempt before the failure share can stop the run |
| `--model <model>` | — | Model for the fix threads (default: gpt-6-luna) |
| `--timeout <seconds>` | `1800` | Maximum seconds to wait for one fix |
| `--retry` | — | Work again on findings that already have a fix branch or pull request |
| `--dry-run` | — | List what would be attempted and skipped; change nothing |
| `--history` | — | List the metrics row of each earlier run and exit |
| `--format <format>` | — | Output: text or json Choices: text, json. |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

#### findings metrics

Show what scan, fix and verify runs cost and produced: cost per proposed fix and the share that passed their checks

```text
0security findings metrics [options]
```

Every `0security scan`, `0security findings fix` and `0security findings verify` run adds one line to `~/.0/metrics.ndjson`. The line holds the command, model, budget, cost, duration, counts, tokens when the thread reports them, and finding ids. It holds no finding text, file paths or credentials. Only you can read the file. It moves to `metrics.ndjson.1` at 1 MB, so about two files of history remain. `0security findings burndown` runs one fix per finding, so each of its fixes adds a line.

The summary lists runs, cost, average time and counts per command. A proposed fix is a committed change. The share verified is the proposed fixes whose checks all passed. Cost per proposed fix is the cost of all fix runs divided by the fixes they proposed. The run does not see the CI result of the pull request it opens, so CI is recorded as unknown.

`--since` takes hours, days or weeks (`36h`, `7d`, `2w`) or a date. `--format json` prints the summary as JSON.

`--by week` shows one row per week (starting Monday, UTC), and `--by model` one row per model. Cost per fix and the share verified in these rows come from fix runs only. Add `--format csv` to export the rows.

| Option | Registered default | Description |
| --- | --- | --- |
| `--refresh-host` | — | Read current PR lifecycle and CI for up to 20 recorded PRs (requires --repo; no host writes) |
| `--repo <checkout>` | — | Explicit local checkout for --refresh-host |
| `--bitbucket-url <url>` | — | Bitbucket Data Center server base for the explicit checkout |
| `--since <when>` | — | Only runs since then: 36h, 7d, 2w or a date such as 2026-11-01 |
| `--command <name>` | — | Only this command: scan, fix, verify, sentinel |
| `--by <group>` | — | One row per command, week (Monday start), model, Sentinel or trigger Choices: command, week, model, sentinel, trigger. |
| `--format <format>` | — | Output: text, json, or csv (with --by) Choices: text, json, csv. |

#### findings rollup

Count open findings across repositories by severity, category, age and owner, from export files and findings databases

```text
0security findings rollup [options] [inputs...]
```

```bash
0security findings rollup --export api.json --repository api
0security findings rollup api.json web.json --format html -o rollup.html
```

Run it once per repository with `--export` to write a rollup export. Put the files in one place, then run it again with the files as inputs. An input is an export file, a SARIF file or a findings database. With no input, it reads the databases on this machine. It reads local files only and sends nothing.

How it counts:

- Each input export is a complete snapshot of the repositories it names. The latest `exportedAt` wins per repository in the current view, even if a finding’s `lastSeen` did not change. Within one timestamp a flaw counts once per repository by fingerprint; its newest row sets state and its oldest first-seen sets age. The same flaw remains present in each historical snapshot. The same fingerprint in two repositories counts twice.
- The open count leaves out findings that are fixed, marked false positive, accepted or suppressed. An acceptance past its expiry counts as open. The output shows how many were left out and why.
- Age is the time since the finding was first seen: under 7 days, 7 to 30, 30 to 90, over 90.
- The owner is the finding's assignee. If it has none, the owner comes from the `--owners` file. Otherwise it counts as unassigned. 0 does not read CODEOWNERS, because that file comes from the repository you scan.
- The repository name is the folder name of the scan target, or the name you pass with `--repository`. An export never contains your directory paths or finding evidence.

The `--owners` file is a JSON object that maps a repository name to an owner or team:

```json
{ "api": "payments", "web": "growth" }
```

An export has the schema `0.findings-rollup.v1`: `schema`, `exportedAt` and `findings`. Each finding has `repository`, `fingerprint`, `title`, `severity`, `category`, `status`, `triage` (new, accepted or suppressed), `owner` (a string or null), `firstSeen` and `lastSeen` (ISO times). It can also have `team` and `tier`; files without them still read. To bring in another scanner's results first, use [findings import](#findings-import).

To see what changed, keep the export of each run and compare a later rollup with an earlier export:

```bash
0security findings rollup api.json web.json --since last-month.json
```

The trend shows opened, fixed and net findings per severity and per repository. A finding is opened if it is open now and was not open then. It is fixed if it was open then and is not open now. That includes findings now marked false positive, accepted or suppressed, and findings gone from the file. Net is opened minus fixed. A repository that is in only one of the two files is listed, not counted as fixed. `--since` takes a rollup export, not a database.

To group by team and tier, pass a labels file. It is JSON or YAML and maps a repository name or glob to a team, a tier or both:

```yaml
api: { team: payments, tier: 1 }
"pay-*": { team: payments, tier: 2 }
"path:src/vault/**": { team: security }
```

For each of team and tier, the most specific match wins: a `path:` rule, then an exact repository name, then the repository glob with the most literal characters. A `path:` rule applies only to findings read from a SARIF file, because only those have a file path. A label from the file replaces a label stored in an export. A finding with no match counts as unlabelled. 0 reads only the file you name, never labels from a scanned repository. Exports keep team and tier but not file paths.

A SARIF file is read with the same limits as [findings import](#findings-import), including the credential scrubbing, and nothing goes into the findings database. The repository is the `--repository` name, else the repository in the SARIF file, else the file name. SARIF has no first-seen time, so the file's modified time sets the age. Results with an active suppression are skipped.

For dated source snapshots, use `--history` in addition to the comparison and label options above:

```bash
0security findings rollup api-2026-11-01.json web-2026-11-01.json --history history.json
0security findings rollup history.json api-2026-11-25.json --history history-next.json --format json -o report.json
0security findings rollup history-next.json --format csv -o dashboard-counts.csv
```

The archive schema is `0.findings-rollup.history.v1`: `snapshots` contains v1 exports with each input's basename as `source`. Captured timestamps, states and repository identity are retained; absolute input paths and evidence are not. An optional `repositories` array in a v1 export records repositories with zero findings, so a newer clean snapshot can replace older findings. Supply `--repository` when exporting an empty database to preserve its identity.

The JSON report keeps the `--since` comparison in `trend` and adds a chronological `snapshotTrend` array, snapshot provenance and current per-repository `observations`. Each repository's latest `exportedAt` supplies its current rows; different repositories can have different observation dates. Each `snapshotTrend` point lists only the repositories actually observed at that timestamp. A change in observed coverage does not establish that findings were fixed. `--export` writes a current consolidated snapshot; `--history` retains the original observation times.

CSV is a stable long-form table: `schema,snapshot_at,scope,dimension,label,count,repositories,sources`. `scope=current` means the view assembled from the latest snapshot per repository; `scope=snapshot` means an actual captured timestamp. The final two columns contain JSON arrays. These JSON/CSV exports do not establish a remote dashboard connection. Verify DefectDojo or Dependency-Track importers separately using their supported scanner formats.


| Argument | Required | Description |
| --- | --- | --- |
| `inputs` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--export <file>` | — | Also write these findings as a rollup export file that another rollup can read |
| `--history <file>` | — | Write a reusable dated snapshot archive, preserving the input timestamps and provenance |
| `--owners <file>` | — | JSON file mapping repository names to owners, used when a finding has no assignee |
| `--labels <file>` | — | JSON or YAML file mapping repository names or globs (or path: globs) to a team and tier, shown as extra breakdowns |
| `--since <file>` | — | An earlier rollup export to compare with: shows findings opened and fixed since then |
| `--repository <name>` | — | Repository name for findings read from a database or a SARIF file (default: the scan target's folder name, or the SARIF's repository) |
| `--format <format>` | — | Output: text, json, html or csv Choices: text, json, html, csv. |
| `-o, --output <file>` | — | Write the rollup to a file instead of stdout |

#### findings reproduce

Experimental: run a finding's proposed steps against a local copy of the app in a container with the network off, and record the result

```text
0security findings reproduce [options] <id>
```

Reproduce replays a finding's proposed request against your app and checks whether a canary file came back. It runs the committed tree of `--folder` (default: the current directory) in a container started from `--image`, which must be pinned by digest and contain node. Uncommitted changes are not included.

The container has no network except its own loopback. Its root file system is read-only. It is capped at 128 processes, 512 MB of memory and one CPU, and a run stops after two minutes. The app runs in `/sandbox/app`. That folder and its parent `/sandbox` are one 256 MB in-memory file system, and `/tmp` is a separate 64 MB one. Programs cannot be run directly from either one, so use a start command like `node server.js`. An app that needs to run a binary from its folder does not start, and the run reports that. Native add-ons are not tested. Every container runtime enforces these size caps. The harness starts the app and waits until it answers. Then it plants a fresh canary file with a random name and content in the app folder and in `/sandbox`, and replays the finding's request with the file name swapped for the canary. The canary does not exist before that, and its token is not in the command or the app's environment. The harness never contacts a live URL. A second request without the traversal checks that the app does not serve the canary anyway.

The start command is `node server.js` unless you pass `--start`. It comes from you. The repository is untrusted, so its scripts and configuration are never read as instructions. Only path traversal on an HTTP GET route is supported. Other findings, encoded payloads and POST requests give an inconclusive result.

The result is stored next to the finding with the commit, the image digest, a hash of the app files, the canary, the times and a redacted log tail. [findings show](#findings-show) prints it. Severity, status and triage do not change. An error result is printed but never stored over an earlier result.

Reproduced means the app as run returned the canary for this request. It is an observation of the running app, not a statement about the code. An app built to lie can fake it by reading the planted file when it sees the request, so read the code before you trust a result from an app you do not trust.

Not reproduced does not mean safe. It means this one request did not reach the canary on this commit. The app may need other input, state or a different route.

A run that is not in a container is marked unisolated and is never reproduced.

Exit codes:

- 0: reproduced or not reproduced.
- 1: inconclusive or error.
- 2: bad usage.

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--image <image>` **required** | — | Container image pinned by digest, with node in it, like node:24-bookworm-slim@sha256:&lt;64 hex digits&gt; |
| `--start <command>` | — | Command that starts the app inside the container (default: node server.js). It comes from you, never from the repository. |
| `--allow-unbounded-storage` | — | Run even when the container runtime cannot cap writable storage. Without this the run is refused. The result records that storage was unbounded. |
| `--folder <path>` | — | Git repository holding the app (default: current directory) |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### findings verify

Experimental: re-check findings with a fresh thread each and record a verdict next to them

```text
0security findings verify [options] [finding...]
```

Verify re-checks findings the way a second reviewer would. Each finding gets its own thread, or with `--batch` a few findings of one file share one. The thread gets only the finding's title, location, category, description and claimed impact, never the scan that produced it. It follows the experimental `verify-finding` skill: it reads the code, traces the input from an entry point to the sink, looks for a control, and builds a concrete attack or says it cannot. It answers true-positive, false-positive, fixed, uncertain or duplicate (a duplicate is only found inside a batch) with reasoning that cites `path:line`, and an advisory severity.

Pass the folder that was scanned with `--folder` (default: the current directory). A finding whose file is not in that folder is skipped with a reason. Name findings by id or id prefix, or select them with `--severity`, `--category` and `--tool`. Findings that are suppressed, fixed or marked false positive are skipped, and so are findings that already have a verdict unless you pass `--force`. `--limit` caps a run; the next run continues with the rest.

The verdict is stored next to the finding by its id. [findings list](#findings-list) and [findings show](#findings-show) print it, for example `verified: likely false positive`. Severity and status do not change, and the advisory severity is kept apart from the finding's own. A thread that returns no verdict for a finding is recorded as uncertain with the reason `no verdict returned`. A thread that fails to run stores nothing, so the next run tries it again.

`--apply` never suppresses a critical or high finding. It suppresses a lower-severity finding only when the verdict is false-positive and it names a control at `path:line` that exists in the folder and the reasoning cites a `path:line` too. The suppression note starts with `False positive (model-verified):` and `0security findings reopen` undoes it. Without `--apply` no status changes.

`--budget` is the total for the run and `--per-finding` caps one finding. `--concurrency` (1 to 3) runs threads side by side. The run stops when `--max-consecutive-failures` threads in a row return no verdict, or when the budget is spent. `--dry-run` lists what would be checked. `--format json` prints the report with counts per verdict, the reasoning, the cost and what `--apply` did.

Verify reads files on this machine, so it needs the local console and rejects `--computer` and `--engine-url`.

Exit codes:

- 0: done
- 1: a check returned no verdict, or the run stopped on failures
- 2: usage error
- 3: the total budget ran out

| Option | Registered default | Description |
| --- | --- | --- |
| `--folder <dir>` | — | The folder that was scanned; the threads read the code there (default: the current directory) |
| `--severity <levels>` | — | Only these severities (critical, high, medium, low, info; comma-separated) |
| `--category <category>` | — | Only this category |
| `--tool <name>` | — | Only findings reported by this tool |
| `--scan <id>` | — | Only findings of this scan (id prefix) |
| `--limit <n>` | — | Check at most this many findings in this run; the next run continues with the rest |
| `--force` | — | Check findings again that already have a verdict |
| `--apply` | — | Suppress findings called false-positive when the verdict cites a control at path:line (default: never change a status) |
| `--batch <n>` | `1` | Findings in one file that share a thread (1 to 5) |
| `--concurrency <n>` | `1` | Threads at the same time (1 to 3) |
| `--budget <usd>` | `2` | Total spend for this run in USD; no new thread starts once it is used |
| `--per-finding <usd>` | `0.3` | Spend cap for one finding, in USD |
| `--max-consecutive-failures <n>` | `3` | Stop after this many checks in a row that return no verdict |
| `--model <model>` | — | Model for the threads (default: gpt-6-luna) |
| `--timeout <seconds>` | `600` | Maximum seconds to wait for one thread |
| `--dry-run` | — | List what would be checked and skipped; change nothing |
| `--format <format>` | — | Output: text or json Choices: text, json. |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |

| Argument | Required | Description |
| --- | --- | --- |
| `finding` | No |  |

#### findings upload

Upload findings to GitHub code scanning (SARIF), to Bitbucket Code Insights (scan JSON or SARIF) or to a shared findings server (SARIF or scan JSON)

```text
0security findings upload [options] <file>
```

Run the scan in a pull request check, then upload the result:

```bash
0security scan . --diff origin/main --format sarif -o scan.sarif
0security findings upload scan.sarif
```

The repository, commit and ref come from the clone (`GITHUB_SHA` and `GITHUB_REF` in Actions). The file is compressed, uploaded with `gh` and checked until GitHub has processed it; a refused file is reported with GitHub's reason. GitHub matches alerts by fingerprint, so an upload for a later commit updates them. `gh` needs permission to write security events (`security-events: write` in Actions).

With `--to bitbucket-cloud` or `--to bitbucket-dc` the findings go to Bitbucket Code Insights instead. Upload the file from `0security scan --format json`, which carries the agent's verdict, rationale and fix guidance. With `BITBUCKET_TOKEN` set the report and its annotations are sent; without it the payload is printed. See [Bitbucket, Jenkins and Azure Pipelines](/ci/#bitbucket-jenkins-and-azure-pipelines).

With `--to` set to an https URL, the findings go to your own shared findings server. Set `ZERO_FINDINGS_API_KEY` to a write key from `0security findings keys create <name> --scope write`. Name the repository with `--repo owner/name` (the clone's origin is used when you omit it) and a CI job or machine with `--source`. This needs an enterprise license on the server. See [Collect findings from many repositories](/server-mode/#collect-findings-from-many-repositories).

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes | SARIF 2.1.0 file from `0security scan --format sarif -o scan.sarif`; for Bitbucket also `0security scan --format json -o scan.json` |

| Option | Registered default | Description |
| --- | --- | --- |
| `--to <target>` | `github` | github (default), bitbucket-cloud, bitbucket-dc, or the https URL of a shared findings server (key from ZERO_FINDINGS_API_KEY) |
| `--source <label>` | — | Shared findings server: name of this CI job or machine (default: the key's name) |
| `--url <url>` | — | Bitbucket Data Center base URL (default: BITBUCKET_URL) |
| `--report-id <id>` | `0-security` | Bitbucket report id or key |
| `--print` | — | Bitbucket: print the report and annotation payload instead of posting it (also the behaviour without BITBUCKET_TOKEN) |
| `--allow-insecure-http` | — | Bitbucket and shared findings server: allow sending the token or key to an http:// URL that is not on this machine (default: refuse) |
| `--repo <owner/name>` | — | Repository (default: the current clone's); Bitbucket: workspace/repo or PROJECT/repo |
| `--commit <sha>` | — | Commit the results are for (default: HEAD, or GITHUB_SHA in Actions) |
| `--ref <ref>` | — | refs/heads/&lt;branch&gt; or refs/pull/&lt;n&gt;/merge (default: the current branch, or GITHUB_REF in Actions) |
| `--tool <name>` | — | Name the tool shown in GitHub |
| `--include-out-of-scope` | — | Also send findings the declared scope (0security scan --scope) labelled out of scope; they are skipped by default |
| `--no-wait` | — | Return when GitHub has accepted the upload instead of waiting for it to be processed |
| `--format <format>` | `text` | Output: text or json |

#### findings issues

Mirror findings into GitHub Issues, one issue per finding, kept in sync without duplicates

```text
0security findings issues [options]
```

```bash
0security findings issues --repo acme/app --dry-run
0security findings issues --repo acme/app --min-severity high --max 10
```

Run `--dry-run` first. It prints what would be created, updated, closed or reopened and changes nothing.

Each finding family gets one issue. A later run finds it through a hidden `<!-- 0-finding:<key> -->` marker in the body (the key is the finding's fingerprint), so running it again never duplicates. Open findings at or above `--min-severity` (default `medium`) get an issue. An issue is updated when the finding's title, severity or location changes, closed with a comment when the finding is suppressed, accepted, fixed or marked a false positive, and reopened if it comes back.

0 creates the `security` and `severity:<level>` labels when they are missing, and warns and carries on if it cannot. It manages only issues that carry the `security` label (applying it needs triage rights). If you remove the label from an issue, that issue is detached and a new one is created for the finding.

`--max` (default 25) caps the changes in one run and `--delay` (default 1000 ms) spaces them out for GitHub's rate limits. Run again to continue.

The issue text holds only the title, severity, category, location (`path:line`), the attacker-impact sentence, the status and a hint for finding the details locally. Evidence, requests, responses and proof-of-concept bodies are never copied, because they can quote code or secrets. Report text has no `@mentions`, no `#123` references, no HTML and no links.

`gh` needs permission to write issues (`issues: write` in Actions). Without `--repo`, the repository comes from the clone.

| Option | Registered default | Description |
| --- | --- | --- |
| `--repo <owner/name>` | — | Repository (default: the current clone's) |
| `--min-severity <severity>` | `medium` | Open issues only for findings at or above this: critical, high, medium, low or info |
| `--max <n>` | `25` | Most issues to create, update, close or reopen in one run |
| `--delay <ms>` | `1000` | Wait this long between changes to respect rate limits |
| `--dry-run` | — | Print what would change and change nothing |
| `--include-out-of-scope` | — | Also open issues for findings the declared scope (0security scan --scope) labelled out of scope; they are skipped by default |
| `--db-path <path>` | — | Path to SQLite database (default: the shared database and every scan's) |
| `--format <format>` | `text` | Output: text or json |

#### findings export

Export selected findings, or a whole scan, as `json`, `md`, `sarif`, `html` or `pdf`. Reads the local database; no engine needs to run. IDs accept a unique prefix. For a share-safe copy of a JSON report use `0security findings reports export`.

```text
0security findings export [options] [ids...]
```

```bash
0security findings export 3f2a 91bc --format sarif -o findings.sarif
0security findings export --scan 20260101-abc --format pdf -o report.pdf
```

| Argument | Required | Description |
| --- | --- | --- |
| `ids` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--scan <id>` | — | Export every finding of this scan instead of selected IDs |
| `--format <format>` | `json` | json, md, sarif, html or pdf |
| `-o, --output <file>` | — | Write to a file instead of stdout |
| `--severity <severity>` | — | With no IDs: only this severity |
| `--category <category>` | — | With no IDs: only this category |
| `--status <status>` | — | With no IDs: only this status |
| `--triage <triage>` | — | With no IDs: only this triage state |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print the result of writing a file as JSON |

#### findings keys

Manage API access keys for the findings API. A read key lists and reads findings. A write key sends findings to a shared findings server. The secret is printed once at creation and never stored in plaintext. Team workspaces manage keys in the browser.

```text
0security findings keys
```

```bash
0security findings keys create ci-reader --expires-in 30
```

Subcommands: [list](#findings-keys-list) · [create](#findings-keys-create) · [revoke](#findings-keys-revoke).

#### findings keys list

List keys with their expiry and status. Secrets are never shown.

```text
0security findings keys list [options]
```

```bash
0security findings keys list --json
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### findings keys create

Create a key. It reads findings unless you pass `--scope write`, which makes a key that only sends findings and needs an enterprise license. Default expiry is 90 days.

```text
0security findings keys create [options] <name>
```

```bash
0security findings keys create ci-reader --expires-in 30
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--scope <scope>` | `read` | read (default) lists and reads findings; write sends findings to the shared findings server and needs an enterprise license |
| `--expires-in <days>` | — | Days until the key expires (default 90) |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### findings keys revoke

Revoke a key. Requires `--yes`.

```text
0security findings keys revoke [options] <id>
```

```bash
0security findings keys revoke 643b88a4-2fae-409b-b4d9-bea00fc75812 --yes
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm the revocation |
| `--db-path <path>` | — | Path to SQLite database |
| `--json` | — | Print JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### config db

Manage the local findings database.

```text
0security config db
```

Subcommands: [repair](#config-db-repair) · [reset](#config-db-reset).

#### config db repair

Back up a malformed local SQLite database and recreate a clean one

```text
0security config db repair [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |

#### config db reset

Delete the local SQLite database and optionally reseed the verification workbench

```text
0security config db reset [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--seed <preset>` | `verification` | Seed preset to load after reset |

Reset also removes the database's `-journal` file and `.lock` directory. It refuses, and deletes nothing, when:

- the database path is a directory (check `ZERO_DB_PATH` and `--db-path`)
- the process recorded in `<db>.lock/pid` is still alive
- the lock has no owner information and changed in the last 5 minutes

Symlinks are removed as links and never followed. The browser's reset-database action behaves the same way and can return an error for a held lock.

## Automation & integration

### computers

Add and manage remote computers. A computer is a remote 0 engine that runs threads and automations on its host. Select it in the browser's computer menu to work there.

```text
0security computers
```

Subcommands: [list](#computers-list) · [add](#computers-add) · [stop](#computers-stop) · [repair](#computers-repair) · [remove](#computers-remove) · [hosts](#computers-hosts).


#### computers list

List the registered remote computers with their host and whether 0 deployed them
(managed computers can be reconnected and stopped from here).

```text
0security computers list [options]
```

```bash
0security computers list --json
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print JSON |
| `--engines-config <path>` | — | Engine registry path |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### computers add

Deploy the built CLI engine onto a running Linux Lima instance or an SSH host and register its connection locally. Run `pnpm build` in a source checkout first.

```bash
0security computers add --ssh me@build-box
```

Use `--ssh` for an SSH host alias or `user@host`. Without it, the command uses the `zero-worker` Lima instance. SSH deployment uses noninteractive key authentication.

```text
0security computers add [options]
```

Use `--target-git` with an `https://` URL to clone your repository into the remote workspace. Deployment installs runtime dependencies and starts the engine on the remote machine.

`--forward-provider-key` sends your `OPENAI_API_KEY` to the remote engine. Use it only for a host you own.

Check the returned backend ID and connection details, then select that computer in the browser before starting remote work.

| Option | Registered default | Description |
| --- | --- | --- |
| `--ssh <user@host>` | — | SSH target host (BatchMode; key auth from ssh config/agent) |
| `--lima <name>` | `zero-worker` | Lima instance name |
| `--target-git <url>` | — | HTTPS URL of a Git repository the remote server clones into the engine folder instead of the bundled demo target |
| `--ssh-config <path>` | — | OpenSSH config file for the SSH target (e.g. a Lima instance's ssh.config) |
| `--engine-port <port>` | — | Engine port on the remote server (default: stable port derived from host) |
| `--trust-new-host` | `false` | Trust and remember the computer's SSH host key if it is not known yet |
| `--forward-provider-key` | `false` | Forward this computer's OPENAI_API_KEY to the remote engine (user-owned hosts only) |
| `--engines-config <path>` | — | Engine registry path |

Aliases: `deploy`.

#### computers repair

Reconnect a deployed computer from its saved deployment details. The command starts the retained engine if needed and recreates its SSH tunnel. It keeps remote files and refuses to replace an unrelated process or an occupied engine port. If the deployment files are missing, add the computer again.

```text
0security computers repair <id>
```

The result is JSON with the backend ID, reconnection status, and whether the
engine was started.

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

Aliases: `reconnect`.

#### computers stop

Stop a computer that 0 deployed and close its local tunnel. Before it signals the process, the command checks the saved deployment details, the remote working directory, and the process ID and command. The remote workspace and the saved registration stay, so you can add the computer again later.

```text
0security computers stop <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

#### computers remove

Remove a remote computer from this machine: closes the tunnel and forgets its
saved connection. Files on the remote computer stay in place.

```text
0security computers remove [options] <id>
```

Run `0security computers list` to see the IDs.

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--engines-config <path>` | — | Engine registry path |

#### computers hosts

List SSH host aliases from `~/.ssh/config`, with their resolved host and user. It does not check connectivity or whether a host can run a Linux engine.

```text
0security computers hosts
```

### skills

Browse, add, create, edit, import, export and link skills

```text
0security skills
```

Every command works with the app running or on its own, and takes `--json`. Adding from GitHub or the catalog shows a review first and needs `--yes`.

```bash
0security skills list
0security skills catalog --search handoff
0security skills add mattpocock~skills~handoff --yes
```

Subcommands: [list](#skills-list) · [add](#skills-add) · [show](#skills-show) · [new](#skills-new) · [edit](#skills-edit) · [copy](#skills-copy) · [delete](#skills-delete) · [import](#skills-import) · [export](#skills-export) · [link](#skills-link) · [unlink](#skills-unlink) · [catalog](#skills-catalog) · [extensions](#skills-extensions) · [remove](#skills-remove).

#### skills list

List installed skills and linked folders

```text
0security skills list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills show

Show a skill's SKILL.md and files

```text
0security skills show [options] <id-or-name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id-or-name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills new

Create a skill from a SKILL.md file

```text
0security skills new [options] <file>
```

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills edit

Replace a skill's SKILL.md with the contents of --file

```text
0security skills edit [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--file <path>` **required** | — | SKILL.md with the new content |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills copy

Save a workspace copy of a skill under a new name

```text
0security skills copy [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--name <name>` **required** | — | Name for the copy (lowercase letters, digits, hyphens) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills delete

Delete a skill from the workspace library

```text
0security skills delete [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm the deletion |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills import

Import a skill bundle (.skill.json) or a folder with SKILL.md

```text
0security skills import [options] <bundle>
```

| Argument | Required | Description |
| --- | --- | --- |
| `bundle` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills export

Export a skill as a bundle

```text
0security skills export [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `-o, --output <file>` | — | Write the bundle to a file instead of stdout |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills link

Link a folder of skills; they stay where they are

```text
0security skills link [options] <folder>
```

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills unlink

Unlink a folder by its link id (see `0security skills list --json`)

```text
0security skills unlink [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills catalog

Browse the skills catalog

```text
0security skills catalog [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--search <text>` | — | Filter by name, publisher or summary |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills add

Add a skill from the catalog or GitHub (owner/repo[/path]); shows a review first

```text
0security skills add [options] <source>
```

| Argument | Required | Description |
| --- | --- | --- |
| `source` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--preview` | — | Only show the review |
| `--yes` | — | Install the reviewed commit |
| `--enable` | — | Extensions: also enable it |
| `--project <dir>` | — | Extensions: with --enable, enable for this folder only |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions

Installed extensions: list, info, enable, disable, update, remove (install with `0security skills add`)

```text
0security skills extensions
```

Subcommands: [add](#skills-extensions-add) · [mcp](#skills-extensions-mcp) · [list](#skills-extensions-list) · [info](#skills-extensions-info) · [enable](#skills-extensions-enable) · [disable](#skills-extensions-disable) · [remove](#skills-extensions-remove) · [update](#skills-extensions-update) · [import](#skills-extensions-import).

#### skills extensions add

Install an extension: <url|owner/repo|folder>@<full sha>; same as `0security skills add`

```text
0security skills extensions add [options] <source>
```

| Argument | Required | Description |
| --- | --- | --- |
| `source` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--preview` | — | Only show the install prompt |
| `--yes` | — | Install the exact revision shown |
| `--enable` | — | Also enable it |
| `--project <dir>` | — | With --enable: enable for this folder only |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions mcp

Add one MCP server as a local extension

```text
0security skills extensions mcp [options] <name> [command...]
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |
| `command` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--url <https-url>` | — | A remote server instead of a command |
| `--preview` | — | Only show the install prompt |
| `--yes` | — | Install the exact revision shown |
| `--enable` | — | Also enable it |
| `--project <dir>` | — | With --enable, enable for this folder only |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions list

List installed extensions and built-ins

```text
0security skills extensions list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--project <dir>` | — | Show enablement for this project |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions info

Show the install prompt for an installed extension

```text
0security skills extensions info [options] <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions enable

Enable globally, or for one project with --project

```text
0security skills extensions enable [options] <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project <dir>` | — | Enable for this folder only |
| `--yes` | — | Approve an unapproved revision (for example an imported one) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions disable

Disable globally, or for one project with --project

```text
0security skills extensions disable [options] <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project <dir>` | — | Disable for this folder only |
| `--yes` | — | Confirm disabling a built-in |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions remove

Remove an installed extension and its stored revisions

```text
0security skills extensions remove [options] <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm the removal |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions update

Show the diff and install prompt for a newer revision; --yes --to <sha> approves it

```text
0security skills extensions update [options] <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--to <sha>` | — | Full commit SHA to update to (default: the remote HEAD) |
| `--yes` | — | Approve the revision given by --to |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills extensions import

Import earlier plugins, MCP servers and skills (runs once automatically); shows what could not be migrated

```text
0security skills extensions import [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--force` | — | Run the importer again |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### skills remove

Remove a skill that was added from GitHub or the catalog

```text
0security skills remove [options] <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `name` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm the removal |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Use this engine database instead of the default |
| `--format <format>` | — | Output: text or json Choices: text, json. |

### automation

Saved automations.

```text
0security automation
```

Subcommands: [list](#automation-list) · [show](#automation-show) · [create](#automation-create) · [edit](#automation-edit) · [duplicate](#automation-duplicate) · [versions](#automation-versions) · [rollback](#automation-rollback) · [delete](#automation-delete).


#### automation list

List saved automations and templates.

```text
0security automation list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--templates` | — | List only templates |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `json` | Output format: json or text |

#### automation show

Inspect one saved automation or select a template with `--template`.

```text
0security automation show [options] [id]
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--template <id>` | — | Show a template definition |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `json` | Output format: json or text |

#### automation create

Create an automation from a template or a JSON definition.

```text
0security automation create [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--template <id>` | — | Start from a template (see `0security sentinels list --automation --templates`) |
| `--file <path>` | — | Definition JSON object |
| `--name <name>` | — | Name for the new automation |
| `--target <target>` | — | Target the automation runs against |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |

#### automation edit

Replace an automation's definition from a JSON file.

```text
0security automation edit [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--file <path>` **required** | — | Definition JSON object |
| `--revision <n>` | — | Reviewed revision to edit (default: the current one) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |

#### automation duplicate

Save a copy of an automation.

```text
0security automation duplicate [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--name <name>` | — | Name for the copy |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |

#### automation versions

List saved revisions of an automation.

```text
0security automation versions [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |

#### automation rollback

Restore an earlier revision as a new revision.

```text
0security automation rollback [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--revision <n>` **required** | — | Revision to restore (see `0security sentinels set --automation versions`) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |

#### automation delete

Delete a saved automation and its schedules.

```text
0security automation delete [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--revision <n>` | — | Reviewed revision to delete (default: the current one) |
| `--yes` | — | Confirm deletion |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |

### threads

Inspect and control the same live threads the browser uses. Attach with `--engine`, or with `--engine-url` and `--engine-token-env`, or use the discovered local engine. These commands keep the engine's current admission grants.

```text
0security threads
```

```bash
0security threads list --engine production
```

Subcommands: [list](#threads-list) · [show](#threads-show) · [send](#threads-send) · [start](#threads-start) · [stop](#threads-stop) · [create](#threads-create) · [continue](#threads-continue) · [cancel](#threads-cancel) · [force-stop](#threads-force-stop) · [events](#threads-events) · [resume](#threads-resume) · [decide](#threads-decide) · [retry](#threads-retry) · [set](#threads-set) · [rename](#threads-rename) · [clear](#threads-clear) · [close](#threads-close) · [archive](#threads-archive) · [delete](#threads-delete) · [export](#threads-export).

#### threads list

List live sessions, or retained snapshots with --saved. Listing does not resume work.

```text
0security threads list [options]
```

```bash
0security threads list --saved --engine production
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--saved` | — | List retained thread snapshots |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads show

Read an existing live session without recreating it or restoring approvals.

```text
0security threads show [options] <id>
```

```bash
0security threads show SESSION_ID --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--wait` | — | Wait for the answer; stdout is the reply only (thread id and usage go to stderr) |
| `--timeout <seconds>` | `600` | Maximum seconds to wait with --wait |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads create

Create a session within the engine's authorized workspace and model configuration. --config reads a bounded JSON object; it cannot expand engine grants.

```text
0security threads create [options]
```

```bash
0security threads create --config session.json --engine production
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--config <path>` | — | Thread configuration JSON object |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `json` | Output format: json or text |
| `--json` | — |  |

#### threads send

Send text to a live engine session. The engine runs the turn using its configured provider and tools.

```text
0security threads send [options] <id> <text>
```

```bash
0security threads send SESSION_ID "Review the current findings" --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `text` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--wait` | — | Wait for the answer; stdout is the reply only (thread id and usage go to stderr) |
| `--timeout <seconds>` | `600` | Maximum seconds to wait with --wait |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads continue

Continue the selected live session with optional text. This preserves the existing engine context.

```text
0security threads continue [options] <id> [text]
```

```bash
0security threads continue SESSION_ID --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `text` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--wait` | — | Wait for the answer; stdout is the reply only (thread id and usage go to stderr) |
| `--timeout <seconds>` | `600` | Maximum seconds to wait with --wait |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads cancel

Explicitly cancel the session's active work. Transport disconnect alone does not request cancellation from an attached engine.

```text
0security threads cancel [options] <id>
```

```bash
0security threads cancel SESSION_ID --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads events

Read engine session events after an optional nonnegative cursor. Cursors belong to that engine and session.

```text
0security threads events [options] <id>
```

```bash
0security threads events SESSION_ID --after 0 --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--after <cursor>` | — | Nonnegative engine event cursor |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `json` | Output format: json or text |
| `--json` | — |  |

#### threads force-stop

Stop a session's owned execution process and registered resources. Use the exact live ID from `0security threads list`. The command never restores a saved chat or substitutes a replacement session.

The owning engine checks authorization and supervisor availability. Unsupported execution returns an error, and teardown that is not confirmed stays quarantined. Nothing is escalated or replayed automatically.

```text
0security threads force-stop [options] <id>
```

```bash
0security threads force-stop LIVE_SESSION_ID --engine production
0security threads force-stop LIVE_SESSION_ID --engine-url http://127.0.0.1:48123 --engine-token-env ZERO_ENGINE_TOKEN
```

Force stop works for qualified Bun sessions on macOS and Linux. Completed external effects are not undone. After an error, run `0security threads show` before you take another action.

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads resume

Restore a retained snapshot as a new session under current engine grants. Stored transcripts do not restore approval or filesystem grants.

```text
0security threads resume [options] <saved-id>
```

```bash
0security threads resume SAVED_ID --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `saved-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `text` | Output format: json or text |
| `--json` | — |  |

#### threads decide

Respond to an existing session decision using a JSON response file. The engine checks the decision belongs to that live session.

```text
0security threads decide [options] <id> <decision-id>
```

```bash
0security threads decide SESSION_ID DECISION_ID --response response.json --engine production
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `decision-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--response <path>` **required** | — | Decision response JSON object |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--engine <id>` | — | Use a registered remote engine; targets and inputs are interpreted there |
| `--engines-config <path>` | — | Operator engine connection registry JSON file |
| `--db-path <path>` | — | Control database of the local engine |
| `--format <format>` | `json` | Output format: json or text |
| `--json` | — |  |

#### threads start

Create a thread, send the first prompt and print its ID. With `--wait`, block until the turn ends and print the reply.

```text
0security threads start [options] <prompt>
```

```bash
0security threads start "Triage the open findings" --model gpt-5 --effort high --mode recon --wait
```

| Argument | Required | Description |
| --- | --- | --- |
| `prompt` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--model <model>` | — | Model for this thread |
| `--effort <level>` | — | Reasoning effort: minimal, low, medium, high, xhigh |
| `--approvals <ask\|auto>` | — | Moved to the global setting |
| `--folder <path>` | — | Folder the thread works in |
| `--skill <id>` | — | Built-in skill to follow; if it declares a check, the harness runs it and the thread cannot claim Verified without it |
| `--title <title>` | — | Thread title |
| `--wait` | — | Wait for the answer; stdout is the reply only (thread id and usage go to stderr) |
| `--cost-ceiling <usd>` | — | Stop the thread when its estimated spend reaches this many USD |
| `--timeout <seconds>` | `600` | Maximum seconds to wait with --wait |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads stop

Cancel a thread's active work. `--force` force stops owned execution that did not drain.

```text
0security threads stop [options] <id>
```

```bash
0security threads stop 3f2a --force
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--force` | — | Force stop owned execution that did not drain |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads retry

Re-run the last turn of a thread.

```text
0security threads retry [options] <id>
```

```bash
0security threads retry 3f2a
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads set

Change a thread's model, reasoning effort, mode or folder. A computer is chosen when the thread starts.

```text
0security threads set [options] <id>
```

```bash
0security threads set 3f2a --mode copilot --folder ~/code/app
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--model <model>` | — | Model |
| `--effort <level>` | — | Reasoning effort: minimal, low, medium, high, xhigh |
| `--approvals <ask\|auto>` | — | Moved to the global setting |
| `--folder <path>` | — | Folder the thread works in |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads rename

Rename a thread, or generate a new title from its conversation.

```text
0security threads rename [options] <id> [title]
```

```bash
0security threads rename 3f2a --regenerate
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `title` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--regenerate` | — | Generate a new title from the conversation |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads clear

Erase a thread's conversation but keep the thread. Requires `--yes`.

```text
0security threads clear [options] <id>
```

```bash
0security threads clear 3f2a --yes
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm the destructive action |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads close

Stop and close a live thread. Its saved copy stays.

```text
0security threads close [options] <id>
```

```bash
0security threads close 3f2a
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads archive

Archive a thread, or a retained snapshot with `--saved`.

```text
0security threads archive [options] <id>
```

```bash
0security threads archive 3f2a
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--saved` | — | The ID is a retained snapshot, not a live thread |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads delete

Permanently delete a thread or, with `--saved`, a retained snapshot. Requires `--yes`.

```text
0security threads delete [options] <id>
```

```bash
0security threads delete 3f2a --yes
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--saved` | — | The ID is a retained snapshot, not a live thread |
| `--yes` | — | Confirm the destructive action |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### threads export

Export a thread transcript as JSON or Markdown.

```text
0security threads export [options] <id>
```

```bash
0security threads export 3f2a --format md -o transcript.md
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--saved` | — | The ID is a retained snapshot, not a live thread |
| `--format <format>` | `json` | json or md |
| `-o, --output <file>` | — | Write to a file instead of stdout |
| `--engine-url <url>` | — | Attach directly to a running trusted engine |
| `--engine-token-env <name>` | — | Environment variable holding the attached engine token |
| `--computer <id>` | — | Use a registered remote computer |
| `--engine <id>` | — |  |
| `--computers-config <path>` | — | Operator computer connection registry JSON file |
| `--engines-config <path>` | — |  |
| `--db-path <path>` | — | Control database of the local engine to attach to |
| `--json` | — | Print the engine response as JSON |

### sentinels

Create, inspect and control Sentinels.

```text
0security sentinels
```

Subcommands: [list](#sentinels-list) · [run](#sentinels-run) · [set](#sentinels-set) · [sync](#sentinels-sync) · [export](#sentinels-export) · [bitbucket](#sentinels-bitbucket) · [show](#sentinels-show) · [presets](#sentinels-presets) · [create](#sentinels-create) · [pause](#sentinels-pause) · [resume](#sentinels-resume) · [acknowledge](#sentinels-acknowledge) · [archive](#sentinels-archive) · [delete](#sentinels-delete) · [activations](#sentinels-activations) · [files](#sentinels-files) · [triggers](#sentinels-triggers) · [webhook](#sentinels-webhook).

#### sentinels sync

Make Sentinels match the YAML files in a folder. Shows what would change; --apply writes it.

```text
0security sentinels sync [options] <folder>
```

```bash
0security sentinels sync ./sentinels
0security sentinels sync ./sentinels --apply
```

Each `*.yaml` file is one Sentinel: name, mission, instructions, skills, model, folder, and automations with their triggers (see [Sentinels as files](/sentinels/#sentinels-as-files)). Without `--apply` nothing is written.

- A new Sentinel is created paused and a new trigger disabled.
- A changed model or skill list sends an active Sentinel back to review.
- A Sentinel that is not in the folder is left alone.

Stop a running console on the same database first.

| Argument | Required | Description |
| --- | --- | --- |
| `folder` | Yes | Folder of Sentinel definitions (*.yaml), for example .0/sentinels |

| Option | Registered default | Description |
| --- | --- | --- |
| `--apply` | — | Write the changes (without it, only the plan is shown) |
| `--check` | — | Exit 1 when the database differs from the files |
| `--commit <sha>` | — | Commit the files came from; recorded on each Sentinel |
| `--enable` | — | Enable the triggers this sync creates (only for a change that was already reviewed) |
| `--db-path <path>` | — | Database to change; stop its running console first |
| `--format <format>` | `text` | Output: text or json |

#### sentinels bitbucket

Review Bitbucket pull requests from this machine (Cloud and Data Center).

```text
0security sentinels bitbucket
```

Subcommands: [review](#sentinels-bitbucket-review) · [watch](#sentinels-bitbucket-watch).

Both commands scan what a pull request changes, publish a Code Insights report and keep one summary comment up to date. See [Review Bitbucket pull requests on your own machine](/ci/#review-bitbucket-pull-requests-on-your-own-machine).

#### sentinels bitbucket review

Review one pull request now.

```text
0security sentinels bitbucket review [options]
```

```bash
export BITBUCKET_TOKEN=...
0security sentinels bitbucket review --platform cloud --repo acme/app --checkout ~/code/app --pr 42
0security sentinels bitbucket review --platform dc --repo PROJ/app --checkout ~/code/app --pr 42 --url https://bitbucket.example.com
```

The command fetches the pull request's commit into a temporary worktree of your clone, runs `0security scan --diff` there, and prints the outcome as JSON. A pull request that is closed, a draft or from a fork is skipped. A commit that was already reviewed is skipped.

| Option | Registered default | Description |
| --- | --- | --- |
| `--pr <number>` **required** | — | Pull request number |
| `--platform <platform>` **required** | — | cloud or dc (Data Center) |
| `--repo <repo>` **required** | — | workspace/repo on Cloud, PROJECT/repo on Data Center |
| `--checkout <folder>` **required** | — | A local clone of the repository; its origin must be the Bitbucket repository |
| `--url <url>` | — | Data Center base URL (default: BITBUCKET_URL) |
| `--allow-insecure-http` | — | Send the token to an http:// URL that is not on this machine (default: refuse) |
| `--budget <usd>` | `2` | Spend limit for one pull request scan |
| `--model <model>` | — | Model for the scan thread |
| `--max-files <n>` | `50` | Skip a pull request that changes more files than this |
| `--max-inline <n>` | `10` | Most inline comments per pull request |
| `--report-id <id>` | `0-security` | Code Insights report id |
| `--state <file>` | — | File that remembers which commit of each pull request was reviewed (default: ~/.0/bitbucket-review.json) |
| `--no-comments` | — | Publish the Code Insights report only; post no comments |
| `--no-insights` | — | Post comments only; publish no Code Insights report |

#### sentinels bitbucket watch

Review pull requests as they open or change: poll, a signed webhook, or both.

```text
0security sentinels bitbucket watch [options]
```

```bash
export BITBUCKET_TOKEN=...
0security sentinels bitbucket watch --platform cloud --repo acme/app --checkout ~/code/app
export BITBUCKET_WEBHOOK_SECRET=...
0security sentinels bitbucket watch --platform dc --repo PROJ/app --checkout ~/code/app --url https://bitbucket.example.com --listen 127.0.0.1:7777
```

The command polls the open pull requests every `--interval` seconds. With `--listen` it also accepts webhook deliveries signed with `BITBUCKET_WEBHOOK_SECRET`. Reviews run one at a time. Use `--once` to poll once and exit, for a scheduled job.

| Option | Registered default | Description |
| --- | --- | --- |
| `--platform <platform>` **required** | — | cloud or dc (Data Center) |
| `--repo <repo>` **required** | — | workspace/repo on Cloud, PROJECT/repo on Data Center |
| `--checkout <folder>` **required** | — | A local clone of the repository; its origin must be the Bitbucket repository |
| `--url <url>` | — | Data Center base URL (default: BITBUCKET_URL) |
| `--allow-insecure-http` | — | Send the token to an http:// URL that is not on this machine (default: refuse) |
| `--budget <usd>` | `2` | Spend limit for one pull request scan |
| `--model <model>` | — | Model for the scan thread |
| `--max-files <n>` | `50` | Skip a pull request that changes more files than this |
| `--max-inline <n>` | `10` | Most inline comments per pull request |
| `--report-id <id>` | `0-security` | Code Insights report id |
| `--state <file>` | — | File that remembers which commit of each pull request was reviewed (default: ~/.0/bitbucket-review.json) |
| `--no-comments` | — | Publish the Code Insights report only; post no comments |
| `--no-insights` | — | Post comments only; publish no Code Insights report |
| `--interval <seconds>` | `120` | Poll every this many seconds (at least 30) |
| `--listen <host:port>` | — | Also accept webhooks here; set BITBUCKET_WEBHOOK_SECRET to the webhook's secret |
| `--once` | — | Poll once, finish the reviews, and exit |
| `--max-reviews <n>` | `5` | Most pull requests one poll queues |

#### sentinels export

Write a Sentinel as a YAML definition file, so a team can start from what it already has

```text
0security sentinels export [options] <id>
```

Prints the definition, or writes `<name>.yaml` into `--out`. Syncing the exported file back changes nothing.

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Sentinel ID (full or prefix) or exact name |

| Option | Registered default | Description |
| --- | --- | --- |
| `--out <folder>` | — | Write &lt;name&gt;.yaml into this folder instead of standard output |
| `--db-path <path>` | — | Database to read; stop its running console first |

#### sentinels list

List Sentinels.

```text
0security sentinels list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--status <status>` | — | Only active, paused, archived |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels show

Show a Sentinel (full or prefix ID).

```text
0security sentinels show [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels presets

List Sentinel presets.

```text
0security sentinels presets [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels create

Create a Sentinel from a preset or a JSON definition.

```text
0security sentinels create [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--preset <id>` | — | Start from a preset (see `0security sentinels list --presets`) |
| `--name <name>` | — | Name |
| `--file <path>` | — | Sentinel JSON object (overrides preset fields) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels set

Change a Sentinel's settings.

```text
0security sentinels set [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--name <name>` | — | Name |
| `--purpose <text>` | — | One-line purpose |
| `--mission <text>` | — |  |
| `--file <path>` | — | Patch JSON object |
| `--version <n>` | — | Reviewed version (default: the current one) |
| `--state <state>` | — | active, paused, acknowledged, archived or deleted |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels pause

Pause a Sentinel.

```text
0security sentinels pause [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels resume

Resume a paused Sentinel.

```text
0security sentinels resume [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--acknowledge` | — | Also acknowledge review of changed model or tools |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels acknowledge

Mark changed model or tools as reviewed.

```text
0security sentinels acknowledge [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels archive

Archive a Sentinel; its history stays.

```text
0security sentinels archive [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels delete

Delete a Sentinel; its automations are detached, not deleted.

```text
0security sentinels delete [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm deletion |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels run

Run a Sentinel now; starts a thread (needs a running engine).

```text
0security sentinels run [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--task <text>` | — | Task for this run |
| `--yes` | — | Confirm that this run is authorized |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels activations

List a Sentinel's recent runs.

```text
0security sentinels activations [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--limit <n>` | `50` | Maximum rows (1-200) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |


#### sentinels files

Read and edit a Sentinel's instructions and notes files.

```text
0security sentinels files
```

Subcommands: [list](#sentinels-files-list) · [get](#sentinels-files-get) · [put](#sentinels-files-put) · [rm](#sentinels-files-rm).

#### sentinels files list

List files.

```text
0security sentinels files list [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels files get

Print a file's content.

```text
0security sentinels files get [options] <id> <path>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `path` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels files put

Create or replace a file from --file or --content.

```text
0security sentinels files put [options] <id> <path>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `path` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--file <path>` | — | Read content from a local text file |
| `--content <text>` | — | Inline content |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels files rm

Delete a file.

```text
0security sentinels files rm [options] <id> <path>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `path` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm deletion |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels triggers

Control what starts a Sentinel's automations.

```text
0security sentinels triggers
```

Subcommands: [list](#sentinels-triggers-list) · [add](#sentinels-triggers-add) · [enable](#sentinels-triggers-enable) · [disable](#sentinels-triggers-disable) · [check](#sentinels-triggers-check) · [secret](#sentinels-triggers-secret) · [rm](#sentinels-triggers-rm).

#### sentinels triggers list

List triggers.

```text
0security sentinels triggers list [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels triggers add

Add a trigger for an automation the Sentinel owns; disabled unless --enable --yes.

```text
0security sentinels triggers add [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--automation <id>` | — | What the trigger starts (default: the only one this Sentinel owns) |
| `--kind <kind>` | — | schedule \| manual \| github-pr \| bitbucket-pr \| release \| check-completed \| webhook |
| `--file <path>` | — | Trigger JSON object with schedule, github, bitbucket, release or check settings |
| `--enable` | — | Enable immediately |
| `--yes` | — | Confirm that an enabled trigger was reviewed |
| `--frequency <frequency>` | — | schedule: minutes, hourly, daily, weekdays, weekly, cron |
| `--every <minutes>` | — | schedule, minutes: interval (5 or more) |
| `--at <HH:MM>` | — | schedule, daily, weekdays, weekly: time of day in --timezone (default UTC) |
| `--weekday <day>` | — | schedule, weekly: sun, mon, ... or 0-6 |
| `--cron <expression>` | — | schedule, cron: five fields |
| `--timezone <zone>` | — | schedule: IANA timezone (default UTC) |
| `--repo <owner/name>` | — | github-pr: repository to watch; bitbucket-pr: workspace/repo (Cloud) or PROJECT/repo (Data Center) |
| `--base-branch <branch>` | — | github-pr: only pull requests into this branch |
| `--comment` | — | github-pr: comment on each pull request with one short summary, edited in place on later pushes (default: off) |
| `--include-forks` | — | github-pr: also review pull requests from forks, marked untrusted (default: skipped) |
| `--results <mode>` | — | github-pr, release, check-completed: send findings back to GitHub: off, sarif, comment, both (default: off). sarif uploads to code scanning; comment posts one pull request comment |
| `--label <text>` | — | webhook: a name for this webhook (default: webhook) |
| `--platform <platform>` | — | bitbucket-pr: cloud or dc (Data Center) |
| `--url <url>` | — | bitbucket-pr, Data Center: server URL, for example https://bitbucket.example.com |
| `--checkout <folder>` | — | bitbucket-pr: absolute path of a local clone whose origin is the Bitbucket repository |
| `--token-env <name>` | — | bitbucket-pr: name of the environment variable that holds the token (default: BITBUCKET_TOKEN) |
| `--events <list>` | — | bitbucket-pr: opened, updated or opened,updated (default: both) |
| `--max-files <n>` | — | bitbucket-pr: skip a pull request that changes more files than this (default: 50) |
| `--budget <usd>` | — | bitbucket-pr: spend limit for one pull request scan (default: 2) |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels triggers enable

Enable a trigger after reviewing it.

```text
0security sentinels triggers enable [options] <id> <trigger-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `trigger-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm that this trigger was reviewed |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels triggers disable

Pause a trigger.

```text
0security sentinels triggers disable [options] <id> <trigger-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `trigger-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels triggers check

Poll a pull request trigger now instead of waiting for its next poll.

```text
0security sentinels triggers check [options] <id> <trigger-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `trigger-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels triggers secret

Create or replace the secret of a webhook trigger. The old secret keeps working for 5 minutes. The new one is printed once.

```text
0security sentinels triggers secret [options] <id> <trigger-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `trigger-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm; update the calling system afterwards |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

Needs server mode. See [Webhook trigger](/sentinels/#webhook-trigger).

#### sentinels triggers rm

Delete a trigger.

```text
0security sentinels triggers rm [options] <id> <trigger-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `trigger-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm deletion |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels webhook

GitHub webhook for pull request Sentinels (server mode). Hidden: most installs poll. See [Sentinels](/sentinels/#faster-with-a-github-webhook-server-mode).

```text
0security sentinels webhook
```

Subcommands: [status](#sentinels-webhook-status) · [secret](#sentinels-webhook-secret).

#### sentinels webhook status

Show whether the webhook is set up and the last deliveries.

```text
0security sentinels webhook status [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

#### sentinels webhook secret

Manage the webhook secret.

```text
0security sentinels webhook secret
```

Subcommands: [rotate](#sentinels-webhook-secret-rotate).

#### sentinels webhook secret rotate

Create the secret, or replace it; the old one keeps working for 5 minutes. Printed once.

```text
0security sentinels webhook secret rotate [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--yes` | — | Confirm; update the secret on GitHub afterwards |
| `--json` | — | Print machine-readable JSON |
| `--db-path <path>` | — | Control database (default: the user database) |
| `--format <format>` | — | Output: text or json Choices: text, json. |

## Team workspace setup

### config team

```text
0security config team
```

Provision opt-in accounts for a team engine you control. Local use without accounts stays the default. Creating a config does not activate it on a running host. See [Team workspaces](/computers/) for roles and deployment boundaries.

Subcommands: [init](#config-team-init) · [add-user](#config-team-add-user) · [list](#config-team-list).

### config team init

Create a private configuration with the first owner account. The password comes from protected terminal input or stdin and is stored as a salted hash. No email invitation is sent. Then start `0security web --team-config <path>`.

```text
0security config team init [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--config <path>` **required** | — | Configuration file to create |
| `--name <name>` **required** | — | Workspace name |
| `--owner <id>` **required** | — | Owner account ID |
| `--display-name <name>` **required** | — | Owner display name |

### config team add-user

Add an account to a private configuration with the role `owner`, `editor` or `viewer`. A viewer cannot control agents. Restart the team engine to load changes. The password is never a command-line argument.

```text
0security config team add-user [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--config <path>` **required** | — | Team configuration |
| `--user <id>` **required** | — | Account ID |
| `--display-name <name>` **required** | — | Display name |
| `--role <role>` **required** | — | owner, editor or viewer |

### config team list

List account IDs, display names and roles. Password hashes are not shown. The configuration must be a private regular file.

```text
0security config team list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--config <path>` **required** | — | Team configuration |
