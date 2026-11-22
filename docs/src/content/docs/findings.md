---
title: Findings
description: Review, triage, verify and export findings in the browser app or from the CLI.
---


A finding is a security issue that a thread or Sentinel recorded, with its evidence. Review findings in the app or the CLI, accept or dismiss them, verify them, and export or fix them.

0 groups duplicates of the same issue into one family by fingerprint, so a decision on one occurrence applies to all of them.

## Review findings in the app

Open **Findings** in the sidebar. The page has these views: **All**, **Needs review**, **Fix ready** and **Closed**. Search, or filter by severity and status.

Select a finding to open its detail panel. It shows the evidence (request, response, analysis and artifacts), severity, triage state and any fix pull request.

- Set the work state to **Backlog**, **Todo**, **In progress**, **Blocked**, **Done** or **Cancelled**. 0 sets **Needs your review** and **Agent review**. Until you confirm a finding that needs review, you can only move it to **Done**, **Cancelled** or **Accepted**.
- Choose **Accept** or **Dismiss**, with an optional note. **Undo** resets the finding to not reviewed.
- Choose **Verify in a thread**, **Fix in a thread** or **Investigate in a thread**, depending on the finding's state. **Terminal command** shows the same step for the CLI.
- Select several findings to change status, **Dismiss**, **Export** or **Add to thread**.
- Choose **Export finding** in the panel, or **More actions** for the current list. Formats are JSON, Markdown, HTML, SARIF and PDF.

Each finding has a stable link at `/findings/<fingerprint>`.

## List and inspect findings

```bash
0 findings
0 findings --severity high --triage new
0 findings show 3f2a
```

`0 findings` is the same as `0 findings list`. It reads the local findings database and groups duplicates. Add `--all` for raw rows. An ID can be a unique prefix.

| Filter | Values |
|---|---|
| `--severity` | `critical`, `high`, `medium`, `low`, `info` |
| `--status` | `discovered`, `verified`, `confirmed`, `scored`, `reported`, `fixed`, `false-positive` |
| `--triage` | `new`, `accepted`, `suppressed` |
| `--category` | An attack category |
| `--limit <n>` | Default 50 |

`0 findings show` prints the title, what an attacker can do (when the scan assessed it), severity, CVSS when present, status, triage state, evidence and related occurrences.

To read another database, add `--db-path`:

```bash
0 findings show 3f2a --db-path ./engagement.db
```

## Triage a finding

Status and triage are separate. Status is what the automation established: `discovered` is a candidate, `verified` and `confirmed` passed a verification step, and `false-positive` was rejected. Triage is your decision: `new`, `accepted` or `suppressed` (shown as **Dismissed** in the app).

Accepting a finding does not verify it, and suppressing it does not make it false.

```bash
0 findings update 3f2a --status accepted --note "Confirmed on staging, ticket SEC-142"
0 findings update 3f2a --status suppressed --note "Test-only endpoint"
0 findings update 3f2a --status open
```

`--status open` resets the finding.

### Mark a false positive

A false positive is suppressed with your reason, and it stays suppressed across scans of the same code.

```bash
0 findings update 3f2a --status false-positive --reason "Echo endpoint only exists in test fixtures"
```

To give every thread standing context, such as "the public API allows CORS on purpose", write it in your operator instructions: `~/.0/AGENTS.md`, or the per-workspace file.

## Verified and Not verified

A finding is a claim. Verified means 0 ran a check itself and it passed. The check runs in a container on a copy of your changes, with the network off, after the Agent says it is done. The Agent cannot mark anything Verified. A fix shows one line under it:

```
Verified by: zizmor passed, 4 findings to 0 (14.2s)
Not verified: no container runtime is available
Not verified: zizmor failed (detector did not run)
```

Without Docker or podman the result is Not verified. A model's own judgment that a finding is real is not a check. Imported findings are marked discovered and unverified.

A skill can declare the check. This command runs zizmor with the repository's own configuration, then actionlint:

```bash
0 threads start "Harden the workflows" --folder . --skill workflow-hardening --wait
```

A planted unpinned action must be flagged first, so a configuration that turns the detector off reads as Not verified.

## Scan a folder

```bash
0 scan ./your-repo
0 scan https://github.com/acme/app --budget 2 --format json -o scan.json
0 scan ./your-repo --format sarif -o scan.sarif --fail-on high
```

A scan is a thread that follows the `scan` skill. It lists every entry point, checks each one and records what it can show from the code. The thread appears in `0 threads` and its findings in `0 findings`.

The target is a folder or a git URL, which 0 clones shallow and removes afterwards. Package names and container images are not scanned. A scan must not edit the code it reads. If it changes a file in a git work tree, the scan is reported as failed and names the files.

To make a scan weigh business logic and authorization, give it a reviewed threat model with `--context`. To check the code against your own written rules, use `--policy` and `--org-policy`. See [Threat model and policy checks](/threat-model-and-policy/).

| Option | What it does |
|---|---|
| `--budget <usd>` | Stop when the estimated spend reaches this much (default 5). Findings so far are kept. |
| `--format <format>` | `md` (default), `json`, `sarif`, `html` or `pdf`. `pdf` needs `-o`. |
| `-o, --output <file>` | Write the report to a file instead of stdout. |
| `--fail-on <severity>` | Exit 1 when a finding is at or above this severity. |
| `--passes <n>` | Scan up to 5 times and merge the findings (default 1). `--budget` is the total, split evenly between the passes. |
| `--timeout <seconds>` | Cancel the scan after this long (default 3600) and print what was found. |
| `--model <model>` | Model for the scan (default `gpt-6-luna`). |
| `--skill <id>` | Skill that holds the scan method (default `scan`). |

Exit codes: `0` done, `1` a finding at or above `--fail-on` or the scan failed, `2` usage error, `3` stopped at the budget or the time limit (the report is partial).

`0 scan` uses the console that is running, or the engine named by `--engine-url` or `--computer`. With none running it starts one and stops it afterwards.

The scan needs a model with working tool calls. In one test, a small model sent most `finding` calls without their title and evidence. Results also vary between runs, so a clean scan is not proof that nothing is there.

### Read the JSON report

The JSON report has `schemaVersion: 1` and these fields:

- `status`: `complete`, `budget_exhausted`, `timed_out` or `failed`.
- `counts` by severity, and the model's closing `summary`.
- `target`: the folder's name, or the git URL without credentials. It is the same on every machine.
- With `--passes`: `passes` (asked for, finished, failed) and every pass's `threadIds`.
- For each finding: `severity`, `category`, `location` (path relative to the scanned folder, with start and end line), `evidence`, and `foundInPasses` with `--passes`. `cvssScore` and `suggestedFix` appear when the scan gave them.

A finding's `fingerprint` is a hash of its file and first line, so the same place in unchanged code keeps it from scan to scan. It is absent when the finding cites no location. A model does not cite exactly the same lines every run, so match findings between scans by file and nearby lines.

Get the same report later, in any format:

```bash
0 findings export --scan <thread id>
```

### Plan a cryptography migration

`--skill crypto-migration` lists every cryptographic use: algorithm, key size, library, call site and what the output feeds. It separates quantum-vulnerable public-key crypto (RSA, ECDH, ECDSA, EdDSA) from weak classical crypto (SHA-1, MD5, DES, ECB, static IVs, hardcoded keys). It records one finding per site with a minimal `suggestedFix`.

```bash
0 scan ./your-repo --skill crypto-migration --format json -o crypto.json
```

The closing `summary` holds a migration plan: rollout order, key and data migration, versioned formats, hybrid mode (for example X25519 with ML-KEM-768) and tests. The skill does not install a post-quantum library or invent function names. Where it could not check a library's API in your code, the finding says so.

Fix one site at a time, each as a pull request (see [Fix a finding](#fix-a-finding)). Review each against the plan. A change to a wire or stored format needs the other side to accept both versions first.

### Scan a built artifact

`0 scan` reads a folder. Unpack the artifact into a new empty folder first, without running anything from it:

```bash
mkdir /tmp/artifact && cd /tmp/artifact
npm pack acme-utils@2.3.1 && tar -xzf acme-utils-*.tgz --no-same-owner   # npm package
pip download --no-deps --only-binary :all: acme-utils==1.0 -d . && unzip -q ./*.whl -d unpacked   # Python wheel
unzip -q app.jar -d unpacked                                                                   # jar
docker save acme/app:1.0 -o image.tar && mkdir image && tar -xf image.tar -C image             # image layers and config
mkdir rootfs && docker create --name tmp-export acme/app:1.0 && docker export tmp-export | tar -x -C rootfs   # image filesystem
docker rm tmp-export
0 scan /tmp/artifact/package --skill artifact-scan --budget 1   # the unpacked folder
```

Before you unpack an archive, list it with `tar -tzf file.tgz | head` or `unzip -l file.whl`. Look for absolute paths or `..` components. Recent GNU tar and Info-ZIP refuse them, but older versions may not. Do not extract with `sudo`, and use a disk with room for the contents.

Extracting as a normal user can drop setuid bits and ownership. A setuid file may then show only as a script that sets the bit itself. The skill checks both.

The skill checks:

- install scripts and startup commands
- embedded credentials
- setuid files
- unexpected native binaries
- URLs the code contacts
- debug leftovers
- shipped dependencies against the manifest

It runs `0 sbom generate` and `0 sbom check` on the folder, and `syft`, `trivy`, `file`, `strings`, `readelf` and `jq` if they are installed. It never executes anything from the artifact.

In a test on a planted npm package, the skill found all four planted problems in one run and three in another. A general scan found two. A clean result is not proof. Read what the summary says it could not check.

### Scan in CI

`0 scan` needs no sign-in and no desktop. In a CI job it starts its own console, scans, writes the report and stops the console. It needs a model connection: on a runner, an API key in the environment. `OPENAI_API_KEY` works with the default model. See [Models](/models/) for other providers.

```yaml
name: scan
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * *"
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://raw.githubusercontent.com/0sec-labs/0security/main/install.sh | bash
      - run: ~/.0/bin/0 scan . --format sarif -o scan.sarif --fail-on high --budget 3
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scan.sarif
```

`--fail-on high` fails the job when a finding is `high` or worse. The exit code is `3` when the budget or time ran out, and the report is partial. `if: always()` uploads the report either way.

The SARIF has paths relative to the repository root, the category as the rule, and a location-based key. Findings attach to the right lines in code scanning wherever the runner checked out the code.

Plan for these:

- A scan stops at `--budget` (default 5). Small projects cost cents and take about a minute. A large one takes minutes and uses the budget. Run it on pushes to the main branch or nightly, not on every pull request.
- Two runs on the same commit do not find exactly the same set. Serious issues come up reliably, the rest less so. A green scan is not proof.
- `--passes 3` runs the scan three times at once, each with a third of the budget, and merges the findings. Each finding says how many passes found it. One that all passes found is the most certain.
- To pin the version, download a release binary and its `checksums.txt` from the [releases page](https://github.com/0sec-labs/0security/releases). `install.sh` installs the latest.

## Import findings from another scanner

Import a SARIF 2.1.0 file, or read a repository's alerts from GitHub. Nothing in the file is executed.

```bash
0 findings import ./other-scanner.sarif --tool "Other scanner"
0 findings import --github acme/app --types code-scanning,dependabot
```

Each result becomes a finding that keeps the scanner's name, rule, severity, CWE, file and line. Importing the same file again changes nothing. Imported findings are marked discovered and unverified.

`--github` runs `gh api` with your own `gh auth login` session. The 0 GitHub connector is not used. Secret alerts record the type and validity, never the secret value. Use `--state` (`open`, `dismissed`, `fixed` or `all`) and `--ref` to narrow the alerts.

Stop a running console on the same database before you import. See [findings import](/commands/#findings-import) for every option.

## Fix a finding

0 fixes a finding in a separate git work tree, so your checkout is never touched. It runs your checks, commits on a branch named `0/fix-<id>` and opens a pull request. The pull request is a draft when a check fails.

```bash
0 findings fix 3f2a --test "npm test"
```

Nothing is pushed to the base branch and nothing is merged. Running the command again updates the same pull request. It edits files on this machine, so it needs the local console.

To work through many findings, batch them. Each gets its own branch and pull request, and you get a report:

```bash
0 findings burndown --severity high,critical --test "npm test" --dry-run
```

Drop `--dry-run` to start. A re-run skips findings that already have a pull request. See [findings fix](/commands/#findings-fix) and [findings burndown](/commands/#findings-burndown) for the policy file, budgets and stop rules.

## Export and share

Export saved findings as JSON, Markdown or SARIF:

```bash
0 findings list 3f2a 91bc --format sarif -o findings.sarif
0 findings list --format md -o report.md
```

Without `-o` the report goes to stdout. `0 findings export` also writes HTML and PDF. The app exports all five formats.

A full report carries evidence, proof-of-concept steps and descriptions that can quote source code or secrets. Check it before you share it.

To bring a report into the app, use `0 findings list --import ./report.json --db-path <db>`. Imported findings are marked discovered and unverified.

## Send findings to GitHub

Mirror findings into a repository's issues, so the team triages them next to the code:

```bash
0 findings issues --repo acme/app --dry-run     # print the plan, change nothing
0 findings issues --repo acme/app               # create and sync issues (needs `gh` signed in)
```

Each finding gets one issue, matched on later runs by a hidden marker in its body, so a re-run updates and never duplicates. Accepted, suppressed and fixed findings close their issue with a comment. A finding that comes back reopens it.

`--min-severity` (default `medium`), `--max` (default 25 changes per run) and `--delay` keep it inside rate limits.

An issue holds only the title, severity, category, location, the attacker-impact sentence and the status. Evidence, requests, responses and proof-of-concept steps are never copied, because they can quote code or secrets. Read them locally with `0 findings show <id>`. Report text is neutralised, so a finding cannot mention a person or reference another issue.

To show findings in the Security tab instead, upload a SARIF file:

```bash
0 findings upload scan.sarif --repo acme/app
```

## Collect evidence and report an exploited vulnerability

Write findings with triage state, SARIF, an SBOM and fix branches into one folder. The folder has a README that says what it does not show.

```bash
0 findings evidence ./evidence --repo .
```

To draft a report about an actively exploited vulnerability for a person to review and submit:

```bash
0 findings report-draft 3f2a --stage early-warning
```

Stages are `early-warning`, `notification` and `final`. Neither command claims compliance. See [Collect evidence and draft vulnerability reports](/ci/#collect-evidence-and-draft-vulnerability-reports).

## Limits

- A finding without reproduced evidence is a lead. Check its status and evidence before you report it.
- Fingerprint grouping can merge or split issues imperfectly. Findings without a fingerprint stay separate.

