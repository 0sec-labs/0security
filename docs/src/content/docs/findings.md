---
title: Findings
description: Review, triage, verify and export findings in the browser app or from the CLI.
---


A finding is a security issue that a thread or Sentinel recorded, with its evidence. Review findings in the app or the CLI, accept or dismiss them, verify them, and export or fix them.

0 groups duplicates of the same issue into one family by fingerprint, so a decision on one occurrence applies to all of them.

## Review findings in the app

Open **Findings** in the sidebar. The page has these views: **All**, **Needs review** and **Closed**, as a list or a board. Search, or filter by severity and status.

Select a finding to open its detail panel. It shows the evidence (request, response, analysis and artifacts), severity, triage state and the thread it came from.

- Set the work state to **Backlog**, **Todo**, **In progress**, **Blocked**, **Done** or **Cancelled**. 0 sets **Needs your review** and **Agent review**. Until you confirm a finding that needs review, you can only move it to **Done**, **Cancelled** or **Accepted**.
- Choose **Accept** or **Dismiss**, with an optional note. **Undo** resets the finding to not reviewed.
- Choose **Verify in a thread**, **Fix in a thread** or **Investigate in a thread**, depending on the finding's state. **Terminal command** shows the same step for the CLI.
- Select several findings to change status, **Dismiss**, **Export** or **Add to thread**.
- Choose **Export finding** in the panel, or **More actions** for the current list. Formats are JSON, Markdown, HTML, SARIF and PDF.

Each finding has a stable link at `/findings/<fingerprint>`.

## List and inspect findings

```bash
0security findings
0security findings --severity high --triage new
0security findings show 3f2a
```

`0security findings` is the same as `0security findings list`. It reads the local findings database and groups duplicates. Add `--all` for raw rows. An ID can be a unique prefix.

| Filter | Values |
|---|---|
| `--severity` | `critical`, `high`, `medium`, `low`, `info` |
| `--status` | `discovered`, `verified`, `confirmed`, `scored`, `reported`, `fixed`, `false-positive` |
| `--triage` | `new`, `accepted`, `suppressed` |
| `--category` | An attack category |
| `--scope` | `in` (not labelled out of scope), `out` (only those), `all` (default) |
| `--limit <n>` | Default 50 |

A group is one flaw. Groups that cite the same file, the same category and overlapping lines are shown as one, with a count of how many were merged. Groups with a different triage state stay apart.

## Finding categories

Each finding has one category. It names the kind of flaw, not where it showed up. The category is the SARIF rule id, the value `--category` filters on, and part of the issue label.

The model picks a category when it records a finding. If it picks a catch-all (`missing-validation`, `other`, `security-misconfiguration`, `information-disclosure`) or a label that is not on the list, 0 files the finding under the class its CWE or title names. A broken ownership check filed as `missing-validation` becomes `broken-access-control`. A specific category the model chose is kept. The model's own label stays on the finding.

| Category | What it is | Usual CWE |
|---|---|---|
| `broken-access-control` | A missing or wrong authorization check, IDOR, no role check, a destructive route anyone can call | 284, 285, 306, 639, 862, 863 |
| `broken-authentication` | Session fixation, a weak password policy, user enumeration, authentication bypass | 204, 287, 384, 521, 613 |
| `mass-assignment` | A request sets fields it should not, such as an admin flag at registration | 915 |
| `csrf` | A state-changing request with no anti-forgery check | 352 |
| `open-redirect` | A redirect to an address the caller chooses | 601 |
| `xxe` | An XML parser that resolves external entities | 611 |
| `hardcoded-secret` | A key, signing secret or credential in source, or a seeded default account | 259, 321, 798 |
| `insecure-randomness` | A predictable token, id or seed | 330, 338, 340 |
| `insecure-storage` | A password or sensitive value stored in plaintext | 256, 312, 522 |
| `insecure-transport` | Data or a database link sent without TLS | 295, 319, 523 |
| `missing-rate-limit` | No limit on attempts, so codes or passwords can be guessed | 307, 799 |
| `sql-injection`, `command-injection`, `code-injection`, `path-traversal`, `xss`, `ssrf`, `unsafe-deserialization`, `prototype-pollution`, `regex-dos`, `cors` | Injection and request classes | 89, 78, 94, 22, 79, 918, 502, 1321, 1333, 942 |
| `information-disclosure`, `security-misconfiguration`, `crypto-misuse`, `denial-of-service`, `missing-validation` | General classes, used when nothing more specific fits | 200, 16, 327, 400, 20 |
| `known-vulnerable-package`, `supply-chain`, `policy-violation` | Dependencies, build pipelines and written rules | 1104, 829 |
| `prompt-injection`, `jailbreak`, `system-prompt-extraction`, `data-exfiltration`, `tool-misuse`, `output-manipulation`, `encoding-bypass`, `multi-turn` | Attacks on AI applications | |
| `heap-overflow`, `out-of-bounds-read`, `out-of-bounds-write`, `use-after-free`, `stack-buffer-overflow`, `null-pointer-deref`, `null-deref`, `integer-overflow`, `integer-truncation`, `race-condition`, `toctou`, `type-confusion`, `double-free`, `format-string`, `uninitialized-memory` | Memory safety and concurrency | |
| `other` | Nothing above fits | |

A report merges findings that two passes or batches filed for one flaw. It merges when the file and the category (or a shared CWE) agree and the cited lines overlap. Findings in different files or categories are never merged. The merged finding keeps the highest severity and lists the ids it absorbed.

`0security findings show` prints the title, what an attacker can do (when the scan assessed it), severity, CVSS when present, status, triage state, evidence and related occurrences.

To read another database, add `--db-path`:

```bash
0security findings show 3f2a --db-path ./engagement.db
```

## Triage a finding

Status and triage are separate. Status is what the automation established: `discovered` is a candidate, `verified` and `confirmed` passed a verification step, and `false-positive` was rejected. Triage is your decision: `new`, `accepted` or `suppressed` (shown as **Dismissed** in the app).

Accepting a finding does not verify it, and suppressing it does not make it false.

```bash
0security findings update 3f2a --status suppressed --note "Test-only endpoint"
0security findings update 3f2a --status open
```

`--status open` resets the finding.

### Accept a risk

Accepting a risk records that you know about a finding and will live with it for a set time. It needs a reason and an expiry. Name the approver if your process needs one.

```bash
0security findings update 3f2a --status accepted --reason "Fix scheduled for the next release, ticket SEC-142" --expires 90d --approver "security lead"
```

`--expires` takes a date such as `2026-12-31` or a number of days such as `90d`. When the date passes, the finding is open again in lists, in exports and in the next scan. See the ones that end soon:

```bash
0security findings list --expiring 30
```

`0security findings list` shows `accepted until <date>` next to an accepted risk. The approver is a label you type. 0 does not check it against a login, so treat it as a note for your records, not as proof of who approved. Every change is also written to the audit log (`0security config get audit`).

JSON, Markdown and `0security findings evidence` carry the reason, expiry and approver. SARIF exports add a `suppressions` entry with `kind` external, status accepted and your reason as the justification, so code scanning tools hide the result while the acceptance lasts.

### Mark a false positive

A false positive is suppressed with your reason, and it stays suppressed across scans of the same code.

```bash
0security findings update 3f2a --status false-positive --reason "Echo endpoint only exists in test fixtures"
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
0security threads start "Harden the workflows" --folder . --skill workflow-hardening --wait
```

A planted unpinned action must be flagged first, so a configuration that turns the detector off reads as Not verified.

## Proof by reproduction

A finding can carry a proof: steps that show the problem. The proof has two parts that are never mixed up.

Proposed steps come from the model's own reasoning. The app, `0security findings show`, reports and SARIF label them "Proposed steps, not run". Nothing has checked them.

A reproduction result exists only when a harness ran a recipe against a local copy of the app in a container. The result records the commit, the digest-pinned image, a hash of the app files, a canary, the times and a redacted log tail. The app shows it as "the app as run returned the canary for this request, on commit X in an isolated container". That is an observation of the running app. It does not say the vulnerability exists in the code, and an app built to lie can fake it. A run outside the container is marked unisolated and can never be reproduced. The model cannot set it, and neither can a finding import. Stored text that lacks the full record is ignored.

A result has one of four states:

- reproduced: the canary appeared.
- not-reproduced: the canary did not appear.
- inconclusive: the run could not show either.
- error: the run did not happen.

Not reproduced does not mean safe. It means this recipe did not work on this commit under these conditions. The app may need other input, other state or another route. Keep the finding open until you have read the code.

The proof never changes a finding's severity, status or triage. It is stored next to the finding. Findings saved before this existed have none.

### Reproduce a path traversal locally

`0security findings reproduce` is experimental. It runs a finding's proposed request against a copy of your app in a container, then records the result. It needs Docker or podman and a Node app that starts with `node server.js`, or with the command you pass.

Pin the image by digest. This runs the committed tree of the folder:

```bash
0security findings reproduce 3f2a --image node:24-bookworm-slim@sha256:<64 hex digits> --folder ~/code/app
```

Use `--start "node app.js"` when your app starts another way. The command comes from you. 0 never reads start commands from the repository.

The harness plants a canary file outside the folder the app serves and replays the finding's request against it. If the canary comes back, the result is reproduced. Run it again after a fix and the result should change to not reproduced. Not reproduced does not prove the fix: it means this request found nothing.

Only path traversal on an HTTP GET route is supported. The request goes to the loopback inside the container, never to a live address. The container step is untested against a real runtime. Tests start the fixture app on the host with a stand-in for the container.

## Scan a folder

```bash
0security scan ./your-repo
0security scan https://github.com/acme/app --budget 2 --format json -o scan.json
0security scan ./your-repo --format sarif -o scan.sarif --fail-on high
```

A scan is a thread that follows the `scan` skill. It lists every entry point, checks each one and records what it can show from the code. The thread appears in `0security threads` and its findings in `0security findings`.

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
| `--batches <mode>` | `auto` (default) reviews a large folder in batches, `on` always does, `off` keeps one thread. See [Large repositories](#large-repositories). |
| `--batch-size <n>` | Entry points one batch reviews (default 8). |
| `--concurrency <n>` | Batches that run at the same time, up to 3 (default 1). |
| `--resume <scan>` | Continue the entry points an earlier scan did not reach. |
| `--coverage [scan]` | Print what an earlier scan reviewed and exit. |
| `--allow-partial` | Exit by the findings alone when the scan stops before it reviews everything. The report still says it is partial. |
| `--plan` | List the entry points, batches and a rough cost, then exit. Calls no model and writes nothing. |

Exit codes: `0` done, `1` a finding at or above `--fail-on` or the scan failed, `2` usage error, `3` not finished: stopped at the budget or the time limit, or entry points were not reached (the report is partial; this is not a failure). `--allow-partial` makes a partial scan exit 0, or 1 with `--fail-on`.

`0security scan` uses the console that is running, or the engine named by `--engine-url` or `--computer`. With none running it starts one and stops it afterwards.

The scan needs a model with working tool calls. In one test, a small model sent most `finding` calls without their title and evidence. Results also vary between runs, so a clean scan is not proof that nothing is there.

### Large repositories

One thread cannot review every entry point of a big repository, and it cannot tell you what it skipped. With more than 8 entry points, or more than 150 source files, `0security scan` splits the work:

1. It lists the entry points without calling a model: routes and handlers (Express, Fastify, Koa, Next, Flask, FastAPI, Django, Go, Spring, Rails, PHP), webhooks, queue and cron consumers, program mains, and the places that deserialize data, accept uploads or run commands. It skips what `.gitignore` ignores and vendored or build folders, and runs nothing from the folder.
2. Source files no pattern matches are grouped by folder, so every source file belongs to a group. Entry points are reviewed first.
3. It runs one thread per batch of entry points, one after another. Each thread gets its batch, a short summary of the whole folder, and your `--context` and `--policy` text. The budget left is split between the batches not yet run, with a small minimum.
4. A batch counts as reviewed only when its thread finished normally. A batch that stopped at its budget, hit a time limit or failed stays pending.
5. A batch that fails because the connection dropped or the provider timed out, was rate limited or returned a server error runs again, up to 2 times (`--retries`). The failed attempt's findings are kept and its cost counts against the budget. A batch that runs past 900 seconds (`--batch-timeout`) is cancelled and stays pending with the reason `timeout`. The next batch still runs.
6. A batch counts as reviewed for the units whose files its thread opened. If the thread skipped files, 0 asks it in the same thread to open them once (`--coverage-rounds`). A unit whose files stay unopened stays pending with the reason `not opened`, and `--resume` runs it again.

### Large Java projects

In a Maven or Gradle project, each batch stays inside one build module. A module is a directory with a `pom.xml`, `build.gradle`, `build.gradle.kts` or `settings.gradle` file. A file belongs to its nearest such directory. 0 checks only that these files exist. It does not read them.

Batches run module by module, in alphabetical order of the module path. Inside a module, entry points are batched in path order, so files of one package sit together. Each batch prompt names its module.

Run `--plan` to see the module map, with the files, entry points and batches of each module:

```bash
0security scan ./my-project --plan
```

`--resume` plans the units still pending by module again, so a later run continues module by module. It needs the same git HEAD, as for any resumed scan.

Limits: a module is not split by package, only ordered by it. 0 does not read `CODEOWNERS` or the module list in a `pom.xml`. Directories with no build file above them form one group of their own.

The report says plainly how much was reviewed:

```text
reviewed 41 of 57 entry points; 16 not reached (budget)
```

In JSON this is a `coverage` object with the counts, the counts by kind and the first entry points not reached. SARIF carries it in the run's `properties`. The exit code is 3 whenever anything is not reached, so a pipeline cannot read a partial review as a full one. Exit 3 means the scan is not finished. It does not mean the scan failed, and the findings so far are kept. A folder with no findings and entry points not reached has not been shown to be clean.

A job that should not fail on a partial scan adds `--allow-partial`. The exit code then follows the findings alone (0, or 1 with `--fail-on`). The JSON `status` is `partial` and `coverage` stays in the report, so nothing reads it as a full review.

When a scan stops early, it prints what stopped it, how much is left and the exact command that continues it. The same text is in the Markdown report, and in JSON as `coverage.stoppedBy` and `coverage.resume`.

```text
Stopped by the $5 budget; 16 of 57 entry points not reached.
Continue with: 0security scan /home/you/code/app --resume scan-1f3a9c
```

Run that command, or use `latest` for the newest scan of the folder. Read the ledger with `--coverage`:

```bash
0security scan ./your-repo --resume latest
0security scan ./your-repo --coverage
```

To see the size of a scan before you run it, use `--plan`. It lists the entry points by kind, the batches `--batch-size` would make, whether `--batches auto` would batch the folder and a rough cost range. It calls no model and no scanner, and writes nothing. `--format json` prints the same as JSON.

```bash
0security scan ./your-repo --plan
```

The cost is a guess. It scales one measurement: about $0.035 per batch on a 40-file test app. Cost for large repositories is not measured. It varies 2 to 3 times with the code and the model, and larger files cost more, so treat the range as an order of magnitude and set `--budget` to what you accept to spend.

`--resume` runs only the pending entry points and reports the findings of every thread of that scan. It refuses when the folder's git HEAD changed since the scan began; `--force` continues anyway. `--coverage` prints the ledger: every unit with its status and the reason it was not reached.

The ledger is kept in the local findings database, so `--resume` and `--coverage` work from the machine that ran the scan. `--batches off` keeps one thread and prints no coverage. `--passes` and `--diff` do not combine with `--resume`, and `--passes` does not combine with `--batches on`.

The patterns over-match on purpose, and they cannot see a framework they do not know. A route they miss still falls into a group of other files, but that group gets less attention than an entry point.

### Read the JSON report

The JSON report has `schemaVersion: 1` and these fields:

- `status`: `complete`, `partial`, `budget_exhausted`, `timed_out` or `failed`. `partial` means entry points were not reached for a reason other than the budget or time limit. With `--allow-partial`, every early stop is `partial`; `coverage.stoppedBy` says why.
- With batches: `coverage` (`complete`, `statement`, `entryPoints` and `otherGroups` with `total`, `reviewed`, `pending` and `skipped`, `byKind`, `notReached`, `pendingUnits`) and every batch's `threadIds`.
- When the scan failed or stopped early: `failure` with a `cause` and a plain `message`, and `error` with the thread's own text. With batches, `coverage.retries` (retries allowed and used, and the cause of each) and `coverage.failures` (the batches that stayed pending, with the cause).
- `counts` by severity, and the model's closing `summary`.
- `warnings`: present when a scan found nothing and its tool calls never named some source files. It lists the files that were not opened. The status stays `complete`: the check reads the commands the model ran, so it can miss a file read by a method it does not recognise. Run the scan again, or use `--passes 2`.
- `target`: the folder's name, or the git URL without credentials. It is the same on every machine.
- With `--passes`: `passes` (asked for, finished, failed) and every pass's `threadIds`.
- For each finding: `severity`, `category`, `location` (path relative to the scanned folder, with start and end line), `evidence`, and `foundInPasses` with `--passes`. `cvssScore` and `suggestedFix` appear when the scan gave them.

A finding's `fingerprint` is a hash of its file and first line, so the same place in unchanged code keeps it from scan to scan. It is absent when the finding cites no location. A model does not cite exactly the same lines every run, so match findings between scans by file and nearby lines.

Get the same report later, in any format:

```bash
0security findings export --scan <thread id>
```

### Label findings by declared scope

```bash
0security scan . --scope SECURITY.md --fail-on high --format json
```

A finding that matches a vector the `## Scope` section of SECURITY.md lists as out of scope gets `scope: "out-of-scope"`, `scopeReason` and `scopeSource`. In the JSON report, `counts` covers the findings that are not labelled, `outOfScopeCounts` counts the labelled ones, and `scope` names the file and the vectors. Labelled findings stay in `findings`, after the others. They do not count toward `--fail-on`. When findings are in classes you have not declared, a scan on a terminal ends with one line that points to `0security threat-model --interview`. See [Declare what is in and out of scope](/threat-model-and-policy/#declare-what-is-in-and-out-of-scope).

### Plan a cryptography migration

`--skill crypto-migration` lists every cryptographic use: algorithm, key size, library, call site and what the output feeds. It separates quantum-vulnerable public-key crypto (RSA, ECDH, ECDSA, EdDSA) from weak classical crypto (SHA-1, MD5, DES, ECB, static IVs, hardcoded keys). It records one finding per site with a minimal `suggestedFix`.

```bash
0security scan ./your-repo --skill crypto-migration --format json -o crypto.json
```

The closing `summary` holds a migration plan: rollout order, key and data migration, versioned formats, hybrid mode (for example X25519 with ML-KEM-768) and tests. The skill does not install a post-quantum library or invent function names. Where it could not check a library's API in your code, the finding says so.

Fix one site at a time, each as a pull request (see [Fix a finding](#fix-a-finding)). Review each against the plan. A change to a wire or stored format needs the other side to accept both versions first.

### Scan a built artifact

`0security scan` reads a folder. Unpack the artifact into a new empty folder first, without running anything from it:

```bash
mkdir /tmp/artifact && cd /tmp/artifact
npm pack acme-utils@2.3.1 && tar -xzf acme-utils-*.tgz --no-same-owner   # npm package
pip download --no-deps --only-binary :all: acme-utils==1.0 -d . && unzip -q ./*.whl -d unpacked   # Python wheel
unzip -q app.jar -d unpacked                                                                   # jar
docker save acme/app:1.0 -o image.tar && mkdir image && tar -xf image.tar -C image             # image layers and config
mkdir rootfs && docker create --name tmp-export acme/app:1.0 && docker export tmp-export | tar -x -C rootfs   # image filesystem
docker rm tmp-export
0security scan /tmp/artifact/package --skill artifact-scan --budget 1   # the unpacked folder
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

It runs `0security sbom generate` and `0security sbom check` on the folder, and `syft`, `trivy`, `file`, `strings`, `readelf` and `jq` if they are installed. It never executes anything from the artifact.

In a test on a planted npm package, the skill found all four planted problems in one run and three in another. A general scan found two. A clean result is not proof. Read what the summary says it could not check.

### Scan in CI

`0security scan` needs no sign-in and no desktop. In a CI job it starts its own console, scans, writes the report and stops the console. It needs a model connection: on a runner, an API key in the environment. `OPENAI_API_KEY` works with the default model. See [Models](/models/) for other providers.

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
0security findings import ./other-scanner.sarif --tool "Other scanner"
0security findings import --github acme/app --types code-scanning,dependabot
```

Each result becomes a finding that keeps the scanner's name, rule, severity, CWE, file and line. Importing the same file again changes nothing. Imported findings are marked discovered and unverified.

`--github` runs `gh api` with your own `gh auth login` session. The 0 GitHub connector is not used. Secret alerts record the type and validity, never the secret value. Use `--state` (`open`, `dismissed`, `fixed` or `all`) and `--ref` to narrow the alerts.

Stop a running console on the same database before you import. See [findings import](/commands/#findings-import) for every option.

## Dependencies

Check the packages your project uses against known advisories, import the results as findings, and fix them with a version bump.

```bash
0security sbom generate . -o sbom.cdx.json
0security sbom check sbom.cdx.json --format sarif -o deps.sarif
0security findings import deps.sarif
```

Each finding is one package and one advisory. It shows the severity, the fixed version and the lockfile it came from. A malicious package is a critical finding.

To bump a package, fix the finding:

```bash
0security findings fix 3f2a --test "npm test"
```

The fix raises the package to the lowest fixed version in the manifest, and refreshes the lockfile with your project's own package manager when it is installed. It changes nothing else.

For a Maven or Gradle project, add `--resolve` to get the transitive packages and the versions your build picks. This runs your `mvn` or `gradle`, so it asks first. See [sbom generate](/commands/#resolve-maven-and-gradle-dependencies).

```bash
0security sbom generate . --resolve --allow-build-tools -o sbom.cdx.json
```

For a Maven fix, 0 changes the version where it is set: the pom, a property, or a `dependencyManagement` entry. For Gradle it changes the version catalog or a literal in the build script. It uses the lowest fixed version from the finding and never invents one. It never lowers a version.

When the repository sets the version itself, 0 makes this edit without a model call, and the pull request says so. When the version comes from a parent POM or BOM outside the repository, a variable, a range or a transitive package, a model makes the change with the `java-dependency-fix` skill. Check the result with your own build:

```bash
0security findings fix 3f2a --test "mvn -q test"
```

To estimate whether your code calls the vulnerable part, run the experimental `dependency-reachability` skill. Give it the advisories as context. This is two commands, because the scan needs a model and `0security sbom check` does not:

```bash
0security sbom check sbom.cdx.json --format json -o advisories.json
0security scan . --skill dependency-reachability --context advisories.json
```

Each advisory gets a verdict: reachable, not-reached or cannot-tell, with the file and line it rests on. The verdict is a model's reading of the code, not a proof. It can be wrong in both directions, and not-reached does not mean safe. See [scan a folder](#scan-a-folder) for the scan options.

On one planted Node app (an old lodash with one vulnerable function called, and an old package imported but never used), seven advisories got six correct verdicts and one cautious cannot-tell in the second run. The first run recorded only five of the seven. That is one small fixture and two runs, so it says nothing about accuracy on your code.

Add `--outdated` to `0security sbom check` to list newer versions. These are notes, not findings.

## Check findings for false positives

`0security findings verify` is experimental. It re-checks findings with a fresh thread for each one. The thread gets only the finding's own text, reads the code itself, and tries to build a concrete attack. It stores a verdict next to the finding: true-positive, false-positive, fixed, uncertain or duplicate.

Pass the folder that was scanned, so the threads can read the code:

```bash
0security findings verify --severity high,medium --folder ~/code/app
```

`0security findings list` and `0security findings show` then print a line such as `verified: likely false positive`. The verdict is advice. The finding's severity and status do not change, and the thread's own severity is stored apart as an advisory severity. A thread that returns no verdict is recorded as uncertain.

To suppress what the threads call false positives, add `--apply`:

```bash
0security findings verify --apply --folder ~/code/app
```

With `--apply`, critical and high findings are never suppressed: a person decides those. A finding of lower severity is suppressed only when the verdict is false-positive and it cites a control at `path:line` that exists in the folder. The suppression note starts with `False positive (model-verified):`. Undo it with `0security findings reopen`. Without `--apply`, no status ever changes.

A re-run skips findings that already have a verdict. Add `--force` to check them again. The model can be wrong in both directions, so read the reasoning in `0security findings show` before you rely on a verdict. See [findings verify](/commands/#findings-verify) for budgets and stop rules.

## Fix a finding

0 fixes a finding in a separate git work tree, so your checkout is never touched. It runs your checks, commits on a branch named `0/fix-<id>` and opens a pull request. The pull request is a draft when a check fails or when you gave no `--test`. Add `--ready` to open it ready for review without checks.

```bash
0security findings fix 3f2a --test "npm test"
```

Nothing is pushed to the base branch and nothing is merged. Running the command again updates the same pull request. It edits files on this machine, so it needs the local console.

To work through many findings, batch them. Each gets its own branch and pull request, and you get a report:

```bash
0security findings burndown --severity high,critical --test "npm test" --dry-run
```

Drop `--dry-run` to start. A re-run skips findings that already have a pull request. See [findings fix](/commands/#findings-fix) and [findings burndown](/commands/#findings-burndown) for the policy file, budgets and stop rules.


### Match your pull request conventions

Set a title template, branch prefix, labels, reviewers, a draft rule and a footer in your policy file, so fix pull requests follow your process. See [pull request conventions](/commands/#pull-request-conventions).

### Show how many fixes were accepted

After a fix or a burndown, write a report of the outcomes:

```bash
0security findings export-fixes --check-merged -o ./fix-report
```

It lists each fix with its pull request and checks, and counts how many were merged. See [findings export-fixes](/commands/#findings-export-fixes).

### Count findings across repositories

Write one export per repository, then roll them up:

```bash
0security findings rollup --export api.json --repository api
0security findings rollup api.json web.json --format html -o rollup.html
```

The result counts open findings by severity, category, age and owner. See [findings rollup](/commands/#findings-rollup) for the export format and the counting rules.

## Verified fixes

A verified fix is a fix whose checks ran in a container with no network. The pull request says so only when every check passed there.

```bash
0security findings fix 3f2a --test "mvn -q test" --sandbox docker --sandbox-image maven:3-eclipse-temurin-21
```

Without `--sandbox`, your `--test` commands run on your machine with your privileges. They can read your files and use your network. With `--sandbox docker`, 0 copies the fix work tree into a folder without its git data and runs each command in a container from the image you name. The container has:

- no network
- 4 GB of memory, 2 CPUs and 1024 processes
- no Linux capabilities, and no new privileges
- none of your environment variables
- a 10 minute limit and 4 MB of output

When a check passes, the pull request body reads "Verified in a sandbox: maven:3-eclipse-temurin-21, network off." A failed check makes the pull request a draft, as without a sandbox. A Docker error is a failed check, never a pass. The work tree on your machine does not change while the checks run.

The model is told not to run builds or tests itself in this mode. It edits files, and the sandbox runs the checks.

The image must hold the tools and the dependencies the tests need, because the container has no network. Build an image with your dependencies cached in a folder any user can read. Or pass `--sandbox-network` to let the container download dependencies. The network is then on, and the pull request says "network on". `ZERO_ENTERPRISE` refuses `--sandbox-network`.

### Download dependencies first

To keep the checks offline without building your own image, add a setup step. It runs once with the network on and downloads dependencies into a cache. The checks then run with the network off and reuse the cache.

```bash
0security findings fix 3f2a \
  --sandbox docker --sandbox-image maven@sha256:<digest> \
  --sandbox-setup "mvn -q dependency:go-offline" \
  --test "mvn -o -q test"
```

Before the checks, 0 runs a canary in the same container settings. It passes only when the container has no network interface other than loopback. If setup or the canary fails, the checks do not run and the pull request is a draft. The cache folder is deleted when the run ends. `ZERO_ENTERPRISE` refuses `--sandbox-setup`, and you cannot combine it with `--sandbox-network`.

Name the image by digest to pin it. A tag such as `maven:3-eclipse-temurin-21` can change. The pull request says whether the image is pinned. Get a digest with `docker buildx imagetools inspect <image>`.

The first run pulls the image if it is not on your machine. A Maven JDK image is several hundred megabytes, so the Docker VM needs that much free disk. A full disk makes the pull fail, which counts as a failed check.

Docker pulls the image when it is not on your machine. Use a local image if nothing may be pulled. On macOS and Windows, Docker runs in a VM, so 0 copies the work tree under `~/.0/sandbox`. Set `ZERO_SANDBOX_DIR` to another folder your VM shares.

Limits:

- The sandbox is Docker's isolation. A flaw in Docker is outside what this gives you.
- The setup step and canary were run for real with an Alpine Node image. A Maven image was not run for real, because the Docker VM had no disk for the pull.
- Disk use inside the container is not limited.
- The checks run in a copy, so files they write (such as build output) are not in the commit.
- Only the `docker` mode exists. Private-repository credentials are not passed into the container.
- `0security findings burndown` does not take `--sandbox`.
- The mechanism was tested with a real container (an Alpine Node image, no network). The Maven image was not run for real in this build, only through a fake `docker`.

## See what runs cost

Each scan, fix and verify run records its cost, duration and counts on your machine. Read the summary with:

```bash
0security findings metrics --since 7d
```

It shows cost per proposed fix and the share of proposed fixes whose checks passed. Add `--command fix` to look at one command, or `--by week` or `--by model` to compare weeks or models. To export, add `--format json`, or `--format csv` with `--by`. See [findings metrics](/commands/#findings-metrics).

To give a command a default budget and model, set them per workflow in your [settings file](/configuration/#set-a-budget-and-model-per-workflow). A flag on the command line wins.

## Export and share

Export saved findings as JSON, Markdown or SARIF:

```bash
0security findings list 3f2a 91bc --format sarif -o findings.sarif
0security findings list --format md -o report.md
```

Without `-o` the report goes to stdout. `0security findings export` also writes HTML and PDF. The app exports all five formats.

A full report carries evidence, proof-of-concept steps and descriptions that can quote source code or secrets. Check it before you share it.

To bring a report into the app, use `0security findings list --import ./report.json --db-path <db>`. Imported findings are marked discovered and unverified.

## Send findings to GitHub

Mirror findings into a repository's issues, so the team triages them next to the code:

```bash
0security findings issues --repo acme/app --dry-run     # print the plan, change nothing
0security findings issues --repo acme/app               # create and sync issues (needs `gh` signed in)
```

Each finding gets one issue, matched on later runs by a hidden marker in its body, so a re-run updates and never duplicates. Accepted, suppressed and fixed findings close their issue with a comment. A finding that comes back reopens it.

`--min-severity` (default `medium`), `--max` (default 25 changes per run) and `--delay` keep it inside rate limits. Findings labelled out of scope by a declared scope get no issue; `--include-out-of-scope` opens issues for them too.

An issue holds only the title, severity, category, location, the attacker-impact sentence and the status. Evidence, requests, responses and proof-of-concept steps are never copied, because they can quote code or secrets. Read them locally with `0security findings show <id>`. Report text is neutralised, so a finding cannot mention a person or reference another issue.

To show findings in the Security tab instead, upload a SARIF file:

```bash
0security findings upload scan.sarif --repo acme/app
```

Results labelled out of scope are left out of the upload. Add `--include-out-of-scope` to send them.

## Collect evidence and report an exploited vulnerability

Write findings with triage state, SARIF, an SBOM and fix branches into one folder. The folder has a README that says what it does not show.

```bash
0security findings evidence ./evidence --repo .
```

To draft a report about an actively exploited vulnerability for a person to review and submit:

```bash
0security findings report-draft 3f2a --stage early-warning
```

Stages are `early-warning`, `notification` and `final`. Neither command claims compliance. See [Collect evidence and draft vulnerability reports](/ci/#collect-evidence-and-draft-vulnerability-reports).

## Limits

- A finding without reproduced evidence is a lead. Check its status and evidence before you report it.
- Fingerprint grouping can merge or split issues imperfectly. Findings without a fingerprint stay separate.

