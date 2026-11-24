# Changelog

All notable changes to 0 (the open-source CLI) are tracked
here. The history before v0.11.0 lives in the git log and on the GitHub
Releases page; this file starts the human-readable summary from v0.11.0
onwards. Entries before v0.13.0 predate the pwnkit → 0 rename and keep the
old product name as written.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and 0 adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
on the GitHub Release tag.

## [Unreleased]

- `0security findings fix` now records its pull request in the same file as burndown, so `0security findings export-fixes` covers single fixes too. The report also gives the summary for each repository (`workspaces` in the JSON, a table in the Markdown), and the schema is documented.
- `0security findings rollup` counts open findings across repositories by severity, category, age and owner, in text, JSON or HTML. It reads rollup export files (`--export` writes one) and findings databases, and sends nothing. Fixed, false-positive, accepted and suppressed findings are left out of the open count.
- The web console and the docs site both render Mermaid diagrams with Mermaid 12. A leftover override had pinned both to version 11.
- Sentinels have a signed `webhook` trigger. Another system calls `/api/webhooks/trigger/<trigger-id>` in server mode and proves it with GitHub's `X-Hub-Signature-256`, Bitbucket's `X-Hub-Signature`, GitLab's `X-Gitlab-Token` or `X-0-Signature-256` with a timestamp. Each trigger has its own secret (`0security sentinels triggers secret`), the body is capped at 256 KB, and repeated deliveries start one run. Refs #430.
- The first line of `0security --help` now describes the product as a security agent (scan, fix, SBOM and evidence) instead of "security sentinels". The messages for `--chat` no longer point at a `0 chats` command that does not exist. The GitHub Action calls `0security`.
### Added

- A key-gated `enterprise/` folder in the repository, under its own license (`enterprise/LICENSE`); the rest stays MIT OR Apache-2.0 (see `LICENSING.md`). It holds an offline license check (no network, no phone home), the list of paid features and tools to issue keys. Set `ZERO_LICENSE` or `ZERO_LICENSE_FILE`, then run `0security config get license` to see the customer, seats, features and expiry. Expired keys get 30 days of grace, then paid writes stop while reading, export and verification keep working. No paid feature ships in this change.

### Changed

- The scan report is shown as readable text in a terminal (no `**`, backticks or `<details>` tags); files, pipes and `--output` still get markdown.
- The one-line description and the README headline say "open-source" instead of "sovereign".
- Every skill on the Skills page now has a topic icon: built-in skills show an icon for what they do (a terminal for command injection, a database for SQL injection, a key for secrets) instead of the 0security mark. Your own skills get an icon when their name matches a topic, and keep their initials otherwise.
- the docs, help examples, hints and error messages name the command `0security`; `0` stays as its short alias. Set `ZERO_PROGRAM_NAME=0security` or `0` to force the name that help shows (tests and docs generation).

### Fixed

- opening a thread in the web console could show only part of the conversation until you refreshed. The console kept the message list from an earlier read while newer events arrived, so a reply or a whole turn could be missing for a few seconds (longer if you opened the thread from the cache). It now re-reads the messages as soon as a turn starts or ends, trusts a cached copy only if it was read a moment ago, and still shows a turn that only the event journal knows about.
- saved threads in the web console's Threads list now show their folder under the title, like open threads do.

## [0.44.0] - 2026-11-23

### Added

- declared scope. `0 scan --scope <file>` reads the `## Scope` section of SECURITY.md (or any Markdown file): `### In scope` and `### Out of scope` lists of `- <vector>: <reason>`, with optional `(until YYYY-MM-DD)` and `[paths: globs]`. A finding in an out-of-scope vector is labelled (`scope`, `scopeReason`, `scopeSource`), listed apart after the others, and left out of the headline counts, `--fail-on` and the exit code. Nothing is hidden or deleted. Labels are stored in the findings database and carried in the JSON, Markdown, HTML, PDF and SARIF reports (as result properties; `--scope-sarif suppress` also marks them suppressed) and in the Action job summary, which counts them on a separate line. Declared in-scope vectors are listed first. 0 never reads SECURITY.md on its own: `--repo-scope` does, with a warning, and in CI you pass the base branch's copy. The Action has a `scope` input with the same trust rule as `rules` and `context`. `0 findings list --scope in|out|all` filters by label; `0 findings issues` and `0 findings upload` skip out-of-scope findings unless you pass `--include-out-of-scope`. The model is not told to skip any vector. Not measured: how much a team's declared scope changes what it fixes.
- `0 threat-model --interview`. After the draft, a model proposes up to 8 specific questions the code cannot answer (new experimental skill `scope-interview`), 0 asks them on the terminal, words one scope entry per answer from your own words, shows each entry and the diff, and asks you to confirm. Only 0 writes SECURITY.md (the entries are added to the `## Scope` lists, every other byte stays) and a `## Scope decisions` section inside a `<!-- human -->` block of the threat model. It needs a terminal (exit 2 without one). `--interview-budget` caps each interview thread (default 0.5 USD). Without a reachable model or budget it asks a fixed set of eight questions and says so. `--pr` commits both files.
- the interview asks about findings. `0 threat-model --interview` uses the latest scan of the folder from the last 30 days (or `--from-scan <report.json>`, or `--scan` to run one first with an estimated cost and a confirmation; `--scan-budget` caps it) and asks one question per class that produced findings, listing up to 5 places, the count and the highest severity. Questions from the model's reading of the code are merged by class and capped at 8, ordered by severity and then by how plausible "out of scope" is. Classes that are real vulnerabilities in nearly every app (code injection, command injection, SQL injection, hardcoded secrets, plaintext passwords, path traversal, XML external entities, unsafe deserialization and similar) are never asked about, in the skill rules and in code. A declared scope that lists one of them as out of scope now prints a warning; behaviour does not change. `0 scan` on a terminal ends with one hint line when findings are in classes with no declared scope; it prints nothing in CI, without a terminal or with a JSON report on standard output. Not measured: how many real teams find the questions useful.
- `0 threat-model --output <path>` writes the threat model to a relative `.md` path inside the folder (default `.0/threat-model.md`), for example `THREAT_MODEL.md`. The skill's human-section rule and `--pr` follow it. When SECURITY.md has a Scope section, the summary links to `SECURITY.md#scope`.
- `0 scan --coverage-rounds <n>` (default 1, 0 to 5, 0 turns it off). After a thread ends, 0 reads which source files its tool calls opened and, if some were never opened, sends the same thread a follow-up that names them. A batch's unit counts as reviewed only when its files were opened; a unit whose files stay unopened stays pending with the reason `not opened`, and `--resume` runs it again. The report has `coverage.opened`, `coverage.unopened` and `coverage.rounds` (`fileCoverage` for a scan with one thread), and the Action job summary has a "Files opened" line. Each round counts against `--budget`. In a real-app benchmark, files opened rose from 91 to 92% to 100% at 1.3 times the cost, and recall did not change beyond the spread between repeats.
- a one-thread scan that records no finding now checks which source files its tool calls named. When some were not opened, the report says "Shallow review" with the files, in the warnings of the Markdown, HTML and PDF reports, in the SARIF run properties and in a `warnings` field of the JSON report. The status stays `complete`. The check reads command text, so a file read in a way it does not recognise is listed as not opened. The Markdown line for a no-findings scan with warnings no longer mentions probe execution.
- a how-to, "Create a Sentinel with a schedule from the terminal", using `0 sentinels sync`. The `--trigger add` error for a Sentinel with no automation now names that route.
- `0 scan` recovers from transient model provider failures. A batch that fails because the connection dropped, the provider timed out, or it returned a rate limit or server error runs again, up to `--retries` times (default 2, 0 turns it off), with a jittered wait. A scan without batches asks its thread once to continue. Budget stops, refused keys, invalid requests and cancelled threads are not retried, and the cost of every attempt counts against `--budget`. `coverage.retries` in the report lists the retries.
- `0 scan --batch-timeout <seconds>` (default 900) limits one batch. A batch that passes it is cancelled and stays pending with the reason `timeout`, and the scan goes on. `--timeout` still limits the whole scan.
- A scan that fails or stops early now says why instead of "Assessment did not complete successfully": the JSON report has `failure` (a `cause` and a plain `message` without secrets), SARIF has it in the run properties, and the Markdown and HTML reports and the Action job summary show it.
- The installer now installs the command as `0security` and keeps `0` as a symlink to it. Help text shows the name you ran. An older install with only `0` gains `0security` on the next install or update. Windows keeps a single `0.exe`.
- Each release publishes the binaries as `0security-darwin-arm64`, `0security-linux-x64`, `0security-linux-arm64` and `0security-windows-x64.exe`, with identical copies under the older `0-<platform>` names so existing installs can still update. `checksums.txt` and the build attestations cover both names. The installer downloads the `0security-` name and falls back to the `0-` name when a release or mirror has only that. The release workflow now has a dry-run job that stages the assets and installs from them.
- The GitHub Action gains inputs `scanner`, `rules`, `tiers`, `known-sarif`, `only-new`, `context`, `policy`, `skill`, `allow-partial` and `mode`, and outputs `status` and `coverage`. Every input is checked in shell (no spaces, newlines or leading dashes; paths must exist and stay inside the workspace after links are resolved) and reaches `0` as a separate argument. A rules, tier, context, policy or known-results file that sits in the pull request's own code is refused for fork pull requests and `pull_request_target`, and warned about for same-repository pull requests. The job summary shows the status, the coverage sentence, the counts by severity, the tier and the new and already-known split, with no text the model wrote. `mode: sbom` generates a CycloneDX SBOM, checks it against OSV, optionally checks licenses with `licenses-preset`, uploads the advisories to code scanning and the SBOM as an artifact. A partial scan (exit code 3) now fails the job unless `allow-partial: true`; before, the action always passed it with a warning. SARIF run properties now carry the scan `status`. The Action page has examples for a pull request scan, a nightly scan, an SBOM and license check, a second opinion and a tiered scan. Checked by running the Action's shell against a local fixture with a real model scan and a local build; not run on GitHub.

### Changed

- With **Ask before running commands** (`approvals: ask`), subagents and persistent workers now ask before each command or file change. Before, approving the spawn let the helper run its own commands unprompted. An unattended Sentinel under `ask` waits for a decision on each call from its helpers; `auto` is unchanged.
- with a declared scope, the `counts` and the summary of a scan report cover only the findings not labelled out of scope; `outOfScopeCounts` counts the rest. The `threat-model` skill takes the file path from the message instead of fixing it. Without `--scope` or `--repo-scope` nothing changes.
- the Markdown report of a scan with no findings is headed "No Findings" instead of "No Vulnerabilities Found". When no pattern scanner can run, the scan prints one line saying it runs without leads and how to install one; FoxGuard now has an install hint.
- Extension scripts run with an environment built from scratch: basics plus the variables the extension declared and you approved. They no longer inherit the bash tool's environment, `TARGET` or the target-auth variables (`AUTH_HEADER`, `AUTH_VALUE`, `AUTH_CURL_FLAG`), or loader variables such as `NODE_OPTIONS`. A script that relied on one of them must now declare it.
- a fix pull request opened without any `--test` check is now a draft and says "No checks were run." Pass `--ready` to `0 findings fix` or `0 findings burndown` to open it ready for review. A pull request whose checks passed is ready, and one whose check failed is a draft, as before.
- the first-run notice and the data-flow page now say that 0 also checks GitHub for updates, and name the settings that turn it off: `ZERO_OFFLINE=1` turns off usage counts, crash reports and the update check; `ZERO_NO_TELEMETRY=1` and `ZERO_NO_UPDATE_CHECK=1` turn off one each. The README has a Privacy section.
- a scan with no findings reports "No vulnerabilities were found in the reviewed scope. A scan with no findings is not proof that the code is safe." instead of "The target passed all tests."
- the missing-key error now points to `0 models connect` and no longer ends with a misleading "Pick another with --model". The `0 findings fix` help describes its exit codes as they behave, and `--at` on a Sentinel schedule says it is a time in `--timezone` (default UTC).
- finding categories. Eleven new categories name classes that models used to file under `missing-validation`, `other` or `security-misconfiguration`: `broken-access-control`, `broken-authentication`, `mass-assignment`, `csrf`, `open-redirect`, `xxe`, `hardcoded-secret`, `insecure-randomness`, `insecure-storage`, `insecure-transport` and `missing-rate-limit`. When a model records a finding under a catch-all category or a label that is not on the list, 0 now files it under the class its CWE or title names, and keeps the model's label (`categoryLabel`). Aliases such as `idor`, `sqli` and `redos` map to their category. A specific category the model chose is kept. Existing category ids are unchanged, so saved databases and SARIF files still read. Imported SARIF uses the same CWE table, so CWE-352 imports as `csrf`, CWE-798 as `hardcoded-secret`, CWE-312 as `insecure-storage` and CWE-330 and CWE-338 as `insecure-randomness`. On 170 hand-labelled findings from real scans, the category matches the label for 98 percent, against 44 percent before. Some of the rules were tuned on part of those findings. The rules are keyword and CWE based and have not been checked on applications outside the three used.
- a scan report merges findings that two passes, or two batches of one pass, filed for the same flaw when they cite the same file and category (or a shared CWE) at overlapping lines. Before, passes merged across categories and one pass never merged with itself. Findings in different files or categories are never merged. The merged finding keeps the highest severity and lists the ids it absorbed in `mergedFindingIds`. `0 findings list` also folds groups of the same flaw from different runs, unless their triage state differs.

### Fixed

- the shallow-review check saw only the last 20 messages of a thread, because the status poll is windowed. It now reads the whole transcript once, and counts globs, `xargs cat`, `python` reads and files named in a task for a worker thread.
- A Sentinel's pull request poll keeps its cursor for long-lived open pull requests: it forgets closed pull requests first, so an open one is no longer reviewed again after the cursor fills up. A repository with more than 190 open pull requests is now refused with "Use a base-branch filter." instead of being polled with churn.
- `0 findings fix --sandbox docker` no longer follows or truncates a symlinked `.0-sandbox-probe` in the work tree copy. The probe is removed without following it and created exclusively.
- `0 sbom generate --resolve` keeps Gradle's own error text when every project in a multi-project build fails, instead of only "No dependency tree was produced."
- The MCP address check blocks more IPv6 forms that reach internal hosts: IPv4-compatible (`::127.0.0.1`), IPv4-translated, 6to4, Teredo, discard and local-use NAT64 addresses. Only global unicast addresses and mapped public IPv4 are allowed.
- `0 sbom licenses` printed "Not legal advice" twice in text output.
- `0 scan` reads a thread's status through a window of its last messages, so the status request of a long thread stays small. A status response over the transport limit ("Backend response exceeds the transport limit") ended one benchmark scan.

## [0.43.0] - 2026-11-22

### Added

- `0 skills add <folder>` installs an Agent Skills folder (`SKILL.md` with optional scripts and references) as a 0 skill, and `0 scan --skill <name>` runs it. `--yes` prints the skill id, its files and bundled scripts, and says that the `SKILL.md` text is instructions the model follows. Scripts do not run when a skill is installed or loaded. A bare `--skill` name is resolved to a full id once when the scan starts, and two skills with the same name are an error that lists their ids.
- `0 scan --tiers <file>` applies an operator-owned tier map (YAML or JSON, or `scan-tiers.yaml|yml|json` in the 0 state folder) that maps a repository (`owner/name` from the git remote or URL, with `*` patterns) or a folder path pattern to `critical`, `standard`, `light` or `skip`. A tier sets the budget, batches mode and skill, and can be pre-pass only. The most specific entry wins (exact repository, exact path, first pattern, default). The tier file is never read from the scanned folder, and 0 warns when a named file sits inside it. The scan prints the tier and the reason on stderr and records `tier` in the JSON, Markdown and SARIF run properties; a typed flag beats the tier, the tier beats the operator's `workflows` defaults, and `--plan` shows the tier; a tier's `skill` goes through the same name resolution as `--skill`. A `skip` tier produces an explicit result (`skipped by tier <name>: <reason>`, JSON `status: skipped`) with exit 0, or exit 1 with `--fail-on-skip`. A pre-pass-only tier runs the scanners without a model and reports their hits as findings labelled `Pre-pass only, not reviewed by a model` (`status: prepass_only`); with no scanner available it fails instead of reporting a clean result. The GitHub Action has no tier input yet.
- `0 scan --known <sarif>` (repeatable) is a second-opinion mode. The scan thread is told, in a delimited, size-bounded, lower-priority block, what other tools already reported and is asked to look for other classes of bug and for authorization and business-logic flaws. Each finding carries a `knownStatus` in JSON, Markdown and the SARIF result properties: `new` or `already-known` (same file, within 5 lines, same category family, as in the benchmark matcher); an already-known finding also carries `confirmedIndependently` when the scan recorded its own analysis of the code. `--only-new` hides the matched findings and leaves them out of `--fail-on`. `scripts/bench/second-opinion.mjs` measures recall of the items a baseline tool misses, with and without the flag; the result is in `docs/design/benchmark.md`.
- `docs/design/surfaces.md` says which job belongs to the CLI and CI, to a chat thread and to the platform, what each leaves out, and the rule for new features.
- `0 config audit-export` writes the audit log as NDJSON (default), CEF or RFC 5424 syslog lines, oldest first, with `--since`, `--until` (a duration such as `24h` or a date), `--type` (an action or prefix), `--limit`, `-o <file>` (mode 0600) and `--follow`. Each event has a stable `eventId` and an ISO timestamp, and text and detail go through the log's redaction again on export. In server mode, setting `ZERO_AUDIT_SINK_URL` to an `https://` collector or a `syslog+tls://host:port` address pushes new events in batches, with retries and backoff. It never blocks the action it records, counts dropped events in a status line, refuses UDP and plain http or TCP except to this machine, and is off by default. `ZERO_ENTERPRISE` leaves it on because you name the destination. See [Send the audit log to a SIEM](/server-mode/#send-the-audit-log-to-a-siem). Checked with a local syslog-over-TCP listener, a local TLS listener with a self-signed certificate, and a server run; not checked against a commercial collector or the compiled binary.
- Sentinels can start on a published GitHub release or pushed tag (`release`) and on a finished check run or suite (`check-completed`). Both poll through `gh` and accept signed webhook deliveries in server mode. The run receives a short, neutralised summary of the event. See the Sentinels page (#430).
- A Sentinel can post its result back as a commit status or an in-place pull request comment. It is off by default and set per trigger with `report`. Text is neutralised and size-capped, and evidence is never posted (#430).
- `0 sentinels sync` accepts the `release` and `check-completed` triggers and the `report` setting (#430).
- Accepted risks have a reason, an expiry and an optional approver label: `0 findings update <id> --status accepted --reason <text> --expires <date|90d> --approver <name>`. An expired acceptance reopens the finding in lists, exports and the next scan. `0 findings list` shows `accepted until <date>`, and `--expiring <days>` lists acceptances that end soon. JSON, Markdown, SARIF (`suppressions`) and `0 findings evidence` carry the reason, expiry and approver, and each change is written to the audit log. The approver is a label you type, not a verified identity. `findings accept` now needs a reason and an expiry too.
- `0 findings export-fixes` writes `fix-outcomes.md` and `fix-outcomes.json` for the fixes `0 findings burndown` proposed: pull requests, checks, cost and summary counts. With `--check-merged` it asks GitHub whether each pull request was merged, closed or edited and gives an acceptance rate. Evidence is never included.
- Fix pull requests follow your conventions. A `pullRequest` object in your own fix policy file sets `titleTemplate`, `commitMessageTemplate`, `branchPrefix`, `labels`, `draft` (`always`, `on-failure`, `never`), `bodyFooter` and `reviewers`. Templates use only `{id}`, `{title}`, `{severity}`, `{category}` and `{path}`. A policy file inside the repository cannot set them. `0 findings burndown` accepts `--policy <file>`.
- Extensions can declare an OS sandbox for their scripts and MCP servers: `"sandbox": { "network", "process", "readPaths", "writePaths" }` in the manifest. The block is part of the install approval, so a revision that widens it asks again. A sandboxed process has no network, cannot read your home folder, `~/.0`, `~/.ssh`, other repositories or the scanned folder, starts only allowlisted interpreters and writes only to a scratch folder, unless the block declares more. macOS uses `sandbox-exec` (Seatbelt, which Apple has deprecated) and Linux uses `bwrap`; Windows has no backend. `ZERO_SANDBOX=auto|require|off` chooses when it applies: `auto` (default) sandboxes only extensions that declare a block and says so when no sandbox is available, `require` sandboxes every extension and refuses to run without one, `off` keeps the old behaviour. Each script run shows whether a sandbox was applied. A server in `ZERO_MCP` can opt in with `"sandbox": true`. `0 doctor` reports `sandbox-exec`, `bwrap` and Docker. Checked on macOS with real runs and on Linux inside a privileged container; other Linux setups and Windows are untested. Existing extensions and the built-in GitHub connector run no scripts or servers of their own and behave as before.
- `0 sbom generate --resolve` (Maven and Gradle) runs your own `mvn dependency:tree` or `gradle dependencies --configuration runtimeClasspath` and adds the transitive packages and graph to the SBOM. Resolved components carry `0:resolved=true` and replace declared versions. It runs the project's build scripts and uses the network, so it needs a yes at a terminal or `--allow-build-tools`, and `ZERO_ENTERPRISE` refuses it. `--resolve-offline` runs the tool offline.
- `0 findings fix --sandbox docker --sandbox-image <image>` runs the `--test` checks in a container with no network, resource limits, a copy of the work tree and none of your environment variables. The pull request says "Verified in a sandbox" only when every check passed there. `--sandbox-network` allows downloads; `ZERO_SANDBOX_DIR` names the folder shared with the Docker VM. Without `--sandbox`, checks run on your machine as before.
- The `fix-finding` skill covers Maven (pom version, property, `dependencyManagement`) and Gradle (version catalog, build script, constraints, lockfile) dependency bumps.
- `0 findings metrics [--since <when>] [--command scan|fix|verify] [--format json|text]` summarises runs from `~/.0/metrics.ndjson`: cost, time, findings attempted and proposed, fixes whose checks passed, cost per proposed fix. `0 scan`, `0 findings fix` and `0 findings verify` each append one line of counts, cost and finding ids (no finding text or paths; owner-only file, rotated at 1 MB). Tokens are recorded for fix and verify runs, not scans. CI results are recorded as unknown.
- A `workflows` key in the operator settings file sets a default `budget` and `model` for `scan`, `fix` and `verify`. A flag on the command wins, and a project settings file cannot set it.
- `scripts/bench/fix-score.mjs` scores `0 findings fix` on ten small planted-vulnerability projects: did it commit, do the project's tests pass, and does a hidden exploit check still succeed. `scripts/bench/triage-score.mjs` reports precision, recall and the real bugs that `0 findings verify` called false-positive. The first measured tables are in `docs/design/benchmark.md`.

### Changed

- `0 findings accept` (and `0 findings update --status accepted`) now needs a reason and an expiry. Calls without them fail instead of accepting the risk with no end date.
- Extension script commands are checked strictly before they run with approved secrets: a `$` outside single quotes, backticks, `;`, `&`, `|`, redirection, parentheses, `#`, line breaks and `\` line continuations are refused, as is any interpreter flag before the script (such as `bash -c` or `node -e`). An interpreter must be a bare known name or sit directly in a system folder, and its type must match the script's extension. Commands that relied on `$` expansion now fail with a clear reason instead of running.

### Fixed

- A Gradle version catalog (`libs.versions.toml`) with a `__proto__`, `constructor` or `prototype` table header or key can no longer change `Object.prototype` while the SBOM is read. Those keys are skipped and catalog tables are built without a prototype; aliases such as `my.lib = { ... }` still resolve as before. Thanks to Himanshu Patro for reporting this in #535.
- The Sentinel runner's `gh` calls now refuse to run under `ZERO_ENTERPRISE`, like every other GitHub call.
- Comments to GitHub no longer turn `#123` in finding titles into issue links.
- The pre-pass scanners no longer read configuration or ignore files from the scanned folder, so a change under review cannot hide findings with them. This covers `.foxguard.yml`, `.semgrepignore`, `.gitleaks.toml`, `.gitleaksignore`, `.trivyignore` and `osv-scanner.toml`. Inline suppressions such as `gitleaks:allow`, `nosemgrep` and `trivy:ignore` still apply. Checkov has no option to ignore its `.checkov.yaml`, so it is skipped when the folder has one. `--repo-ignores` restores the old behavior and prints a warning.
- `--engine-port` rejects values such as `8080abc`, which used to be accepted as 8080.
- The saved conversation list keeps the newest conversations when the file cap applies, instead of dropping recent ones with later file names.
- `--finding` accepts the short id that `0 findings list` shows for an imported finding.
- Legacy redirect paths such as `/workers/<id>` are titled as the app and not "Page not found" while they redirect.
- A `NaN` concurrency limit no longer makes the concurrency helper return an array of empty slots.
- SBOM generation reads lockfiles and Gradle scripts with Windows (CRLF) line endings.
- The installer treats a `gh` without the `attestation` command as missing, says so, and shows `gh`'s own error. It then installs on the checksum check alone, like the no-`gh` case; `INSTALL_ATTESTATION=require` still refuses.

## [0.42.0] - 2026-11-22

### Added

- `0 scan --allow-partial` exits by the findings alone (0, or 1 with `--fail-on`) when a scan stops before it reviews everything; the default stays exit 3, which means "not finished", not "failed". The JSON `status` is `partial` and `coverage` stays in the report. A scan that ends partial now prints what stopped it, how much is left and the exact `Continue with: 0 scan <folder> --resume <id>` command, on stderr, in the Markdown report and as `coverage.resume` and `coverage.stoppedBy` in JSON. `0 scan --plan [folder]` lists the entry points by kind, the batches, whether `--batches auto` would batch the folder and a rough cost range, without calling a model or writing to the findings database; `--format json` is supported. The cost range scales one measurement (about $0.035 per batch on a 40-file fixture); cost for large repositories is not measured and varies 2 to 3 times. The GitHub Action already treats exit 3 as a warning and does not fail the job; the docs now say so.
- `0 findings verify [finding...]` (experimental) re-checks findings with a fresh thread each, or a few findings of one file with `--batch`. The thread gets only the finding's title, location, category, description and claimed impact, follows the new `verify-finding` skill (read the code, trace the input from an entry point to the sink, look for a real control, build a concrete attack or say it cannot) and answers true-positive, false-positive, fixed, uncertain or duplicate with `path:line` reasoning. The verdict is stored next to the finding by finding id and shows in `0 findings list` and `0 findings show`; the finding's severity and status are not changed, and the thread's severity is kept apart as an advisory. `--apply` suppresses a finding only for a false-positive verdict that cites a control at `path:line`. It selects by id or by `--severity`, `--category` and `--tool`, takes `--budget` with a `--per-finding` cap and `--concurrency` up to 3, skips findings that already have a verdict (`--force` checks again) and stops after consecutive threads that return no verdict.
- `0 sbom licenses [sbom-file-or-folder]` checks the licenses in a CycloneDX SBOM, or in a folder's lockfiles, against a policy: `--preset permissive|no-copyleft`, `--allow`, `--deny`, or `--policy` (JSON or YAML with allow, deny, `allowByPackage` exceptions that need a reason, and `unknown: warn|fail|allow`). SPDX expressions are evaluated (OR is a choice, AND needs both sides, `WITH` exceptions, `+` and `-or-later`); free-text license names, ids not on the SPDX list and components with no license are unknown and never guessed. Output is a table by verdict, `--format json` or `--format sarif` (rule `license/<spdx-id>`, located at the lockfile, importable with `0 findings import`); exit 1 on a violation, 2 on a usage error. Only npm and Composer lockfiles state licenses: on this repository 1088 of 1107 components were unknown, and the opt-in `--resolve` (deps.dev; sends package names and versions) cut that to 11 in 32 seconds. Not legal advice.
- `0 scan --scanner` also runs `gitleaks`, `trivy` and `osv-scanner` in the pre-pass, alone or together (`--scanner gitleaks,trivy`). Each runs without a shell and with a time limit, reads SARIF, has a `ZERO_<NAME>_PATH` override and prints an install hint when missing. gitleaks runs with `--redact`, and secret leads never carry a snippet or matched value into the prompt. FoxGuard stays the default. `0 sbom generate --generator syft|trivy --image <reference-or-archive>` describes a container image; check it with `0 sbom check`. 0 relies on syft or trivy for the image and does no layer analysis of its own.
- `0 sbom check` shows the lowest fixed version for each advisory (or `No fixed version known.`) and a severity from the database label or a CVSS 3 score, and labels OSV `MAL-` records as critical malicious packages. `--format sarif` and `-o` write results that `0 findings import` accepts, located at the lockfile the SBOM names; `0 sbom generate` now records each component's lockfile in a `0:source` property. `--outdated` adds informational newer-version notes from deps.dev (up to 200 components, never a vulnerability, never an exit code). Checked live against OSV and deps.dev with an old lodash and the malicious crate in `MAL-2022-1`.
- The `dependency-reachability` skill (experimental) estimates, for each advisory, whether the application imports and calls the vulnerable package: reachable, not-reached or cannot-tell, with `path:line` evidence. It is a model's reading of the code, not a proof. `fix-finding` now has a section for dependency findings: bump to the lowest fixed version, refresh the lockfile only with the project's own package manager, keep the change to manifest and lockfile. On a planted Node app (an old lodash with one vulnerable function called and one old package imported but never used), the second of two runs gave six correct verdicts out of seven advisories and one cautious cannot-tell; the first run recorded five of the seven. One fixture is not a measure of accuracy. `0 findings fix --no-pr` on an imported lodash 4.17.15 finding committed a bump to 4.17.21 in `package.json` and `package-lock.json` (npm wrote the lockfile; the project's tests passed).
- `0 scan --scanner checkov` runs Checkov in the pre-pass for Terraform, CloudFormation, Kubernetes, Dockerfiles and GitHub Actions (`ZERO_CHECKOV_PATH` names the binary), and the experimental `iac-review` skill (`--skill iac-review`) reviews infrastructure code across resources: IAM escalation, networks exposed through routes and referenced groups, secrets in variables, unpinned images and actions, workflows that run untrusted pull request code, and Kubernetes pod privilege. The planted-bug benchmark gains an `iac-app` fixture and `checkov` configurations.
- `0 scan --rules <file-or-folder>` (repeatable) passes your own Semgrep or OpenGrep rules to the pre-pass, one `--config` per path, without a shell. It needs `--scanner semgrep` or `opengrep` and replaces the scanner's default pack; FoxGuard has its own format and is not given them. Paths must exist; a rule file the scanner rejects fails the scan with the scanner's message. Rules are never read from the scanned folder unless named. Findings at a custom rule's rule id or lines carry `ruleSource: "custom"` in JSON and in the SARIF properties, and the description names the rule. Checked end to end with Semgrep 1.176; OpenGrep is covered only by a stand-in binary.
- `0 scan` reviews a large folder in batches and says how much it reviewed. A folder with more than 8 entry points (or 150 source files) is listed without a model (routes, handlers, webhooks, queue and cron consumers, program mains, deserialization, upload and command points; files nothing matches are grouped by folder), then reviewed by one thread per batch with a share of the remaining budget. A coverage ledger in the findings database records each unit as pending, reviewed or skipped with a reason. The report states it, for example `reviewed 41 of 57 entry points; 16 not reached (budget)`, with a `coverage` object in JSON and in the SARIF run properties, and the exit code is 3 while anything is not reached. `--resume <scan|latest>` continues the pending units (it refuses when the git HEAD changed, unless `--force`), `--coverage` prints the ledger, and `--batches off|auto|on`, `--batch-size` and `--concurrency` tune it. Small folders keep the single thread. See [Large repositories](/findings/#large-repositories).
- `0 findings import --github owner/repo` imports GitHub code scanning, Dependabot and secret scanning alerts as findings (`--state`, `--types`, `--ref`). It reads them with your own `gh auth login` session through `gh api`, not the 0 GitHub connector. Partial fetches are reported as warnings and marked incomplete in the import (a failed fetch exits 1), a changed alert imports again as updated, secret alerts get their file and line without the secret value ever being read, and alert text is stripped of control characters and bounded.

- `0 findings fix --policy <file>` gives the fix thread a policy of approved libraries, forbidden patterns and rules (JSON or YAML); without the flag it reads `~/.0/fix-policy.json|yaml|yml`. A policy file inside the repository being fixed is ignored unless you pass `--repo-policy`, which warns that the content is untrusted. The policy is escaped and size-bounded in the prompt, marked as lower-priority guidance, and the never-commit, never-push, never-merge rules come after it.
- A self-hosting guide for Azure and AWS (persistent data disk, cloud secret stores, TLS ingress, offsite backups, a restore procedure that checks the database before starting, upgrades and rollbacks). `deploy/compose/docker-compose.data-disk.yml` keeps the data on a host directory such as a mounted cloud disk instead of the `zero-data` volume. The Dockerfiles moved from `scripts/docker/` to `deploy/docker/`. The AWS and Azure steps are marked untested in the guide.
- Threat models and policy checks. `0 threat-model [folder]` drafts `.0/threat-model.md` (assets, actors, trust boundaries, entry points, authorization and business rules, data flows, open questions; unknowns marked `unknown: confirm with the team`), keeps sections marked `<!-- human -->` when it updates the file, and with `--pr` opens a pull request from the branch `0/threat-model`. `0 scan --context <file>` gives a scan such a file as delimited, size-bounded, lower-priority background that cannot steer tool use; nothing is read from the scanned repository by default, `--repo-context` opts in with a warning, and in CI the file should come from the base branch. `0 scan --policy <file-or-folder>` checks the code against Markdown policies with the new `policy-check` skill (pass, fail or not-applicable per policy with `path:line` evidence, one `policy-violation` finding per failure), and `--org-policy <folder>` is evaluated first and wins. Policy findings say "What the violation exposes", not what an attacker can do. On a planted 120-line Express fixture (a missing admin check, a missing tenant check, customer emails sent to an analytics SDK) a plain scan found 2 of 3 in each of 3 runs, the same with a drafted threat model, and 3 of 3 with a three-line rules file written by a person (2 runs); the policy check marked the planted violation FAIL in both runs. See [Threat model and policy checks](/threat-model-and-policy/).
- `0 sbom generate` now writes hashes (npm, pnpm, yarn, Cargo, Composer, Bundler checksums), the dependency graph (npm, pnpm, yarn, Cargo, poetry, Bundler, Composer) and licenses (npm, Composer) into the CycloneDX SBOM when the lockfile states them. `--format spdx` writes SPDX 2.3 JSON, and `--generator syft|cdxgen|trivy` runs that installed tool for what lockfiles do not cover (exit 2 with install instructions if it is missing).
- `0 findings evidence <folder>` writes one folder of security evidence: findings with triage state and timestamps (JSON and Markdown), SARIF, a CycloneDX SBOM from `--repo`, the fix branches that exist there, an optional OSV advisory check (`--check-advisories`, the only network use) and a README with a manifest of the `0` version, date, commit and file hashes that says what each file does not show. Evidence and proof-of-concept bodies are left out unless `--include-evidence`. `0 findings report-draft <finding> --stage early-warning|notification|final` drafts a report about an actively exploited vulnerability from the finding and the facts you supply, with every other field left as a visible blank; a person reviews and submits it. Neither claims compliance.

- `0 sbom scan-models <file-or-folder>` scans pickle-based model files (`.pkl`, `.pt`, `.pth`, `.ckpt`, `.bin`, `.joblib`, PyTorch zips, numpy `.npy`/`.npz`) for imports that can run code when loaded, without Python and without loading anything. It lists each file with its format, a verdict and the dangerous or unrecognised imports, writes SARIF with `--format sarif`, and exits 1 when a file is dangerous. `0 sbom generate --ai` now flags model files the scan finds dangerous.
- `0 findings import <file|->` brings another scanner's SARIF 2.1.0 results in as findings (FoxGuard, CodeQL, Semgrep and others). Each finding keeps the scanner's name, rule, severity, CWE and file and line, shows the scanner as a chip in the Findings list, and is marked as imported and unverified. Importing the same file again changes nothing. Absolute paths become repo-relative under `--root` (default: the current directory); paths outside it are dropped.

- `0 findings fix <finding>` fixes one finding in an isolated git work tree: a thread that follows the new `fix-finding` skill makes the smallest change, the command runs your `--test` checks, commits on a `0/fix-<id>` branch and opens a pull request (a draft when a check fails). Running it again updates the same pull request. It never pushes to the base branch and never merges. `--no-pr` stops after the commit.
- `0 findings burndown` works through open findings in batches: it selects them by severity, category, tool, scan or fingerprint, runs each through the `0 findings fix` flow (own work tree, `0/fix-<id>` branch, one pull request, a draft when a check fails) with `--concurrency` up to 4, a `--budget` split into `--per-fix` caps and a stop on consecutive failures or failure share, and prints a report (`--format json`). It remembers each outcome in `~/.0/burndown.json`, so a second run skips findings that already have a pull request and continues with the rest, and `--history` lists a metrics row per run. Nothing is pushed to the base branch or merged.
- Scans and fixes started with `--db-path` now start their console on that database when none is running.

- With `--comment` on, a Sentinel's pull request review also posts inline suggestion blocks on changed lines that a finding has a replacement for (at most 10 per run, none on forks); a comment is removed when a later push no longer has its finding.

- Sentinels can be defined as YAML files in a git repository: `0 sentinels sync <folder>` shows what would change and `--apply` writes it (new Sentinels paused, new triggers disabled, a changed model or skill list sent back to review, nothing deleted; `--check` for CI), and `0 sentinels export <id>` writes an existing Sentinel as a file.
- The pull request poll reads up to 1,000 open pull requests instead of 50.

- `0 scan` runs a fast pattern scanner first when FoxGuard is installed (`--prepass auto`, the default; `--prepass off` skips it) and hands its hits to the scan thread as leads to check. The thread records only the leads that are real, says which it rejected, and still reviews the entry points itself, so bugs a pattern scanner cannot see are not lost.

- `0 scan --diff <ref>` reviews only the files that differ from a git ref (for example `origin/main`) and the code they connect to, and only the pattern-scanner leads inside those files. For a pull request check this costs a fraction of a full scan. When nothing differs it starts no thread and writes a valid empty report, so a pipeline that reads the file keeps working.

- `0 findings issues --repo <owner/name>` mirrors findings into GitHub Issues, one issue per finding, found again on later runs through a hidden marker so it never duplicates. It creates issues for open findings at or above `--min-severity` (default `medium`), updates them when the finding changed, closes them with a comment when the finding is suppressed, accepted or fixed, and reopens them if it returns. `--dry-run` prints the plan; `--max` and `--delay` respect rate limits. Issue text carries only share-safe fields (never evidence or proof-of-concept bodies) and is neutralised against mentions, references and markup.
- `0 findings upload <sarif>` uploads a SARIF file (for example from `0 scan --format sarif -o scan.sarif`) to GitHub code scanning, so findings appear in the repository's Security tab and as pull request annotations. It takes the repository, commit and ref from the clone (or `GITHUB_SHA` and `GITHUB_REF` in Actions), compresses the file, waits for GitHub to process it and reports why it refused it. Uploading again for a later commit updates the alerts. Needs `gh` signed in with permission to write security events.

- A GitHub Action (`uses: 0sec-labs/0security@v<version>`) that scans a pull request and uploads the findings to GitHub code scanning: it installs the release you pin (checksum-verified), runs `0 scan --diff` against the base branch, uploads the SARIF with `0 findings upload`, and fails the job at `fail-on`. See [Pull request checks](https://docs.0.security/ci/). It needs a release that contains `action.yml`, so it works from the next tag.

- A scan now says what each finding means: "what an attacker can do", who can do it (no login, a logged-in user, a local user) and what they get (run code, read data, change data, take down the service). The scan skill asks for it on every finding, and it appears in Markdown and HTML reports, in the SARIF message GitHub shows on an alert, and in the JSON. It states only what the code shows; business impact stays "not assessed" when the code does not say what the service does.
- Imported findings can be addressed by the short id that `0 findings list` shows (their ids all started with the same 70 characters, so a prefix never matched one); a unique prefix, shown part or end of the id all work.

- `0 sbom generate [folder]` writes a CycloneDX 1.5 SBOM, validated against the official schema in the tests, from the lockfiles in a folder (npm, pnpm, yarn, Cargo, Go, Poetry, Pipenv, pinned requirements, Bundler, Composer, NuGet, Gradle, Dart and Mix); MCP servers from `--ai` are listed under CycloneDX `services`, as the schema requires, reading them as text and never installing anything; `0 sbom check <file>` looks every component up in the public OSV database and lists the advisories (exit 1 when there are any). On this repository it listed 1,106 components from four lockfiles in a moment and the check found two real advisories in Rust crates. Maven, Gradle, NuGet and container images are not covered by the built-in generator.

- Two skills for AI applications, `llm-app-review` and `mcp-server-review` (`0 scan --skill llm-app-review`): they map an app's trust boundaries (what reaches the model, what it can do, what happens to its output) and check them against the OWASP LLM risks, or check MCP configuration and tool handlers for poisoning, over-broad access, unpinned launchers and injection.
- Two skills for jobs beyond a source review: `crypto-migration` (`0 scan --skill crypto-migration`) inventories every cryptographic use, separates quantum-vulnerable public-key crypto from weak classical crypto, records a minimal replacement per site without inventing library calls, and ends with a migration plan (interoperability, key and data migration, versioned formats, hybrid mode, tests); `artifact-scan` reviews an unpacked npm package, wheel, jar, image filesystem or firmware folder for install-time scripts, embedded credentials, setuid files, unexpected binaries, endpoints and stale components, never running anything from it. Unpacking recipes and `0 findings fix` follow-up are in the Findings guide. On planted fixtures the crypto skill found 7 of 7 sites against 4 for a general scan, and the artifact skill 3 to 4 of 4 problems against 2.
- `0 sbom generate --ai` also lists the AI in a folder (models, datasets, hosted model ids, MCP servers) as CycloneDX components, found by reading files as text.

- `0 probe <url>` sends ten adversarial messages (instruction override, fake system markup, hidden instructions in a document or base64, a role-play jailbreak, system prompt extraction, credential requests, command execution, markdown and HTML output) to a live model or agent endpoint and reports the ones whose reply shows they worked. Each carries a canary, so a hit is checked on the reply, not judged by another model. Reports in every format, `--save` into the findings store, `--fail-on` for CI. On a real model it got 3 of 10 through a deliberately weak prompt and 0 of 10 through a hardened one.

### Changed

- The FoxGuard companion that `install.sh` and the container image download is now v0.14.2 (checksum-pinned for every platform). It fixes changed-file scans of non-ASCII file names. On a test app and a Java servlet it reports the same findings as v0.14.0.
- Less text in the app: shorter Settings descriptions, no subtitle that repeats a page's name, a one-line Memory notice, and shorter dialogs on Computers.

### Removed

- Business priority: every finding read "Not assessed" because a scan cannot know a business, so the label, its sort order, the rationale line, the SARIF `businessPriority*` properties and the "Edit business impact" form are gone. Findings are ordered by technical severity, then CVSS, and show what an attacker can do instead.
- Memory: the model-written notes shared across threads, with its `memory` tool, the Memory page, `0 memory`, the `/memory` routes and the hidden `0 findings triage` commands that wrote to it. Operator instructions (`~/.0/AGENTS.md` and the per-workspace file) are the one place you write context for every thread, a Sentinel keeps its own `NOTES.md`, and why a finding is a false positive stays with the finding (`0 findings update --status false-positive --note ...`). Notes already in `~/.0/memory` are left on disk and no longer read.
- About 27,000 lines of engine code that nothing used: ten unfinished engines (mobile, recon, attack, emit, h1, cve, protocol, specdrift, adgraph, xnu-fuzz), old scanners and helpers, the old runners, the attack-template loader, the red-team harness and its `0-llm` bin, the core/full build edition, and the matching package exports (`./identity`, `./adgraph`, `./xnu-fuzz`, `./kernel`, `./templates`, `./redteam`).
- `0 memory proposed list`, `accept` and `reject`, and the `proposed` field of `0 memory list --json` and of the Memory API.

### Fixed

- `0 sbom generate`, `0 sbom licenses` and `0 findings evidence` read `yarn.lock`, `Gemfile.lock`, `build.gradle`/`build.gradle.kts` and hashed `requirements.txt` files with Windows (CRLF) line endings, as Git for Windows checks them out by default. Before, such a file gave no components and no warning, so `0 sbom check` had nothing to look up for it.
- Pending crash reports, feedback, scanner binaries and the 0verse runtime config now live under the same state folder as everything else, so they follow `HOME` on Windows too.
- A Lima worker's private ssh config is now kept in the 0 state folder with owner-only permissions, can no longer be pre-created or swapped by another user, and is removed when the worker's tunnel is stopped or already gone.
- `0 findings issues`, `0 fix` and `0 findings burndown`, found by an end-to-end run: issue titles are plain text (no backslash escapes), id hints resolve for imported findings, a closed issue's status table says closed, the pull request body shows the real Checks table before the model's labelled summary and escapes table cells and command text, `0 findings update --status false-positive` without `--reason` says that `--reason` is required, and burndown fixes findings reported twice at one place and category once.
- An MCP server that lists the same tool name twice is refused with a clear reason ("duplicate tool names; refused") and shown as needing approval, instead of failing with a generic listing error. Duplicate names cannot be used to slip past tool pinning.
- `0 computers add --target-git` accepts only `https://` URLs (no spaces or quotes); the option help and docs now say so.
- `0 findings fix` no longer fails its commit on a machine with no git identity (a fresh install, a GitHub Actions runner); it uses a neutral `0 <noreply@0.security>` author unless git has one.
- `0 scan` with the released binary could not start its own console on a machine where none was running: it waited 30 seconds and gave up (v0.41.0). The console's output now goes to a file instead of a closed stream, and when it stops the scan says why at once. The release smoke test now runs this case.
- The repository of a Sentinel pull request trigger can no longer be a path such as `../x`; it must be `owner/name`.

- The console that `0 scan` starts for itself takes a free port, so another console on the default port can no longer stop the scan from finding its own.
- The scan skill tells the model not to use the memory tool.

## [0.41.0] - 2026-11-19

This release makes `0 scan` usable in CI and fuller: several passes merged into one report, a SARIF that works in GitHub code scanning, and two more skills.

### Added

- `0 scan --passes <n>` (up to 5) scans the same code several times, three at a time, and merges the findings by place, so the report is the union of what the runs found. `--budget` is the total and is split evenly. Each merged finding carries `foundInPasses` in the JSON and a "Found in k of n scan passes" line in every format, and the JSON has `passes` and every pass's `threadIds`. On NodeGoat three single scans found 8, 11 and 14 issues (18 distinct in all); three passes together reported 16, 8 of them found by every pass, for $0.25.
- Two built-in skills that work from the shell and the `finding` tool alone. `variant-hunting` takes a fix (a commit or diff), names the bug class and the unsafe pattern, searches the whole tree for the same shape and checks every hit. `assumption-mining` lists what each function silently relies on and looks for a caller that does not establish it. On planted examples they found all 3 unfixed variants and both broken assumptions, with no false positive on a guarded decoy.

### Fixed

- A scan's SARIF works in GitHub code scanning. Paths are relative to the repository root instead of `file:///` URLs with the runner's checkout path, the rule is the finding's category instead of `manual`, and the finding key comes from its file and first line instead of the title and the checkout path, which changed on every run. In the JSON report `target` is the folder's name or the git URL, never an absolute path, and `location.path` is relative to the scanned folder.
- A scan of a git URL no longer sends a user name and password in the URL to the thread, the model or the report.
- The scan skill leaves out `node_modules`, `vendor`, build output and generated files.
- `0 scan` keeps going when a few status requests to a busy console fail, as happens with several scans at once or a slow model provider. It gives up after about a minute of failures and names the thread, whose findings are kept (`0 findings export --scan <thread id>`).

## [0.40.1] - 2026-11-19

This patch release fixes the standalone `0` binary, in which every folder looked unreadable.

### Fixed

- In the standalone `0` binary (every release since 0.36.0), a folder could not be read: `threads start --folder`, choosing a folder in the app and `0 scan` failed with "Zero couldn't read that folder". The release smoke test now starts a console from the compiled binary and starts a thread in a folder, so this cannot ship again.

## [0.40.0] - 2026-11-19

This release brings `0 scan` back as a thread: a scan is a thread that follows the `scan` skill, so it shows up in `0 threads` and in the app, and its findings are exported as json, md, sarif, html or pdf. It also cleans up the CLI and the Findings, Extensions and Computers pages.

### Added

- `0 scan <folder or git URL>` scans a code base for security bugs and prints the findings as a report. A scan is a thread that follows the built-in `scan` skill, so it shows up in `0 threads` and in the app. `--budget` (default $5) stops it and keeps the partial findings, `--format` is `json`, `md`, `sarif`, `html` or `pdf`, `-o` writes a file, `--fail-on <severity>` sets the exit code for CI, `--timeout` cancels it and still prints what was found, and `--model` picks the model (default `gpt-6-luna`). With no console running it starts one for the scan; it also works with `--engine-url` and `--computer`. The JSON report is versioned (`schemaVersion: 1`). Exit codes: 0 done, 1 a finding at or above `--fail-on` or the scan failed, 2 usage error, 3 stopped at the budget or time limit. Package and image targets are not supported. In chat, `/scan <folder>` runs the same scan in the current thread. If the scan changes a file in a git target, it is reported as failed and names the files.

### Fixed

- In a scan, one flaw is one finding: findings of one scan that cite the same lines of a file are merged, and a scan's findings are no longer merged into another scan's, so a repeat scan or a scan of another project can no longer lose a finding from its own report.
- A finding with a category outside the known list is stored as `other` (the model's label is kept in the description) instead of making the whole report unreadable, and a report skips a stored finding it cannot read and says so.
- The Markdown report no longer prints a Depth row or an Attacks line of 0.
- Sub-agents, Sentinel runs and every thread now get the same tools with a shell; one bad skill file no longer breaks `load_skill`; helpers can work in one folder together; a Sentinel run now tells its thread the charter.

### Changed

- Extensions and Computers are plain rows like Skills: one Add menu, Connect GitHub in a small dialog, details in a side sheet.
- Findings is a full-width page with tabs, filters and status groups; a finding opens on its own page with previous/next.
- `0 -p` prints only the answer on stdout; the tool trace and token count go to stderr on a terminal. `--folder` sets the folder, `-c` and `-r` work after `-p` too, and a failed turn exits 1.
- `threads list` and `threads show` print text by default (`--format json` for JSON); `threads show <id>` is listed, and `show`, `send` and `continue` take `--wait`, which prints only the reply.
- Every command that had `--json` also takes `--format text|json`, and the reverse. Usage errors exit 2 and name the command to run; a command with no subcommand prints its help.
- `sentinels set <id> --trigger add` takes `--frequency`, `--every`, `--at`, `--weekday`, `--cron` and `--timezone`, and starts the Sentinel's only automation by default. `--mission` is now `--purpose`.
- `findings list --format json` with no findings prints an empty report instead of failing. `config doctor --json` exists, and doctor says when no model is connected.

## [0.39.0] - 2026-11-18

This release is a large simplification: Agents become Sentinels, the model gets eight tools, and the scan engines, scope and budgets are gone.

### Added

- `0 computers remove <id>` takes a remote computer out of the list from the terminal. Files on the computer stay.

### Changed

- Agents are now Sentinels: `0 sentinels` and `/sentinels`. A Sentinel is one thread that keeps going, with its own prompt, triggers and memory file. Its page has a side pane for status, triggers, instructions and memory, and a small Profile dialog.
- Creating a Sentinel is one small dialog. Six starting points remain: PR security reviewer, dependency watcher, secrets hunter, fix engineer, incident triage and release gate.
- The model has eight tools: a shell, file edit, findings, skills, memory, web search and sub-agents. A turn ends when the model replies without a tool call.
- Your message appears the moment you send it, including follow-ups and queued messages.
- The default accent is neutral again; blue is an option in Appearance.
- The CLI is `findings`, `threads`, `sentinels`, `skills`, `memory`, `models`, `computers` and `config`, plus `0 -p`, `0 -c` and `0 --resume`.

### Removed

- The scan pipelines and `0 scan`, the kernel, triage, disclosure, research, review and replay engines, benchmarks and the GitHub Action.
- The workflow graph and steps, learning, scope, daily budgets, todos and plan, the MCP server mode, and the legacy command names.

### Fixed

- Untrusted automated and peer turns can no longer write live notes to Memory. (@Adityakk9031)
- A verifier canary can no longer be planted through a symlink out of the snapshot. (@Adityakk9031)
- A Sentinel's tripped circuit breaker keeps its state across late turn results. (@hopstreax)
- MCP tool revalidation no longer races on repeated tool-list changes. (@hopstreax)
- Memory notes no longer duplicate after an edit. (@hopstreax)

## [0.38.0] - 2026-11-16

This release makes Memory one thing, puts Settings > Appearance on one page, replaces the backgrounds with six new scenes and puts every page on one width.

### Added

- Memory is one set of plain notes, per folder or global, that threads read at the start of each turn. There is one Memory page and one `0 memory` command: `list`, `add`, `remove`, `clear`, `export`, `import` and `proposed`.
- A thread that has read untrusted content can only propose notes. They wait in a Proposed inbox for you to accept, and are not used until you do.
- Secrets and hidden characters are never saved as notes. 0 saves at most 5 notes per thread and 20 per day.
- Worktrees and clones of one repository share notes.
- `0 memory export --to AGENTS.md` writes the notes you wrote or accepted as a file you can review and commit.

### Changed

- Settings > Appearance is one page. Mode, Theme, Accent, Background, Text and layout, and Motion each show what they do.
- Theme cards are small copies of the app in that theme, and each Background tile is a real frame of that background.
- Theme and mode live in one place. The profile menu has one Appearance item and the command palette has fewer entries.
- Six new backgrounds replace the old eight: Dither (flow) (still the default), Contours, Glyph contours, Fish school, Plankton and Ink. A saved choice of a removed background falls back to Dither.
- All pages share one width. Agents, Skills, Memory, Computers, Extensions and the rest line up, and Settings sections are narrower.
- `0 findings update --status false-positive` remembers why as an `avoid` note, and only `avoid` notes you wrote or accepted reach the scan verifier.
- `ZERO_DISABLE_HUNT_MEMORY` still turns Memory off, next to the new `ZERO_DISABLE_MEMORY`.
- The first time Memory opens, the older stores are imported into notes once. Nothing is deleted, and the report is in `~/.0/memory/import-report.json`.
- Memory is not available inside an isolated workbench for now.

### Removed

- The older memory stores: hunt memory, craft memory, triage memories as a separate store, and lesson capture with the lesson pages. They are imported once into Memory and left untouched on disk.
- The `remember_codebase` tool and the `CYBERGYM_MEMORY_DB` option.
- The two learning-comparison bench scripts, which measured the old hunt memory.

### Fixed

- The new-thread skeleton race that made CI flaky is now a deterministic test.
- The What's new dialog no longer shows an old screenshot.
- Refusing an approval run by a thread says "This command was run by a thread, not by you. Run it yourself in a terminal to approve." instead of naming an internal variable.
- A command run from another folder than the console says "This console is for <folder>. Run the command there, or add --db-path <path>."
- The Extensions page scope row says On with no switch only when a scope is defined.
- The docs pin the current release, and `node scripts/bump-docs-pins.mjs --check` fails when a pin lags.
- `0 usage --by` takes `model` or `thread`, and leftover mentions of plugins and Sentinels in command help were reworded.
- A command that needs your approval now names the command ("Run touch approved.txt") instead of "Confirm tool action", and the closed line keeps it, so you can tell which action you allowed or declined.
- Messages queued before you pressed Stop now say they are paused and offer Send now, instead of "sends after the current response" while nothing is running.
- Links in replies are underlined so they can be told from plain text, narrow table headers no longer break mid-word, and unchecked task-list items no longer look like dark filled squares.
- A thread no longer says its model "is no longer available" when the provider's model list could not be loaded for a moment, and a chat cost under half a cent reads "<$0.01" instead of "$0.00".

## [0.37.0] - 2026-11-16

This release adds a verifier gate so a fix is only called Verified when the harness checked it, brings back the Findings board and the Agents list, and simplifies the sidebar, the Skills page, the docs and CI.

### Added

- A skill can declare a check that the harness runs in a container before anything is called Verified. The Agent does not run it. The check uses a pinned image with the network off after setup, a timeout, and success as exit 0, a pattern or no worse than before.
- Fixes and threads now end with "Verified by ..." when the check passed or "Not verified: ..." with the reason when it did not.
- A built-in `workflow-hardening` skill checks GitHub workflows with zizmor and actionlint. Run it with `0 threads start --skill workflow-hardening`.
- `0 scan fix --verify-image <image@sha256:...>` runs `--test-command` in a container with the network off. Without it the command runs on this machine and is never labelled Verified.
- The second-Agent check is now called Corroborated. Verified is kept for checks the harness ran itself.
- The Findings board is back, with a List | Board toggle and drag and drop between columns.

### Changed

- The sidebar has an Agents | Threads toggle with Agent and thread rows, a shared header with Sort by and Density, and the Agents list is back on the left.
- The Skills page is a flat two-column list with a tile for each skill and search at the top right.
- Extensions connect 0 to your tools and services: GitHub, MCP servers and rules like scope. The pages and help text now say so.
- Scope shows On, with no switch, while a scope is set. GitHub shows Built in.
- Automations are created and edited inside Agents. `/automations` and its old addresses open Agents.
- `0 skills add` flags work before or after the source, and `--yes` installs without a terminal (CI, scripts). A command run by a thread still refuses.
- The docs went from 49 pages to 12.
- CI went from 14 workflows to 5, with one shared build and a release that waits for a green Main on the tag's commit.
- Skills now live at `/skills`; `/plugins/skills` redirects there.

### Removed

- The Reports, Scans and Engagements pages. Findings and Threads carry the same findings, evidence and exports, and the old addresses open Findings. The scan, report and engagement APIs are unchanged.
- The Automations page. Automations live inside Agents.
- Unused web code: dead API client functions, imports and components. A few old scripts and checks are gone too.

### Fixed

- Opening a page while the server is down shows "Couldn't load this page. It will retry when the connection returns." instead of a raw error.
- A new thread gets its title after the first answer. It stayed "New thread" before.
- A pull request or scheduled Agent run that fails now says why on the activation, for example an invalid API key.
- Server mode with an explicit port stops with a clear error when the port is busy, instead of silently listening on a random one.
- An extension's own MCP server now starts. It was refused because it runs in the extension's folder.
- A changed or new MCP tool list is no longer approved automatically when commands run without asking.
- A thread can no longer install or approve an extension by clearing the agent-session variable or wrapping the command in `env`, `sudo` or `node <script>`.
- A thread can run or read a file inside an installed extension, so connector scripts get their approved token. State files under `~/.0/extensions` are still protected.
- Messages that named a command that does not exist now point at `0 --headless`, and a console that belongs to another folder says which folder.
- `0 findings list --all` and `--format sarif|json|md` work as documented. Without IDs the export covers every finding and honours `--severity`, `--category`, `--status` and `--triage`.
- `0 findings list` and `0 agents set --state` reject an unknown value and list the valid ones.
- `0 threads list --format text` is a table. Agent and scan threads are titled `Agent: ...` and `Scan: ...`, not Sentinel or Workflow.
- `0 ... | head` ends quietly instead of printing an EPIPE stack trace.
- `0 skills add <path-or-url>@<sha>` shows the install prompt instead of `Cannot read`.
- `0 skills extensions list` shows an extension that no longer matches its pinned commit as `refused`, with the reason.
- `0 memory set --import` on a file that is not a memory archive says so. `0 scan . --module bogus` and a missing folder give a plain message.
- The Extensions page has one Connect button on the GitHub card, squared chips and shorter intro copy.
- The command palette has Diagnostics, Tools, Folder and Fix again, and the slash menu names `/extensions list`.
- The audit log says "Agent create" instead of "Sentinel create", and "Finish setting up" no longer asks for a first thread when you have saved ones.
- A link to a deleted saved thread returns Home with a note instead of a retry loop.

## [0.36.0] - 2026-11-15

This release replaces the old plugin system with extensions. Extensions connect 0 to your tools and services: GitHub, MCP servers and rules like scope. Each is pinned to a commit and never updates on its own, with one decision point before every command.

### Added

- Extensions connect 0 to your tools and services: GitHub, MCP servers and rules like scope. Each is pinned to a commit and never updates on its own, and an extension can come with a skill that explains how to use it. Install one with `0 skills add <repo>@<sha>`. A prompt shows what it can do and, on update, the diff since the last approved version; nothing updates on its own.
- `0 skills extensions list|info|enable|disable|update|remove` manage extensions from the CLI. A folder that no longer matches its pinned commit refuses to load, and scripts get a scrubbed environment with only the names you approved.
- The Extensions page (`/extensions`) lists installed and built-in extensions, what each can do, its source at a commit and an on/off switch. Add shows the install prompt and Update shows the diff. Only team owners in the browser console can install, update, enable or remove, and each is audited.
- MCP servers now live inside extensions and start on demand. A thread's default tool list carries one line per server and no MCP schema; tool schemas load only when the model asks for a server. Add one from the Extensions page (**Add MCP server**) or `0 skills extensions mcp`.
- Skills inside an enabled extension appear on the Skills page, in `list_skills` and in `load_skill`, labelled with the extension's name. Disabled, refused or tampered extensions provide none.
- Connectors are extensions. A connector declares how it connects, what it may read and write, the hosts it may reach and a health check, and the Extensions page shows one Connect card each. GitHub is a built-in connector. See [Connect a service](/connect-a-service/).
- A one-time importer carries earlier skills and custom MCP servers into extensions, reports what it could not migrate and never deletes anything.

### Changed

- Every command now goes through one decision point (`beforeCommand`) covering bash, network targets and the **Ask before running commands** setting. Any deny wins, then any ask, and a scope denial beats a prompt.
- Scope is a built-in extension that is on by default whenever a scope is set (`--scope`, a thread, Agent or automation scope, a pull request checkout). With no scope set everything is allowed. This reverses the 0.30 to 0.33 rule that a scope file alone never activates checks.
- If the scope extension is off or errors while a scope is set, commands are denied instead of allowed. Projects that already enabled scope keep it enabled.
- Every MCP tool is pinned by a hash of its name, description, schema and annotations. If a server changes, adds or removes a tool, the server stays blocked until you approve it again, and `0 skills extensions info <name>` shows Changed, New and Removed.
- MCP tool results are treated as untrusted: they are labelled, fenced and capped at 32 KB. Launchers such as `npx`, `uvx` and `pip` must pin an exact version, and remote hosts that resolve to private, loopback or metadata addresses are refused.
- `0 skills add owner/repo` goes through the extension prompt (pin it with `@<full sha>` to install). Catalog ids and `owner/repo/path` keep the earlier skill flow.

### Removed

- The old plugin system is gone. Installed plugins are kept on disk, imported once as disabled entries marked "could not migrate" and never deleted. Re-express them as scripts run through bash or as MCP servers.
- Executable plugins: the `plugin.js` runtime, loader, wire protocol and the per-tool approvals for them (first shipped in 0.16.3, review UI in 0.34.0).
- `self_extend`, the live harness (agent drivers, plugin views and harness trust) and the `allowModelSelfExtension` setting (0.14.0 to 0.16.3). The model writes a skill or script folder with bash and you install it through the install prompt.
- The plugin registry, the hackstore index, `ZERO_REGISTRY_URL`, plugin submit (0.14.0), and `ZERO_REGISTRY_PUBLIC_KEY_FILE` with Ed25519 registry signatures (0.30.0). Signatures and publisher identity are not offered; the defence is the install prompt, the commit pin, scope and the sandbox.
- The Plugins page, plugin detail page and Explore plugin entries (0.29.0 to 0.32.0), the browser MCP sheets and service plugin adapters (0.29.0), and their `/api/console` routes. `/plugins` redirects to `/extensions`; Elastic, Semgrep, Snyk and Jira connections are reported by the importer and their credentials are untouched.
- The Explore page and its Plugins and Themes tabs. Themes and backgrounds live in Settings > Appearance, and old Explore links open Extensions.
- `0 skills run` and the `0 plugin` commands. `plugin list|search|info|enable|disable|install` and `plugin mcp add|list|remove` stay as hidden aliases that print `moved: use ...`; the rest print `removed: ...`.

### Fixed

- A malformed glob in a command no longer fails the protected-paths check.
- Extension folder checks, update diffs, imports and git fetches are stricter, and built-in enablement has one store that is locked and audited.

### Security

- An agent can no longer approve its own extensions by flag. Approval commands refuse when a thread runs them, and commands from an agent that touch approval, enablement or settings files are denied. These are layers; the sandbox is the boundary (see `docs/design/extension-architecture.md`).
- Every executing tool (monitor, pty_session, python_exec, run_command and file tools) now goes through `beforeCommand`, and extension approvals are sealed.
- A connector's stored token reaches only the scripts and MCP servers of the extension that declared and was approved for it, and is masked in what comes back.
- MCP approval prompts show sanitised plain text with an old versus new description and schema diff. Extension server ids are namespaced (`x-`), and a dead process or hung call blocks the server.

## [0.35.0] - 2026-11-15

This release shrinks the CLI to nine commands, makes `0` open the console, and gives Threads and Agents one mode with shell access and a small core tool list.

### Added

- Choose the animated background behind a new thread in **Settings > Appearance > Background**. Dither stays the default. Nine others are live previews that follow the colour theme and pause when the tab is hidden.
- `0 threads start --cost-ceiling <usd>` stops a thread at a spend limit. `--wait` now prints the reply with its tokens and cost, and `0 threads show <id> --json` shows its usage.
- `0 web --headless` serves the API only, so it starts without built dashboard assets. A missing 0verse environment is skipped with one log line instead of stopping the console.

### Changed

- **The CLI is nine commands:** `scan`, `findings`, `threads`, `agents`, `skills`, `memory`, `models`, `computers` and `config`. Every old command and flag still works for one release and prints one dim `moved: use ...` line to stderr on a terminal (not when piped, in CI or with `--json`); exit codes are unchanged. The old-to-new table is on [CLI changes in 0.35](https://docs.0.security/cli-changes-0-35/).
- Running `0` with no arguments opens the web console. It takes the old `0 web` flags, for example `0 --headless` or `0 --port 8080`. Automations are under `agents --automation`, plugins, MCP servers and connectors are under `skills`, and `0 config doctor` replaces `0 doctor`.
- `scan <target>` is the one scan command. `--module deep|repair|campaign|deps|deps-fix` replaces the old scan subcommands.
- `findings update`, `threads send new`, `agents set`, `models set`, `models connect` and `config get|set` replace the older verbs. `computers add` is now the command name, with `computers deploy` as the alias.
- **There is one mode: Threads and Agents have shell access.** Read-only and Can make changes are gone from Threads, Agents, automations, scans, presets, slash commands, the browser app and the CLI. A run is limited by its scope (hosts and folders), its budget, the optional sandbox (SmolVM or Docker) and the **Ask before running commands** setting, which is unchanged and off by default.
- Saved Threads and Agents from older versions still load and are not rewritten. An Agent that was read-only is marked as needing review once because its authority widened. `--access`, `--mode`, `--autonomy` and `--tool-access` are accepted and ignored for one release.
- Pull request Agents run scoped to the repository's checked-out folder and still skip fork pull requests and drafts by default. The shell gets an allowlisted environment, so other provider keys and tokens are stripped unless you set `ZERO_BASH_ENV_ALLOW`.
- Threads and Agents now give the model 11 core tools instead of 17 plus a catalog of about 40 more. Specialist tools such as browser, HTTP probes, cloud, proxy and delegation load only when a skill that needs them is loaded. Set `ZERO_TOOLSET=full` for the previous list; scans keep the full list.
- `load_skill` with no skill ID lists the available skills. Old tool names keep working for saved threads.
- `0 --version` and `0 --help` start in about 0.15 s instead of 0.72 s because command modules load only when their command runs. They no longer run the startup update check or print the telemetry notice.
- `0 scan eval` and `0 scan agent-assure` move into plugins after this release, and `automation versions` and `automation rollback` are removed after it (use git history).

### Removed

- `--runtime ollama` and `--runtime gemini` are removed and fail with a clear error: use an OpenAI-compatible endpoint with `--runtime api`. Ollama serves one at `http://localhost:11434/v1`; see [Models and keys](/models/#ollama).
- The legacy `sourceReview` engine is deleted. The old `scan()` and package audit paths now live behind the internal `legacy-bench` directory.

### Fixed

- A long-running console no longer stops answering after heavy use. Model calls used one shared HTTP/2 connection that the provider could close, after which every later call failed with `fetch failed` until restart. They now use their own connections, replaced after any failure, and errors name the real cause. `/healthz` reports model transport counters.
- `0 threads start --folder` no longer fails with "Console thread is already processing a turn". The first prompt after a folder change now waits for the change instead of being refused, and no empty thread is left behind.
- `0 threads` commands now fail with "No console running. Start one with: 0 web --headless" and a non-zero exit when no console is running, instead of printing `[]`.

## [0.34.0] - 2026-11-15

This release lets the console update and restart itself, lets pull request Agents react to GitHub straight away in server mode, and shows exactly which tools change when you review a plugin update.

### Added

- **Update and restart** in the console. The **Update available** card now has an **Update and restart** button for standalone installs: 0 downloads the release, verifies its checksum, replaces the binary and restarts on the same port and database. Docker, source and npm installs show the right command instead.
- A running console keeps itself current. With **Updates** set to **Automatic** it checks every six hours and installs a verified release in the background when nothing is running, then restarts after 10 idle minutes. Server mode and service-managed consoles show the card instead.
- Server mode accepts GitHub webhooks so pull request Agents react at once. `POST /api/webhooks/github` checks a signature, accepts only `pull_request` and `ping`, and just asks the poller to check now, so polling stays the default and every review rule is unchanged.
- The per-instance webhook secret is generated on first use, stored with mode 0600, shown once, and can be rotated; the old secret keeps working for 5 minutes. Set it up from the **GitHub webhook** card on Agents and in Settings > Git (server mode only), or with the hidden `0 agents webhook status` and `0 agents webhook secret rotate --yes`.
- `pnpm test:webhook-e2e` runs a signed delivery, a replay, a bad signature and an oversize body against a throwaway server-mode console.

### Changed

- Reviewing a GitHub plugin update in the web app now marks each tool as Changed, New or Removed against the installed version, using the same per-tool hashes as the install check. Approval is still for the whole plugin.
- The update card reads **Update available · 0.34.0** with **You have 0.33.0** and a **What's new** link, instead of repeating the product name. **Settings → Updates** (Off, Notify me, Automatic) stays the one control, with a plain description.
- Agents is now the main page address: `/agents` is the route and `/sentinels` redirects to it, along with the other old addresses.
- Surfaces across the console use one corner radius (`rounded-md`), and a check keeps new styles from drifting.
- Copies older than this release cannot be updated remotely. Run `0 doctor upgrade`, or the install one-liner, once.
- Internal cleanup only: shared engine types moved to neutral modules, and unreferenced helpers and benchmark tooling were deleted. The Docker publish job now refuses to push any name other than `ghcr.io/0sec-labs/0security`.

### Fixed

- A page left open while the console restarts no longer reloads into the browser's error page.

### Security

- The GitHub webhook is the only anonymous `/api` route in server mode, and it is authenticated by its signature. Audit events `webhook.received`, `webhook.ignored` and `webhook.rejected` record a reason and never the payload, secret or signature.

### Removed

- Four unused enterprise hooks that shipped in v0.30.0 are gone: audit event subscriptions for plugins, offline verification of signed licences, support for an external identity provider for team sign-in, and the named-permission policy behind team roles. None was needed for open-source use: no signing key was ever bundled, so no licence was accepted, and built-in OIDC sign-in and the owner, editor and viewer roles behave as before. Ed25519 verification of plugin registry entries (`ZERO_REGISTRY_PUBLIC_KEY_FILE`) stays.

## [0.33.0] - 2026-11-15

This release makes access the same two choices everywhere: Read-only or Can make changes. Asking before each command is only the global setting.

### Changed

- **Upgrade note:** Agents that used Ask first and threads that used the ask-first modes now follow the global **Ask before running commands** setting, which is off by default, so turn it on (Settings, Helpers, or `0 config set approvals ask`) to keep confirmations. Stored values still load: older Observe and Recon read as Read-only, and Act, Run, Propose, Standard, Copilot and YOLO read as Can make changes; nothing is rewritten until you save the Agent. The hidden aliases `--mode`, `--yolo`, `--autonomy` and `--tool-access` still work. `0 threads start|set --approvals` now stops with an error that points to the setting. The first start after upgrading records one audit entry and shows one dismissible note in Settings > Helpers.
- Access has two choices everywhere: **Read-only** and **Can make changes** (runs commands, edits files and opens pull requests). Threads, Agents, automations, scans, presets and slash commands all use just these two, replacing the three Agent access levels (Read-only, Can run commands, Can open pull requests) and the older thread modes. The CLI takes `--access read-only|changes` on `0 agents create`, `0 threads start`, `0 threads set` and `0 lab console`, and the API takes an `access` field (`autonomy` and `toolAccess` are kept for compatibility, and `accessLevel` with `commands` and `pull-requests` is still accepted). The older names are gone from every screen, help text and doc.
- Whether commands ask first is no longer a per-thread or per-Agent choice. It is only the global **Ask before running commands** setting, off by default.
- Read-only refuses every command and edit, whatever the scope says. Access is separate from scope, which still means what a scan or Agent may target.

## [0.32.0] - 2026-11-15

This release simplifies approvals and Agent access, makes chat slash commands the same as the CLI commands, gives the console a seven-item sidebar and calmer Threads, and discontinues npm distribution.

### Added

- Real brand logos on Explore and Skills rows: each connector mark sits on its brand colour in a 48 px tile (white or black glyph, whichever reads better), and skills show the publisher's avatar with stars and the owner's name. Nothing is fetched from a third-party site. Slack and Teams stay a brand-coloured letter tile.
- A Thread turn that ends without an answer says so. A quiet line under your message reads "The model returned no reply.", "The reply was cut off.", "The provider blocked this reply." or "The connection dropped before the model answered.", with Retry, Continue or Switch model. Partial progress is kept and the Thread is marked "Needs attention" in the sidebar.
- A failed send now says what happened and what to do: your message could not reach the model, the connection dropped, the model took too long, the provider is busy or rate limiting, the model is unavailable, the thread is too long, a folder needs access, or the connection needs signing in. Retry shows only when trying again can work, and your progress is kept.
- Agents have three access levels: **Read-only**, **Can run commands** and **Can open pull requests**. Create one with `0 agents create --access read-only|commands|pull-requests`. Existing Agents keep exactly their behavior; the API adds a derived `accessLevel` and keeps `autonomy`.
- A setting, **Ask before running commands** (Settings, Helpers; `0 config set approvals ask`), also `--approvals ask|auto` on `0 lab console` and `0 threads start|set`.
- The container image is also published as `:edge`, rebuilt nightly from the newest main commit whose checks passed.

### Changed

- Chat slash commands are now the CLI commands: `/threads start`, `/threads list`, `/findings list`, `/models default`, `/config get`, `/agents list`, `/doctor` and more mirror `0 threads start` and so on. The `/` menu is grouped, filterable and shows the CLI command for each entry. Old names such as `/new-mission`, `/sessions`, `/history`, `/connect`, `/plugins`, `/settings` and `/model` still work as aliases. The stale `/onboard`, `/chat`, `/launcher`, `/ops`, `/back` and `/scope` commands are gone, and `/exit` is now `/threads close`.
- The sidebar has seven items and no More menu: New thread, Findings, Automations, Skills, Memory, Computers and Explore. Computers is always listed and no longer appears under Settings.
- Skills has its own sidebar entry with **Installed** and **Browse** tabs. The GitHub skills directory moved from Explore to Skills > Browse, and Explore keeps Plugins and Themes. Old `/plugins/explore?tab=skills` links redirect to Skills > Browse.
- Approvals are simpler. Threads and Agents run commands automatically by default and never ask first, unless you turn on **Ask before running commands**. The old approval wording is gone from the app, CLI help, errors and docs. `--yolo` and `--mode` still work as hidden aliases, and Threads saved earlier keep working: stored values are read, never rewritten.
- Scope now means one thing: what a scan or Agent may target. The thread Permissions card is the Scope card, its two confirmation checkboxes and "Limited to" text are gone, and your chosen folder is always allowed. Third-party target authorization remains an optional plugin.
- The thread work log is calmer. Only the newest active item shimmers (the running call, else the Thinking row, else the Working label), so a Thread has one shimmer at a time. Each call is one row that changes in place from Running to Ran, and two or more finished calls fold into one line such as "Read 3 files and ran 2 commands" that opens on click. Questions from the Agent are a flat list instead of a bordered card, and after you answer the Thread keeps one "Answered: <choice>" line.
- The thread composer dock is tighter and cleaner: the transcript no longer dims its last lines above the composer, there is less empty space under the footer row, and the Scroll to latest pill is smaller and sits clear of the card.
- Hover and focus follow one language across the app: rows, cards and table rows get a light overlay, bordered chips and selects step from button to button-hover, text fields and switches draw a 1px inset focus ring, sidebar thread row actions appear on hover or focus (always on touch), and icon-only buttons show a tooltip taken from their label.
- Thread message actions (time, Reply, Copy, More) sit in reserved space above each message instead of covering its first line, with tooltips, a "Copied" confirmation and keyboard and touch access. The code block copy button shows a tooltip too.
- Old installs find and apply updates whatever the repository is called: the latest-release lookup falls back from the API to the release redirect, the repository id and the old name, the installer script falls back between names, and an upgrade replaces the folder of the running binary instead of always using `~/.0/bin`. An install made with npm gets a hint in `0 doctor`, `0 doctor upgrade` and at startup on how to move to the installer.
- The container image is published only as `ghcr.io/0sec-labs/0security`; `ghcr.io/0sec-labs/0` is no longer updated, so switch to the new name. Images are published for releases and for nightly `:edge`, not for every commit on main.
- For contributors: CI runs fewer workflows. Docs-only changes skip test groups, Windows storage and dependency audits run only for the paths they cover, superseded integration runs are cancelled, and Main also runs on release tags. A guard keeps workflow triggers lean.

### Fixed

- Findings board: dropping a card lands in the column under the pointer, a card moves out of Accepted and Cancelled at once, Accepted accepts drops, columns are reachable by edge auto-scroll, touch and keyboard (Space, arrows, Space), and refused moves (review stages, a finding that needs review) are shown in the column and in a message instead of silently doing nothing. The workflow API now rejects unknown or engine-only statuses with a clear error instead of storing them as Backlog, so it enforces the same transitions as the board.
- Reopening a thread no longer shows calls that have not started as Running.

### Removed

- npm distribution is discontinued; install with `install.sh`, the release binaries or the Docker image. A check fails CI if npm publishing returns.
- The composer options menu (Ask before acting, Act without asking) and the two confirmation checkboxes in thread settings.
- The notice that announced a silently granted local scope in threads.

## [0.31.0] - 2026-11-14

This release renames Missions to Threads and Sentinels to Agents, brings most of the console to the CLI under 14 top-level commands, and shows whether a model connection really works. It also adds an experimental single-node server mode and automatic anonymous usage and crash reports.

### Added

- The CLI has 14 top-level commands: `web`, `scan`, `findings`, `threads`, `agents`, `automation`, `models`, `computers`, `skills`, `plugin`, `memory`, `config`, `doctor` and `api`. Old command names keep working as hidden aliases with the same behaviour.
- New CLI groups cover what the console does: `threads`, `agents`, `automation`, `findings export` and `findings keys`, `skills`, `memory`, `config get` and `config set`, `computers list`, and `models` with connections and usage.
- `plugin connectors`, `plugin mcp` and `plugin github install` manage plugin connectors, MCP servers and GitHub installs, and `config audit-log` reads the audit log.
- **Experimental single-node server mode.** `0 web --host 0.0.0.0 --server-mode` serves the console behind a TLS proxy. It is off by default and local use is unchanged.
- Server mode requires sign-in (team accounts, or an access token of 32 or more characters), an explicit `--allowed-host` list, and `--trusted-proxy` and `--public-url` for the proxy.
- The web console port answers `/healthz` and `/readyz`, and a `SIGTERM` drains running work gracefully (`--shutdown-timeout`). The audit log records console sign-ins, failed sign-ins, throttling and refused hosts.
- The Docker image now serves the web console by default, exposes port 48123, has a health check, keeps its state in a `/data` volume, runs under `tini` and carries image labels. Release builds also publish `vX.Y.Z` and `X.Y` tags.
- `deploy/compose/` holds a single-node Docker Compose file, an `.env.example` and an optional Caddy profile with automatic HTTPS.
- The Docker image includes the OpenSSH client, so remote computers can be connected over SSH from a container. `0 computers deploy --ssh` now says how to install `ssh` when it is missing.
- Anonymous usage and crash reports are on by default in official release builds, with a notice on first run. Usage holds counts only: tool and error counts, findings by severity, turns, time, cost, version, operating system and a random install ID. Crashes hold the error class and scrubbed locations in 0's own code.
- Reports never hold targets, findings, code, prompts, file paths or error messages. Turn them off with `ZERO_NO_TELEMETRY=1`, or `0 config set analyticsLevel off` and `0 config set diagnosticReporting off`, or in Settings, Privacy. See [Telemetry](/configuration/#telemetry).
- Updating a plugin installed from GitHub says which tools were added, removed or changed. Each tool has its own hash over its name, description, parameters and capabilities, so a changed description is caught too. Plugins installed earlier count as having all tools unreviewed. Thanks to @Amresh-01 (#367).
- Pull request Agents have two opt-in toggles, both off by default: **Comment on the pull request** posts one short summary (severity, title and repository-relative location only), found by a hidden marker and edited in place on later pushes, and **Include pull requests from forks** runs read-only analysis of the diff marked untrusted. Set them in the Agents page trigger dialog or with `0 agents triggers add --comment --include-forks`. `0 agents triggers check` polls a trigger now.

### Changed

- Missions are now Threads and Sentinels are now Agents, in the console, the CLI and the docs. `0 missions` and `0 sentinels` still work. The Settings page that was called Agents is now Helpers, and "this machine" now says "this computer".
- Memory has its name back after 0.30.0 renamed it. `/memory` is the page address again, and `/learning` redirects to it.
- Automation templates no longer talk about a separate place to run, and automations run in the current folder.
- A connection reads **Connected** only when the provider accepted its key. Connections, Models and Diagnostics show **Key rejected** or **Can't reach** with a one-line hint, including for keys set in the environment. The check is cached and never blocks the page, and Connections says when an environment variable wins over a saved key.
- Choosing Desktop, Documents, Downloads, iCloud Drive or an external drive on macOS waits for the permission prompt instead of accepting the folder after three seconds. The picker shows checking, waiting, blocked and retry states, and the folder changes only once access is granted.
- GitHub Releases are now titled with the bare tag, for example v0.31.0.

### Removed

- The Suggestions view in Memory and the Learning section on the Automation page are gone. Memory lists saved memory only.

### Fixed

- Pull request Agents now skip fork and draft pull requests by default and record a skipped activation with the reason, instead of reviewing them. A pull request marked ready for review is reviewed once. Closed and merged pull requests are ignored.
- New threads and Home no longer default to a model from a provider whose key was rejected, and a remembered choice from one is skipped.
- An empty thread no longer keeps a model its provider stopped listing. It switches to a usable model and the model button matches. A thread with history says the model is no longer available and waits until you pick another.
- A message that fails with a rejected key names the provider and model and offers **Switch to** a working model, which resends the message, and **Manage connection**. **Ask 0 to get started** shows **Connect a model to get started** when no model works.
- macOS privacy blocks on protected folders are explained: the picker names the app to allow and offers **Open Privacy settings**.
- Folder fixes: the chooser no longer opens for a browser on another computer or without a desktop session, closing the popover closes the chooser, and a switch to a symlinked, differently cased or decomposed-unicode path no longer waits 8 seconds.
- Home shows its composer at once, loading shows a thread-shaped skeleton, and loads no longer stick or flicker.
- A browser tab left open across an update reloads itself once instead of showing "Something went wrong".

### Security

- Plugin updates report per-tool changes, so a tool whose description changed is visible when you review the update (#367).

## [0.30.0] - 2026-11-14

This release reorganises the web console around a shorter sidebar and a Models page, adds a guided GitHub connection and a What's new dialog, and gives Automations eight ready-made starting points. It also adds hooks for enterprise add-ons and faster, safer releases.

### Added

- Add a GitHub connection card in Settings that reuses an existing `gh` login, signs in with a device code, or guides you to a fine-grained token with the right permissions prefilled, and shows a "Needs permissions" state when the connected account lacks access.
- Add a What's new dialog that opens once after an update, and a sidebar card that reopens it.
- Add eight outcome-named starting points for Automations (code review, deep code review, dependency check, secrets and config check, smart contract review, native code review, web app test and API authorization test), each with a ready-to-use prompt; code starters run on the current project and web starters ask for a URL.
- Add a summary-first run dialog for Automations that shows where it runs, the number of steps, the time and cost caps and the model on one line, with the step detail behind Details.
- Add a **Show cost and usage** switch in Settings that hides cost, token counts and the context meter.
- Add `0 reports export` and a `share-report` option in the GitHub Action, which write a `report.share.json` copy without evidence, proof-of-concept steps or local paths; see [Reports](/reports/).
- Add audit event subscriptions for plugins: a plugin can receive every audit event after it has been redacted, and a failing subscriber never affects auditing.
- Add offline verification of signed licences for entitlements; no signing key is bundled yet, so no licence is accepted today and nothing changes for open-source use.
- Add Ed25519 verification of plugin registry entries when you set `ZERO_REGISTRY_PUBLIC_KEY_FILE` to a PEM file of public keys; with a key configured, unsigned or badly signed entries are refused, and without one nothing changes.
- Add support for an external identity provider to handle team sign-in; the built-in OIDC sign-in is used when none is installed.
- Add a documentation page on Open source and Enterprise, and publish the container image under `ghcr.io/0sec-labs/0security` as well as the old name.

### Changed

- Change the sidebar to New mission, Findings, Automations and Explore, with Lessons and Computers (when a remote computer is connected) under More.
- Move Skills and Plugins under Explore, move Computers into Settings, and rename Memory to **Lessons**.
- Move model connections to a Models page with a Providers list at `/models`; `/connections` now redirects there.
- Use one vocabulary in the console (Project, Computer, Team and Environment) and rename Scope and autonomy to Permissions.
- Regroup Settings into Preferences, Agent and Activity, and keep privacy and support in General.
- Make Automations use the current project automatically, show **This project** instead of a project picker, and offer a project folder list from your recent projects when you choose Change.
- Route team authorization through named permissions that a replaceable policy can override; default behaviour is unchanged.
- Run CI checks as parallel jobs behind one required `verify` check.
- Run the native-binary release dry run every night and on changes that affect the binary, using one shared smoke script.
- Generate GitHub Release notes from this changelog, and fail a release that has no changelog section.

### Fixed

- Fix switching project folders so the folder picker stays in sync, `~` expands to your home folder, errors are in plain words, and new missions start in the last project folder you used.

### Security

- Refuse unsigned or badly signed plugin registry entries when an operator has configured a registry public key.

### Removed

- Remove unused code, duplicate tests and stale assets, including the old workflows demo video and an unused theme preview.

## [0.29.0] - 2026-11-14

This release moves 0 to a new web console (Capy design system), adds Sentinels, a skills directory and recommended models, consolidates the CLI into fewer commands, and drops npm distribution in favour of native binaries. It contains several breaking changes: see Removed and the CI behavior change under Changed.

### Added

- Add a redesigned web console with a neutral default accent (orange is optional), a Mode setting that follows the system, and a theme gallery in Settings → Appearance and Explore with ten colour palettes in light and dark.
- Add Sentinels: standing security agents with a scope, tool access, memory files, an autonomy level (Report only, Ask first or Act on its own) and one daily budget, shown on the `/sentinels` page and the `/api/console/sentinels` API; see [Sentinels](/sentinels/).
- Add ten Sentinel presets (PR Security Reviewer, Pen Tester, Dependency Watcher, Fix Engineer, Secrets Hunter, Attack-surface Monitor, Cloud Posture Auditor, Incident Triage, Web Regression Tester and Release Security Gate), each created paused from a one-step flow that asks only for a name.
- Add three Sentinel triggers (schedule, manual and GitHub pull request); a background scheduler runs schedules and polls open pull requests through the connected `gh` account, and the first poll only records pull requests that are already open.
- Add Skills with Installed and Explore tabs, and a curated directory of 47 skills from nine public GitHub repositories with category groups, plain-language summaries, a detail page with the full `SKILL.md` preview, and **Add from GitHub repository**.
- Add Explore tabs for plugins, skills and themes, and a detail page for each plugin.
- Add custom MCP servers (stdio, HTTP and SSE) and plugin install from a GitHub repository to the browser console, where GitHub plugins are pinned to a commit, installed disabled and never auto-updated.
- Add recommended models for four roles (main model, reading code, hard problems, titles and summaries), chosen from one engine catalog, shown first in the model picker and in Settings, and limited to models you can actually reach.
- Add API key validation when you connect a provider: one authenticated request runs before saving, and a rejected or unreachable key is reported inline (OpenRouter, xAI, Z.ai and OpenCode Zen are checked this way too).
- Add a global default model, set from one picker in Settings → Models and used for new missions that have no remembered choice.
- Add a visible "Rate limited, retrying in Ns" status when a provider answers 429, driven by a new retry event.
- Add connection controls: rename a connection, reorder accounts, spread new missions across a provider's saved accounts, turn off individual models (`409 model_disabled` when one is selected) and show OpenRouter key usage.
- Add automatic mission titles after the first exchange (a short model-generated title with a fallback, never overwriting a title you set), plus a `titleInstructions` setting.
- Add subagent limits (`subagentConcurrency`, `subagentMaxDepth`, `subagentFanOut`) and `archiveIdleDays` in Settings → Missions, and `ZERO_REAP_IDLE_RESUMED_MS` to close resumed missions that were never used.
- Add the `visualize` tool and inline graphs, attack graphs, charts, timelines, tables and Mermaid diagrams in missions, rendered by the browser from size-capped plain data; see [Inline visualizations](/visualizations/).
- Add mission conveniences: open saved missions in the live conversation, retry and thread actions, a curated slash menu, finding and mission mentions, a shortcuts dialog (Cmd+B toggles the sidebar), command palette tabs with recents, and browser notifications for mission events.
- Add Automations that choose a model and reasoning effort, list tabs and a schedule form.
- Add a "Finish setting up" sidebar card (connect a provider, start a mission) and an "Ask 0 to get started" action that runs the first mission.
- Add windowed mission snapshots and long-poll events (`GET /api/console/sessions/:id?window=<n>`) so long missions load and reconnect faster; the default snapshot is unchanged.
- Add an opt-in self-edit preview (`ZERO_SELF_EDIT=1`) that edits a `self/*` worktree and previews it on loopback ports; apply is not implemented and nothing reaches the running dashboard.
- Add `ZERO_MAX_COMPLETION_TOKENS` (default 8192, clamped to 131072) to cap completion tokens on every model call; see [Configuration](/configuration/#completion-token-cap-zero_max_completion_tokens).
- Add a `0 reports import` command and CI action options (changed-only scans, an empty-diff skip, a step summary, proposed fixes as pull request suggestions and `static-only`) for importing pipeline reports into the browser; see [CI](/ci/github-action/).
- Add `ZERO_EDITION=core|full` to leave the identity, Entra, AD and kernel-fuzz research packs out of a build.
- Add a rewritten documentation site organised around tasks, with a Concepts glossary, a Browser interface page and an FAQ.

### Changed

- Change the web routes to `/chats`, `/computers`, `/scope` (the Reports page), `/plugins/skills`, `/sentinels`, `/automations`, `/findings`, `/plugins` and `/settings`; the old `/console`, `/workers`, `/engines`, `/engagements`, `/skills`, `/operations`, `/threads`, `/scans`, `/live` and `/dashboard` URLs redirect, and `/runs/:id` stays as the Report view.
- Rename the machines page to **Computers** (`/computers`, with an "Add computer" action); the CLI keeps `--engine` and `--engines-config`, with `~/.0/engines.json` as the registry and `backends.json` as a read-only fallback.
- Use one vocabulary across the console: Mission, Automation, Report, Scope, Sentinel, Computer and a single "Plugin" concept (MCP servers and tool plugins are kinds of plugin).
- Slim Settings to ten pages (General, Appearance, Missions, Notifications, Shortcuts, Instructions, Agents and privacy, Git and pull requests, Usage and Audit log); old `?section=` links redirect, and the Profile, Experiments, Activity, Finding states, Integrations, Skills and Members pages are gone.
- Change Accept on a finding to record an accepted risk that leaves the review queue but stays visible as Accepted, Dismiss to close a false positive, and Undo to restore the previous state.
- Route API-key model calls through the pi runtime by default; ChatGPT Codex, Azure, OpenCode, z-ai, kimi, qwen and granted transports still use the built-in client, `ZERO_RUNTIME=legacy` forces it everywhere, and `ZERO_RUNTIME_TRACE=1` prints which client served a call.
- Change provider rate-limit handling to give up after 30 seconds by default (was 5 minutes), so the error and Retry appear promptly; `ZERO_LLM_429_MAX_RETRY_WAIT_MS` still overrides.
- Change default models to Claude Sonnet 5.5 for Anthropic and OpenRouter, Grok 4.7 for xAI and gpt-6-luna for OpenAI-family models.
- Limit autonomy choices in the console to "Ask before acting" and "Act without asking".
- Change `0 scan` to a single entry point that picks a module (web, source, package, deep, repair or campaign) from the target, and move specialist commands into `research`, `runs`, `findings`, `improve` and `plugin author` groups; old command names keep working for one release with a stderr notice.
- Rename CLI flags `--backend`, `--backends-config`, `--session` and `--workflows` to `--engine`, `--engines-config`, `--chat` and `--automations`; the old spellings remain as hidden aliases.
- Make `0 scan` exit 3 and report `aiAnalysisSkipped` when its AI layer was needed but skipped, unless `--static-only` was passed on purpose.
- **CI behavior change:** `0 research intel cve <id>` now exits 1 when no intel is found, in text and `--json` modes, so a CVE that NVD does not list yet or an `--offline` cache miss fails CI unless you pass `--allow-missing`.
- Make `0 deps fix` print the command only, without running it, unless `--yes` is passed.
- Install updates automatically at startup when no update policy is set; only an explicit notify or off choice opts out, and project settings cannot change it.
- Make usage of a model with no pricing entry (custom or free-tier endpoints) record $0 with one warning instead of aborting runs or tripping cost caps.
- Declare `MIT OR Apache-2.0` in package metadata, ship both licence files, and leave source maps and type declarations out of the CLI package.
- Release native binaries for macOS arm64, Linux x64, Linux arm64 and Windows x64 with checksums on the GitHub Release, each smoke-tested on its own runner.
- Load the console lazily so first-load JavaScript is roughly halved, and show flat loading skeletons, calmer page headers and bottom-right toasts.
- Speed up `0 db reset` (from about 15 seconds to about 1) and make it also remove `<db>-journal` and the `<db>.lock` directory, refusing, with nothing deleted, when the path is a directory, the lock owner is alive or an owner-less lock changed within 5 minutes.

### Fixed

- Fix deleting the open mission so it lands on a fresh composer and stays deleted, and make Retry re-run the failed turn in place.
- Fix failed first turns, failed sends and stopped replies so they show inline with Retry and keep their text.
- Fix duplicate creates on double click, abandoned mission drafts, and the model picker stealing focus or dropping connected providers while discovery is pending.
- Fix the shell staying usable when a page chunk fails to load: it retries every 5 seconds, reports offline and recovers when the server returns.
- Fix keyboard focus rings and muted text contrast to meet AA, and long unbroken text overflowing in dialogs, headers and skill pages.
- Fix GitHub token rejection returning 500 instead of 422, the engine crashing on `GET /assets`, and malformed percent-encoding or null bodies returning 500 instead of 400.
- Fix finding deduplication merging findings with different evidence, and keep the finding lifecycle intact for findings reported by subagents.
- Fix confirmed autonomy changes not applying to tool actions that were already waiting, and keep mode changes separate from source-learning grants.
- Fix concurrent database writers failing immediately, opening a read-only 0444 database, redaction of CRLF-terminated `Authorization`, `Cookie` and `X-API-Key` headers, slow redaction patterns, and NaN, Infinity or negative token counts bypassing cost ceilings.
- Fix package names starting with a dash reaching npm, pip, cargo or docker, and empty ids or non-domain targets in `0 disclose`, `0 research intel` and `0 research recon` exiting 0.

### Removed

- Remove the full-screen onboarding; `/onboarding` and `/setup` redirect to Missions.
- Remove Sentinel crew settings and the default `CREW.md`; subagents follow the global subagent limits, and old stored crew data is ignored.
- Remove Sentinel triggers other than schedule, manual and GitHub pull request, and replace per-run cost and time caps with one daily USD cap and a daily run limit; stored Sentinels in the old shape still load and the old caps are ignored.
- **Migration note (providers):** remove the Cline / ClinePass, GitHub Copilot and Gemini Code Assist (OAuth) providers, with their sign-in flows, model catalogs, connection tiles and the `cline/`, `cline-pass/` and `copilot/` model prefixes; saved credentials and chats stay on disk and are ignored, and a saved selection falls back to the next configured provider, or fails with `provider_removed` (HTTP 400) when chosen explicitly through the web API.
- **Migration note (Jev):** remove the Jev commands with no alias or successor (`0 research radar`, `0 research kernel jev-prepass`, `jev-commit-prepass`, `jev-source-prepass` and `crash-triage`, and `kernel weights --jev-prepass`), along with the `ZERO_JEV_*` variables, which are now ignored; use `0 research hunt`, `0 research recency-hunt` or `0 research ingest` instead.
- Remove 21 terminal-only settings left over from the retired terminal UI (such as `showStatusBar`, `mouseSupport`, `leaderKey`, `composerStyle`, `richToolCards` and `keybindings`); settings files that still contain them load normally and drop the keys on the next save.
- Remove the retired terminal renderer and the top-level `chat`, `dashboard`, `update`, `hack`, `store`, `tui`, `watch` and `theme` commands and `console --prompt` and `--autonomy`, with no alias.
- Remove npm distribution and the npm install instructions; install with `install.sh`, Docker or a release binary.
- Remove the verify-stage skill pilot (`ZERO_FEATURE_SKILL_VERIFY`) and the unused `OpenRouterRuntime` adapter.

### Security

- Make the engine bearer token (held by attached engines, host workers and the remote proxy) default-deny for mutating `/api` routes outside a small allow-list; anything that runs code as the operator, changes credentials, consent or execution settings, installs plugins or MCP servers, or creates automations needs the browser control token and returns 403 `browser_only`.
- Require approval of the exact reviewed configuration (a fingerprint that also binds env and header values through a per-install keyed MAC) before a custom MCP server or GitHub plugin can be created, edited or enabled, and block env entries that load code into the server process (`LD_*`, `DYLD_*`, `NODE_OPTIONS` and similar).
- Make the browser settings reset scoped: resetting display and behavior settings leaves safety and privacy settings untouched, and those reset only through their own action after a preview.
- Add Settings → Instructions, with operator-owned global and per-workspace `AGENTS.md` files (32,000 characters each, browser-only) appended to mission system prompts in a delimited trusted block; instruction files inside a target repository are never loaded.
- Add an append-only local audit log of privileged actions (approvals, plugin, connection, settings and Sentinel changes, resets and engine-bearer denials) with no secret values, viewable and exportable in Settings → Audit log.
- Send a Content-Security-Policy and companion security headers with the dashboard HTML, limiting scripts to same-origin modules and hashed inline scripts.
- Record a `skill.install` audit event for every skill install, which copies only the pinned folder, never runs scripts and never overwrites; see [Plugins: trust model](/plugin-trust/).

## [0.28.11] - 2026-11-13

### Fixed

- Guard shared-checkout writes across owned workers and parent tool calls. Allow parallel reviewers through inherited, enforced read-only delegation; retain local-tool attempts and confirmed direct-edit observations without claiming an unchanged filesystem.
- Keep discovered Together model prices provider-scoped and support `TOGETHER_MODEL_LIST=all` for catalog rows without published token prices.
- Reject incomplete or malformed OpenAI-compatible and Responses token receipts; ignore invalid cache discounts conservatively and explain missing workflow usage without disabling cost ceilings.
- Preserve current assistant observations when a worker returns a generic completion summary, including executable-driver completion. Advertise supported HEAD and OPTIONS HTTP requests.
- Make frontend and backend development reload reliably on selected ports, detect watcher failures, and drain owned development processes on shutdown.
- Patch Hono and its Node server adapter for current security advisories.

### Tests

- Add actual native-loop and built-CLI worker orchestration checks, cancellation/draining regressions, real HTTP method contracts, provider receipt regressions, and development-runner lifecycle checks.

## [0.28.10] - 2026-11-10

### Added

- Add Together AI with explicit provider selection, isolated credentials and public-catalog model discovery, including zero-priced models.
- Choose custom OpenAI-compatible models from a dropdown after connecting; retain manual model IDs when discovery is unavailable.

### Fixed

- Bind custom model catalogs to the current credentials and endpoint, reject connection-switch races, and display discovery failures.
- Pass native tools to Claude Code through an authenticated local bridge. Drain the owned client on loop completion, refresh tool definitions, prevent duplicate calls, and reconcile usage receipts.
- Preserve in-flight user/tool history after confirmed force-stop teardown without restoring callbacks, runtime authority or checkpoints.
- Correct published context metadata for known OpenCode Go models in the picker and active display; explicit captured limits take precedence.

## [0.28.9] - 2026-11-09

### Added

- Inspect and stop owned descendants through the existing agent tool, with bounded terminal history and explicit cleanup state.
- Expose explicit `0 sessions force-stop` for qualified live sessions through the existing authenticated owner route; reject saved aliases and unsupported execution without replay.
- Preserve idle private chat branches through authenticated, exclusive save-as snapshots without replacing the original transcript.

### Fixed

- Allow one fresh ten-second Windows ACL retry after the initial five-second timeout, retaining permission checks and fail-closed behavior.
- Patch the optional firmware terminal dependencies to Urwid 4.0.7 and wcwidth 0.4.0 without changing the firmware engine.

## [0.28.8] - 2026-11-09

### Added

- Confirm local console Force stop on Bun for macOS and Linux only after the dedicated execution process and registered tool resources have exited. Retain conversation history, queued messages, scope, and captured provider/account/model selections (#229).
- Qualify the actual compiled native worker and private bootstrap protocol in release smoke checks using a loopback-only synthetic provider.

### Fixed

- Quarantine unconfirmed startup and teardown across save and resume; never dispatch a cancelled startup request when readiness arrives late.
- Retain quarantine, captured account/program bindings, paused operator messages, and staged context when large or deeply nested worker display data exceeds persistence limits. Recover metadata without invoking getters or serialization hooks.
- Await private runtime-change acknowledgements and retain explicit Daybreak selection, actual provider receipts, and OpenCode Go conversation affinity across worker replacement. Keep independent worker forks in separate routing conversations.

### Changed

- Preserve the existing execution adapter for Node, Windows, enabled Jev capabilities, and unsupported live transports. Switching an already supervised chat to a native-plan transport or model relay requires a new chat before changing its captured connection.

## [0.28.7] - 2026-11-09

### Added

- Select Daybreak Blue, Daybreak Red or standard access independently of the model in CLI assessments and the console. Support public OpenAI Responses and existing ChatGPT/Codex OAuth connections while preserving account and tool permissions.
- Retain requested access programs separately from provider-confirmed response metadata; reject unsupported routes without switching providers.

### Fixed

- Send stable conversation session headers and the 0 user agent to current and legacy OpenCode Go endpoints, including custom OpenAI-compatible connections (#281).
- Reduce Windows ACL verifier cold-start overhead while retaining fail-closed ACL checks and the existing deadline. Three measured fresh-runner probes fell from 2.85–4.83 seconds to 1.91–2.20 seconds; arbitrary host startup stalls remain possible (#280, #282).

## [0.28.6] - 2026-11-09

### Fixed

- Validate Windows evolution and executable-plugin storage using native ACLs instead of unsupported POSIX permission bits. Retain ownership, private-access and reparse-point protections.
- Keep delayed executable-plugin initialization failures observable without crashing the dashboard through an unhandled rejection.

## [0.28.5] - 2026-11-09

### Fixed

- Preserve findings already saved during discovery in failed scan aggregates, without marking unverified candidates or incomplete execution as successful.
- Preserve workflow and step deadline causes in owned assessment reports instead of attributing automatic expiry to operator cancellation.
- Align scan help and documentation with scope-plugin activation, timeout precedence and the published npm package.

### Documentation

- Correct browser, provider, Findings, collaboration and research-workflow guidance against current code. Replace historical roadmap sprawl and duplicated examples with current workflow links; retain earlier planning snapshots in Git history.

## [0.28.4] - 2026-11-08

### Fixed

- Retain all Ollama tool calls when they arrive in separate streaming chunks instead of overwriting earlier requests.
- Explain native tool-calling requirements when Ollama explicitly rejects the selected installed model/template.

## [0.28.3] - 2026-11-08

### Fixed

- Persist console findings from background and nested agents through the root session's selected database, with duplicate suppression and cancellation fencing. Keep non-console scan persistence behavior unchanged.
- Return a finding-save failure before publishing to memory when its database write fails, so a retry cannot falsely report an unsaved duplicate as saved.
- Keep the global search input anchored as asynchronous results grow or shrink, with viewport bounds and keyboard behavior preserved on desktop and mobile.

## [0.28.2] - 2026-11-08

### Fixed

- Refresh stale account-model catalogs when model pickers reopen, retaining visible rows during discovery and reusing fresh cached results.
- Update the Codex protocol baseline used for account-model discovery and Responses headers, pick up refreshed CLI login credentials for new runtimes without changing existing chat bindings, and show actionable expired-login diagnostics.
- Interrupt process-monitor readiness and wait polling on session cancellation while preserving truthful process status.
- Correct the public npm install command, installer PATH persistence description, and scope-plugin activation in local and Docker quickstarts.
- Bind evaluation claims to retained run receipts, distinguish clean-control false-positive rates from finding-level precision, and remove unsupported training-exclusion claims.

## [0.28.1] - 2026-11-08

### Security

- Build supervised child-process environments from the existing allowlist instead of inheriting the operator environment. Screen explicit overrides using the same credential filtering. Thanks to Frank Kuhn (Swipergy GmbH) for reporting the monitor-process environment disclosure.

## [0.28.0] - 2026-11-08

### Added

- Session-owned background workers with unified delegation and an abortable FIFO execution queue.
- CLI-first setup for external agents in the browser console.

### Changed

- Drive investigations by evidence rather than implicit turn quotas, with uncapped interactive and native execution.

### Fixed

- Keep parents alive while owned background work is pending, preserve worker results under mailbox backpressure, and restore persistent workers correctly.
- Preserve running agents when queueing follow-ups and report cancellation cleanup accurately.
- Preserve console drafts, isolate typing from transcript rendering, present operator questions individually, and reconnect interrupted planner requests on transport errors.
- Preserve CRLF read-file windows and reject dangling symlinks during scope checks.
- Locate SARIF findings at cited source lines with correct source roots and encoded artifact paths.
- Align the documentation Astro dependency with its patched resolution.
- Mark failed or incomplete scans accurately, preserve fenced Markdown evidence, and report CLI command failures without stack traces.
- Correct the private vulnerability-reporting contact and fully fund the benchmark pilot's declared final reserve.

## [0.27.0] - 2026-11-05

### Added

- Self-directed campaigns with console-visible iterations, retained journals, follow-up verification, and optional documentation-grounded severity triage.
- Runtime model-pricing discovery and cost reporting for chats and engine-routed planning.
- Account- and backend-scoped model catalog caching across page refreshes, with first-load skeletons and a readable All providers filter.

### Changed

- Keep source counts and links inside their tool activity group.
- Preserve cached model choices during background discovery and share scoped catalogs across model settings and onboarding.
- Base plan capacity on open tasks so completed and dropped tasks free space.

### Fixed

- Remove privileged kernel-build containers and host-side Makefile execution; read the release from the built image and disable Git fsmonitor hooks during fingerprinting.
- Authenticate DNS ingestion before reading request bodies, reject oversized OAST requests, and bind OAuth loopback callbacks to private transaction paths.
- Upgrade the Hono node-server adapter to its patched major version and reject provenance content changes with unchanged file metadata.
- Stop dispatching queued subagents after cancellation, while preserving cleanup and terminal outcomes for active work.
- Preserve CRLF files, intentional blank process-log lines, readiness matches, and filtered log cursors; handle closed process stdin safely.
- Keep findings evidence and review metadata from the same database row and correctly classify nested tool errors and cancellations.
- Normalize cross-provider model pins and pricing identifiers, and honor guided-scan goal and planning-time options.


## [0.26.0] - 2026-10-31

### Added

- Searchable provider-aware model selection with keyboard navigation and official model/provider marks.
- Workspace directory browsing and native folder selection for local chats.
- Expanded provider connection, web-search fallback, and tool-catalog provenance support.

### Changed

- Show assistant text and tool calls chronologically, with readable command/output details and one live activity row.
- Keep agent progress in a stable list and place agent/task controls beside the workspace picker.
- Open findings on full detail pages with simpler severity, sorting, and review controls.
- Watch frontend and backend changes together when running `npm run dev`.

### Fixed

- Preserve validated saved-chat configuration and prevent failed resumes from overwriting retained history.
- Return saved-chat metadata without repeatedly sending complete transcript display state.
- Continue console tool rounds and provider output automatically without arbitrary default count limits; preserve explicit limits and cancellation.
- Reconcile idle task status, completion timelines, provider usage accounting, and model connection recovery.
- Avoid hidden, unmetered model inference when saving findings, while preserving explicit impact assessments.
- Preserve advisory review checks and warnings in rich HTML/PDF report exports.

## [0.25.0] - 2026-10-27

### Added

- Shared UI primitives, motion, skeleton loaders, and consistent composer controls.
- Side-by-side chat docking with drag previews and browser previews.
- Reviewed import and export of source-grounded codebase memories.
- Improved local and remote provider relay recovery and browser evidence support.

### Changed

- Make the browser console the default interface; retain headless CLI and MCP workflows.
- Switch chats immediately in the current pane, keep history order stable, and show loading skeletons.
- Combine model and reasoning controls, show context usage as a ring, and simplify chat details.
- Present tool activity with compact summaries, category icons, and source chips.

### Fixed

- Clear drag overlays and promote the surviving chat when closing a split pane.
- Suppress routine cancellation notices and preserve the interface during reconnects.
- Include cached token usage in estimated API costs.
- Preserve validated Responses terminal events and timeout authority across provider transports.
- Harden evidence receipts, local model routing, and evolution study authority boundaries.
- Update vulnerable dependency families to patched releases.
- Separate host names from connection status in the host picker.


## [0.24.1] - 2026-10-13

### Fixed

- Prefer the dashboard embedded in a standalone release binary over stale
  checkout build artifacts when `0` or `0 web` is launched inside a source tree.

## [0.24.0] - 2026-10-13

### Added

- Shared assessments, reports, cross-chat finding selection, authenticated team
  workspaces and live presence, with personal and team onboarding.
- Agent Skills library with editing, mounting and team sharing, plus a read-only
  findings API for integrations.
- Remote worker deployment and shared web sessions and workflows across the CLI
  and MCP.
- Local source lessons, evidence retention and versioned workflow history, with
  reviewed workflow restore suggestions and execution measurements.
- Cline provider support, evidence-grounded assessment milestones and finding
  prioritization based on business impact.
- A research counterexample evidence lane.

### Changed

- Make the browser the primary interface and simplify Command Center navigation,
  account controls, chat search and execution choices.
- Surface live findings and tool activity throughout chat turns; new chats default
  to YOLO and also offer Auto approval mode.
- Show animated CLI update stages and download progress, and discover model
  availability from each provider connection.

### Fixed

- Show registered worker connections and connection errors in the Workers page,
  refresh deployed engines and saved credentials without restarting, and show
  the selected computer when confirming a workflow run.
- Keep the browser responsive during worker deployment, package demo inputs
  for npm installs, and assign distinct worker identities and default ports.
  Worker deployment currently requires the npm package or a built source checkout;
  standalone binaries explain this requirement.
- Manage deployed engines from the Workers page: stop a verified Zero process and
  its owned tunnel without deleting remote files, or remove a saved connection,
  credential and managed tunnel. Never stop an unverified remote process.
- Recover chats after provider reconnects and preserve editor drafts and saved
  chat ordering.
- Retry subagent model request timeouts, isolate MCP authorization credentials,
  and explicitly request JSON responses from Cline.
- Restore saved terminal connections, clean up Docker timeouts and allow Local
  approval mode changes during active turns.
- Repair browser documentation links and public routes, harden release recovery
  and CI isolation, and update vulnerable dependencies.

## [0.23.0] - 2026-10-01

### Added

- Typed security workflows across the CLI, browser and MCP, with common run,
  trigger and execution contracts.
- Registered remote engine connections from the browser, CLI and MCP. Keep
  computer selection beside the workspace controls.
- Render chat Markdown and bounded diagrams in the browser dashboard, with
  Zero mascot companions across workspace pages.

### Changed

- Simplify dashboard navigation, workspace layout, workflow controls and agent
  activity. Keep the navigation rail consistent between pages.
- Explain scan goal and depth recommendations, repeat runs versus subagents,
  and sequential/parallel tradeoffs. Describe shared cost limits as estimates
  and warn about in-flight overshoot before confirmation.
- Lead the README with workflows and move integration guidance into Plugins.
- Generate offline paper evidence tables from hashed inputs. Preserve
  historical results while suppressing unsupported benchmark and efficacy claims.

### Fixed

- Reopen a running dashboard reliably and handle occupied ports.
- Acknowledge console cancellation promptly and stop startup cleanly.
- Distinguish local development artifacts from release builds in runtime
  diagnostics and feedback, using an explicit build-channel marker.
- Replay POST XSS probes and require ownership evidence for IDOR verification.

## [0.22.4] - 2026-10-01

### Added

- Opt-in Jev finding prioritization (`rank`) and native EGATS methodology
  selection (`specialist`), with bounded advisory scores, shared scan accounting,
  and fallback that preserves vulnerability confidence and verification state.

- Private, project-scoped review checks with explicit revision approval and
  advisory pass, issue, and unknown results in human and machine reports.
- Guided scan goals, repeated sequential or parallel runs, shared priced
  budgets, and explicit partial, failed, cancelled, and budget-stopped outcomes.
- Durable evolution dispatch accounting, holdout exposure limits, observed
  provider/model provenance, and explicit interrupted-cost reconciliation.

### Changed

- Console data sharing offers only Off and usage metrics. Legacy content-sharing
  preferences migrate to usage; saved refusals and environment opt-outs remain
  effective. An unset setup choice can highlight usage without granting consent
  until Finish. Problem-report consent remains separate.
- Diagnostics can use an operator-provisioned `ZERO_SENTRY_DSN`, with finite
  failure categories, bounded package-relative stack locations and CLI
  release/build/environment tags. Raw messages, output and local review detail
  are excluded; existing first-party feedback remains the fallback.

### Fixed

- Fix Windows dashboard startup with a relative database filename by avoiding
  redundant creation of an existing database parent directory.
- Include the current web onboarding, model selection, privacy controls, chat
  navigation and branding in standalone releases. Verify embedded assets and
  onboarding persistence without a separately installed runtime before publishing.
- Persist the installer PATH in shell startup files and show the command for
  the current terminal. Use baseline Linux x64 executables for CPUs without AVX2.

- Continue safe native Responses output-cap checkpoints without losing completed
  observations or plan state, replaying ambiguous tool calls, or failing workers
  solely because a parent response reached its output cap. Repeated caps pause
  with an actionable resume state; existing execution limits remain in force.
- Bound live Markdown previews, parse-cache weight, diagnostic lines, and native
  review buffers while preserving full canonical messages and plain-code layout.
  Streamed replies follow the tail and native review fits the available viewport.
- Preserve specialized review methodology and literal frontmatter-like check
  prompts; show advisory failures instead of silently dropping them.
- Keep JSON/SARIF report stdout free of human-only cost and cross-validation text.
- Preserve current model-selection and scope boundaries, exact repository
  identity, subsystem review scoping, and known cache-write charges. Correct
  nested private storage paths and enforce durable safety at real promotion.
- Scrub recognized secrets, URL credentials, emails and home usernames from
  both crash notes and captured crash text.
- Embed the build revision in native binaries without probing Bun's virtual
  executable path as a source checkout.
- Use a controlled loopback model in CLI smoke checks instead of sending fake
  credentials to a live provider; successful and rejected-provider outcomes
  remain distinct on both bundled and native executables.
- Align isolated sibling source and artifact paths, reject occupied scratch
  directories, and recover retained workbench admission only after native
  cleanup proof. Setup and execution share the eight-GiB archive ceiling.
- Exercise offline VM disk exhaustion within the normal import budget instead
  of assuming every Node/SDK image fits in a one-GiB reservation.
- Remove generated coordinator-summary prose while keeping the real task plan
  and worker outcomes. Main's work row uses the original goal, not a short title.
- Wrap worker tasks and activity within the viewport instead of prematurely
  clipping them. Resizing preserves focused and remaining-worker navigation.
- Restore focused-worker context usage with that worker's model/provider and
  latest measured sample; partial updates do not erase it, and billing remains
  separately attributed.

## [0.22.1] - 2026-09-30

### Fixed

- Remove orphaned `/comms` and `/messages` slash entries and the standalone
  `/impact` ID-entry workflow. Command menus no longer show actions without a runner.
- Show persisted impact with the selected finding's description and evidence.
  List filters stay in list controls, not in the finding payload; missing
  assessments remain unassessed.
- Keep tool output previews within twenty displayed lines even when an old
  expanded-detail preference is saved. Full retained output requires an
  explicit card disclosure.

## [0.22.0] - 2026-09-30

### Changed

- The interactive CLI now uses connected API keys or provider subscriptions
  only. Cloud credentials no longer select hosted inference implicitly, and
  `/connect` and `/model` no longer offer 0cloud sign-in or 0security Auto.
  Local token, context and estimated-cost reporting remains available.
- Removed managed-cloud login, scans and hosted-inference commands from the CLI.
  Provider API keys and supported provider subscriptions remain available.
- Added automatic provider model-catalog refresh and account-specific Codex
  discovery using current protocol negotiation and backend recommendation order.
  Successful explicit model choices persist for the same connection; CLI and
  environment overrides win. Fresh launches no longer silently select GPT-5.5.
- Reworked onboarding and dialogs with compact controls, live theme preview and
  0.security branding. Setup is five steps; sharing preferences remain optional
  and editable from Settings, and completion returns directly to chat.
- Replaced the Audits sidebar and separate saved-audit browser with one
  `/sessions` picker for open and saved conversations. Removed both chat sidebars;
  compact agent task rows share the main transcript and composer.
- Added an optional local SmolVM workbench: the complete Kali-based 0 runtime,
  browser, Linux tools and scoped GitHub CLI run in a network-enabled Linux VM on
  Apple Silicon, without Docker/Colima at execution. Docker can still build the
  OCI image; it is not required to run it.
- Added safe `0dev --watch console` frontend reloads at idle boundaries, preserving
  conversations, drafts and runtime ownership.
- Added reviewed `/fix` setup with private per-project inputs and separately
  approved, regression-verified draft-PR publication.
- Scope enforcement is an explicitly enabled plugin. Desktop remains alpha and
  is excluded from normal release artifacts. Per-answer usage is off by default.

### Fixed

- Stop repeated NVD requests after rate limits rather than flooding the transcript.
- Preserve model-picker selection while runtime metadata hydrates; compact
  onboarding keeps a selectable model row instead of spending its space on chrome.
- Fix development build failures in tool registration, plugin capabilities and
  source-fix state handling.
- Publish native SmolVM cleanup proofs atomically, and make craft directory
  listing portable without interpreting model-supplied paths as shell input.
- Let worker task titles use the available row width instead of truncating them
  at the compact agent-name limit.

## [0.21.4] - 2026-09-23

### Changed

- Changed-only reviews use one bounded researcher in the shared harness, receive
  the exact patch, and inspect surrounding code only for change-related issues.
  Delegated inference is disabled. Concrete findings retain sequential,
  independent verification under the same scan budget.
  A compact change-review prompt replaces full-audit instructions, and finishing
  a small diff no longer requires reading three unrelated source files.
- Missing, unreadable, oversized or empty diffs never fall back to whole-repository
  scans. Deletion-only changes remain reviewable.
- Recognize GPT-6 Luna's short-context supplier-list estimate separately from
  hosted customer tariffs and invoiced provider spend.

### Fixed

- Show exact settled usage in `0 service status` and `0 service wait`;
  PostgreSQL decimal values no longer crash the terminal display.

- Correct the pinned tree-sitter runtime lock metadata so immutable Docker
  publication can complete `npm ci`; validate the generated runtime with npm's
  locked-install check instead of comparing selected manifest fields.

- Default signed-in accounts to 0security Auto when no provider or model was
  explicitly selected, rather than preferring ambient BYOK credentials.
- Share hosted request capacity across audits and nested agents, queueing excess
  work locally instead of generating avoidable concurrency-limit retries.
- Use the runtime's resolved model for cost estimates and ledger entries,
  including models resolved on first use, rather than pricing the Auto label.
- Check 0cloud account admission and service-model availability before accepting
  chat messages. Keep blocked drafts and offer an explicit recheck without
  replaying messages or asking users to choose a hosted model.
- Read the service's `usage-v2` account response, showing included allowance and
  exact prepaid amounts. Distinguish `prepaid_disabled` from missing credentials.
- Give connected onboarding an explicit Continue action and skip the model
  picker when 0cloud selects the service model.
- Simplify hosted usage to percentage used and reset timing. Show a prepaid
  balance only when prepaid fallback is enabled; keep extra billing metadata
  in JSON instead of the normal display.
- Make `0dev` rebuild and run its source checkout by default instead of silently
  launching the installed release.
- Distinguish a missing included allowance from unavailable usage data. Clarify
  that included usage does not require prepaid fallback.

## [0.21.3] - 2026-09-22

### Changed

- Publish the npm package as `0sec-cli` (bins `0` and `0sec`), resuming the
  established package name so existing installs keep updating. The
  `@0sec/zero` publish was accepted by npm and then quarantined — present in
  the org's access list but never served by the registry — after `@0sec/0`
  had already been refused by name policy. The scoped identity can return
  once npm support clears it.

## [0.21.2] - 2026-09-22

### Changed

- Publish the npm package as `@0sec/zero` (bin stays `0`). npm's name policy
  rejects single-character package names, so the v0.21.1 publish of `@0sec/0`
  was refused with E400 after every build, release, and smoke step had passed.
- Start directly in chat on fresh installations; keep guided setup available
  through `/onboard` instead of opening it automatically.
- Keep runtime initialization details and diagnostic stacks in the local TUI
  log. Show each failed turn once with model/connection recovery commands, and
  label an inactive chat `idle` rather than implying its provider is ready.

### Fixed

- Honour legacy `0SEC_CLOUD_HOST`/`0SEC_CLOUD_TOKEN` keys in `~/.0/cloud.env`
  (env and file, with a deprecation warning) so installs written by the
  pre-rename `0sec` CLI stay authenticated after upgrading instead of
  reporting "credentials not found".
- Declare the bundle's external runtime dependencies (`react`,
  `@opentui/core`, `@opentui/react`) in the root package so a root-packed
  tarball runs under `npx`; `@types/pdfkit` moves to devDependencies.

## [0.21.1] - 2026-09-22

### Changed

- Publish the npm package as `@0sec/0`; the unscoped `0` name is a
  third-party squat and could not receive the v0.21.0 publish.

- Source-review agents can delegate recursively through the normal agent runtime.
  Descendants retain scoped tool restrictions, share scan-wide accounting, and
  publish findings once; stopping a subtree waits for its descendants to drain.
- Ordinary deep reviews use the same agent runner as other source reviews;
  remove the opaque `file_security_review` and `deep_source_review` agent tools.
- Managed reviews consume scan-bound human feedback as untrusted context, without
  mixing it with persistent local history or treating prior dismissals as proof.
- Local native agents keep cross-run hunt memory off unless explicitly enabled;
  managed source research opts in through the Cloud sink. Session history is separate.
- Recursive descendants inherit root policy and their own task without accumulating
  ancestor task prompts.

### Fixed

- Onboarding theme swatches and sample text now preview the highlighted choice
  before confirmation; Back still discards the draft and Enter saves it.
- Keep model switches on the active Codex subscription and discover models from
  that account, including IDs absent from public pricing lists. Preserve provider
  identity for duplicate model IDs; report and retry discovery failures.

- Onboarding Escape returns to the previous decision; skipping setup enters
  chat without completing setup or quitting. Provider login/search cancellation
  stays local, confirmed choices survive navigation, and setup has clickable
  Back/Confirm/Skip controls.
- Use Alt+Left/Right for consistent route history and Shift+Tab for backward
  launcher focus, preserving nested popup and text-input ownership.
- Maintain context between continuing tool rounds, re-arm after reduction,
  and recover bounded context-overflow errors without replaying completed tools.
  Explicit budgets, provider failures, and operator cancellation remain distinct.
- Align console and resume launch defaults with the engine's 100-round limit;
  retain the unlimited default cumulative turn-token budget.

## [0.21.0] - 2026-09-20

### Added

- Enroll repositories through `0 project enroll`, with browser handoff when
  GitHub App access is required and agent-readable setup guidance.

### Changed

- Managed project setup uses per-run credit limits. The published `0` CLI
  can select development or production with `auth login --host`; the `0dev`
  wrapper remains a contributor convenience, not an installation requirement.

### Fixed

- Keep source inventory requests within the process argument-size limit.
- Include C# and .NET source in deep-review and audit inventory.

## [0.20.0] - 2026-09-20

### Added

- Opt-in Jev assistance for bounded read-only browser exploration, memory
  ranking, duplicate assessment, and red-team feedback. Evaluations remain
  advisory; managed requests use a separate scan capability, and credentials
  alone never enable the feature.

### Changed

- Refresh the documentation and README against current source: multi-model
  configuration, console behavior, find/verify/fix workflows, managed-service
  compatibility, extensions, 0verse, and research provenance. Clarify evidence,
  cost-accounting, and execution boundaries without changing engine behavior
  or treating retained benchmark attempts as single-shot results.
- Cloud balance and connection views consume the versioned credit account with
  exact credit amounts, separate free/subscription/prepaid states, and no inferred
  totals or zero balances for unavailable data. Cloud model views expose public
  IDs and capabilities without supplier prices or routing metadata; BYOK pricing
  remains unchanged.
- `0dev` defaults to the development Cloud host and stores Cloud credentials
  separately, without changing normal `0` credentials or BYOK configuration.

### Fixed

- Initialize and upgrade local SQLite schemas in one transaction, avoiding
  repeated durable commits on slow disks and rolling back interrupted upgrades.
- Use Azure's DeepSeek V4.1 Flash rates for exact, mixed-case and versioned
  deployment names instead of the generic cost-estimation fallback. Direct
  DeepSeek API pricing is unchanged; this does not rewrite recorded spend.
- Keep the `triage` command on the explicit command path so it opens its
  registered subcommands instead of being misclassified as a scan target.

## [0.19.0] - 2026-09-18

### Added

- `0 guide` provides an agent-readable product and capability reference,
  with command contracts discovered from registered CLI metadata.

### Security

- Move automatic HTTP target classification after engagement-scope admission.
  Previously, an unscoped or out-of-scope configured target could receive a
  probe before the scan was refused. The probe now refuses redirects and
  cancels their response bodies.

### Changed

- Bound executable-plugin and source-evolution guest admission per controller
  by active count, aggregate memory/CPU, and a bounded FIFO queue. Deadlines
  cover queued work; nested calls fail promptly when capacity is unavailable.
  Reservations stay held through teardown, and uncertain cleanup stops new
  admissions. Docker remains the default; guests are not reused.
- Present the product as **0security**, with a full wordmark and orange branding
  across the CLI, dashboard, desktop app, documentation, and README assets.
  The `0` executable, package identifiers, configuration paths, desktop
  profile location, and release artifact names remain compatible.
- Clarify the Research Preview mission and 0cloud's hosted inference and managed
  security roles while preserving local and BYOK operation.

### Fixed

- Separate dashboard text accents from solid orange actions so links, selected
  workflow text, and translucent badges remain readable in light and dark
  themes. Use the canonical aperture and SVG wordmark in dashboard navigation.
- Fail closed when `connect` cannot establish enrollment readiness or inspect
  existing schedules. Missing/malformed endpoints no longer fabricate repository
  authorization. GitHub App installation remains an action-required handoff.
- Require explicit `--yes` approval for new work in JSON mode. A failed
  recurrence operation preserves the created scan ID and reports incomplete
  enrollment instead of success. The budget confirmation describes a per-run
  ceiling, not a monthly allowance.
- Keep guide account state unknown after a health response. Add hosted inference
  as a separate service capability, discover command contracts from registered
  metadata, and reject unknown JSON topics consistently with human output.

## [0.18.0] - 2026-09-16

### Added

- **`0 secure` — the self-securing lifecycle.** Point the CLI at a
  repository and it investigates, behaviorally reproduces each finding with a
  frozen probe, repairs across multiple files, runs your regression command,
  and independently verifies the fix in a fresh checkout before retaining the
  patch and evidence. Broken candidates (e.g. feature-disabling patches) are
  rejected; unresolved findings block the run instead of reporting clean.
  Runs are resumable with identity checks, persist an exclusive lock, and
  track real token cost. `--publish` opens PRs for verified patches only.
- **`0 connect` — one-command cloud onboarding.** `0 auth login` once,
  then `0 connect <repo-url>`: auth is verified, the test command is
  auto-detected (package.json / Makefile / pytest / Cargo / Go), the first
  secure run starts immediately, and a recurring schedule is installed.
- **Learning loop.** Verified and failed repair outcomes are recorded in the
  revision-aware memory store and recalled as untrusted hints on later runs.
  State is stable per repository by default, so learnings accumulate across
  runs instead of resetting.
- **Developer-choice learning.** Repair PRs carry a machine-readable
  attribution marker; accepted/rejected outcomes (`ZERO_SECURE_PRIOR_OUTCOMES`)
  and reviewer comments (`ZERO_SECURE_GUIDANCE`) flow back into future repair
  prompts as untrusted guidance.
- **Per-repo repair rules.** `--rules` / `ZERO_SECURE_RULES` render
  plain-English team standards ("minimal diffs; no new dependencies") into
  repair prompts.

### Changed

- `0 update` is now an alias of `0 doctor upgrade`.


- Show a consistently spaced `ZEROSECURITY` hero wordmark on wide terminals, with
  the original `ZERO` mark retained for narrow columns.
- Replace the duplicate aperture above the wordmark with Zero peeking over an
  edge, facing forward with both gloves visible. Preserve the original image
  resolution and antialias the silhouette without its white fringe. Native
  images are composited onto the active theme canvas; when native graphics
  cannot be used, omit the mascot entirely instead of displaying pixel art.
  Keep the orange band and fit the portrait to the available body rows rather
  than hiding it below a fixed terminal-height cutoff.
- Vertically centre the entire welcome group, including the mascot, wordmark,
  input and shortcuts, while keeping the input stationary when filtering commands.
- Default analytics and training sharing to `full` for new installations, with
  category-specific onboarding/settings disclosure and preserved saved,
  environment and organization opt-outs. Capture console tools and all submitted
  executable-plugin files through the shared redaction boundary.
- Retain ordinary training content, including emails, URLs and opaque strings.
  Scrub recognized credentials rather than applying broad PII or entropy
  masking; handle nested JSON/shell credentials without losing JSON quoting.
- Keep metadata overflow markers within the receiver's 4,000-character limit
  so a long finding cannot invalidate an otherwise acceptable capture batch.
- Preserve accepted tool/code content up to 256 KiB per redacted UTF-8 field;
  bound Cloud batches by encoded bytes and count, report oversized captures
  locally, and recheck consent before every POST.
- Use the latest planner request's input tokens for context occupancy rather
  than cumulative turn usage, including usage reported before a stream failure.
- Render scrollbars with a one-column, narrow-stroke thumb and remove unused
  scrollbar reservations from expanded inline tool cards.
- Accept `update` as an alias for `upgrade`, including the CLI entrypoint and
  generated command reference.

## [0.17.0] - 2026-09-15

### Added

- Hackstore community discovery, extension authoring commands, and a runnable
  generated SHA-256 extension. Installation and per-project enablement remain
  separate operator decisions.
- Multi-tab browser tools, authenticated Chrome attachment, JavaScript/Python
  evaluation tools, and additional security-engine tools and skills.
- Additional provider connection flows, live model/provider selection,
  per-agent routing, context compaction, and consent-gated redacted analytics.
- A publishable benchmark scoreboard through `0 bench scoreboard`, with
  benchmark-miss harvesting available through `lens-synth --from-bench`.

### Changed

- Reworked terminal dialogs, command and model pickers, keyboard controls,
  code and tool cards, worker activity, themes, and shutdown feedback.
- Report live session links, pane activity, and runtime context to Herdr, and
  release the session sink on exit.
- Default automatic updates on for profiles without an explicit update policy.
  Eligible startup checks may download and install remote code; explicit `off`
  and `notify` preferences and existing updater safety checks remain intact.
- Pin the default Foxguard scanner and standalone installer companion to
  v0.14.0, with matching published checksums for every supported platform.

### Fixed

- Make `plugin run` consume the name-keyed built-in tool registry correctly.
  Approval-denied output distinguishes loading plugin code from invoking a tool.
- Execute plugins with the embedded Bun interpreter in standalone builds,
  without requiring Node or Bun on `PATH`.
- Exclude security engines with sub-analysis or network capabilities from
  attacker-controlled source scopes while retaining trusted audit access.
- Preserve live conversations, scope decisions, worker state, and accounting
  across supported runtime changes; retain the active engine on failed replacement.
- Keep unlimited turn budgets out of finite-JSON checkpoints, contain source
  aliases within immutable engine generations, and terminate owned sandbox
  process groups on cancellation, deadlines, and output overflow.
- Validate browser arguments and initial scope before acquiring a backend.
  Preserve explicit target authority, origin-bound credentials, and refusal
  of unanchored shared-address-space destinations.
- Commit work-plan transitions and audit records atomically, with rollback
  when audit artifact storage fails.

### Release

- Publish the established `@0/cli` npm package through the release workflow
  after the standalone platform builds, using the repository's CI credential.
  An npm-only recovery run leaves existing tags and native assets unchanged.

## [0.16.3] - 2026-09-12

### Fixed

- Resolve relative JavaScript bundles against the actual document URL, preserving
  standard directory, query and fragment semantics.
- Keep `js-recon` command tests offline through the scoped transport boundary;
  retain scope-refusal and redacted-output checks.

### Added

- Messenger conversation framing and the Agents sidebar default on while saved
  alternatives and explicit opt-outs remain effective. Clickable sidebar controls,
  compact worker activity and a single configured-scope display preserve chat state.
- `/copy` (`/export`, `/dump`) saves the complete public conversation as private
  local JSON and attempts clipboard delivery. OSC52 delivery remains unverified.
  `/impact` loads a saved finding into the current chat for evidence-qualified analysis.
- Finding detail prioritizes title, severity and CVSS, with distinct evidence
  sections. Endpoint metadata uses the same redacted request as the evidence body.
- Context meters report unavailable when runtime window data is missing. Hosted
  Cloud credit state remains separate from estimated model cost.
- Cloud sign-in, BYOK credentials, and provider subscriptions are separate
  connection choices. Cancelling sign-in returns to the current conversation;
  changing the provider or model applies to the next chat. Login alone does not
  establish model availability or a funded account.
- `0 balance` displays the service-reported percentage of inference credits
  remaining. Missing percentage data stays unavailable; JSON retains accounting
  fields, and reservations remain distinct from settled spending. Small positive
  balances display `<0.1%`; nearly full balances display `>99.9%`.
- Interactive YOLO public-network tools no longer require a launch target or
  approval for each discovered public host. Explicit configured restrictions,
  exclusions, prior refusals, private-address checks and credential boundaries
  remain enforced. Search results do not change target or scope.
- Browser HTTP requests in public-network mode are bound to the current tool
  action; cancellation prevents delayed dispatch and held-response delivery.
- Entering a previously declined host directly in chat reopens scope approval.
  Approval preserves the conversation and exclusions; model retries remain denied.
- Main and worker transcripts share expandable command and output views.
  Status rows and pickers use Nerd Font icons with retained text labels;
  glyph appearance depends on the terminal font. Cancellation keeps partial
  output without adding a persistent interruption notice.
- Removed the persistent problem-reporting invitation from the chat footer.
- Target HTTP tools check scope and resolved addresses before connecting and
  following redirects. Requests pin destination addresses, retain TLS hostname
  verification, and bound decoded bodies and elapsed time. WordPress advisory
  requests use a separate service-bound transport.
- The standalone CLI runtime includes the existing PDF report dependency.
- Console guidance asks for useful parallel delegation on independent work and
  evidence-backed finding summaries while retaining scope and budget limits.
- Contextual model, session, finding, usage, worker, and marketplace views use
  compact controls. Usage reports scroll without losing unknown-cost markers;
  worker steering accepts pasted text, and marketplace actions retain confirmation.
- Child runtimes inherit the parent's resolved provider configuration.
  Scoped harness shutdown drains work before disposal and reports incomplete
  cleanup. Restarting an engine does not reconstruct active harness state.
- Problem reporting defaults to automatic limited diagnostics with a global
  off/ask/automatic preference. Explicit opt-outs remain effective; project
  settings cannot override the preference. Reports exclude prompts, tool
  arguments, output, paths, and credentials. Delivery requires Cloud sign-in
  or a configured HTTPS endpoint; manual feedback retains review and local capture.
  Feedback submission rejects redirects to unreviewed destinations.
- Update checks and automatic installation use an operator-global policy.
  Automatic installation is opt-in and completes before interactive startup;
  notification-only checks remain in the background. Manual upgrades retain
  their version and destination options and report failures or interruption.
- `/explain` and `/eli5` request a short explanation in everyday words without
  new tool execution. The idle worker panel suggests how to request subagents.

- Executable TypeScript plugins, reusable skills, and agent programs can be
  created during a session, composed through tool/model brokers, retained
  across restarts, replaced, and rolled back. Evaluated source evolution can
  activate measured versions and explore compatible archived alternatives
  without confusing their provenance with the deployed rollback parent.
  Docker and local smolvm provide isolated execution; provider credentials
  stay in the controller. New console sessions default to YOLO within their
  configured authorization scope; `console --scope` now also reaches the
  full-screen UI instead of being dropped during startup.
- Source evolution can recover from a fully observed zero-success baseline
  without treating its undefined cost-per-success as missing evidence.
  Candidate costs must still be finite, and evaluation budgets, private
  lanes, negative controls, approval policy, and canaries still apply.

- Worker inspection now retains text-only final answers, live tool snapshots,
  and expandable commands, output, diffs, and tool details. Completed workers
  remain navigable; live steering is consumed at model boundaries, finished
  one-shot follow-ups return to Main with quoted context, and persistent workers
  notify their parent. Status rows distinguish worker measurements and context
  from turn-spend limits. Plans expand into scrollable full descriptions, and
  worker transcripts preserve their scrollable extent through detail and size
  changes without leaking layout state into the Main conversation.

- Native desktop development is paused. Root desktop launch and packaging
  shortcuts are removed, and the macOS packaging workflow is archived.
  Desktop source and CLI-required dashboard components are retained.

- YOLO console sessions can acquire public HTTPS Git repositories for local
  review without authorizing their hosting services as testing targets.
  Standalone clones run without a shell through a public-address-pinned tunnel,
  with isolated Git configuration and bounded execution. Explicit exclusions,
  declined-host memory, and private-network protection remain enforced.
  Git checkout failures are reported as failures rather than successful output.

- Console history now connects to the persistent findings database across TUI,
  readline, one-shot, and desktop sessions. `--db-path` also works without
  `--finding` and follows history navigation. Read-only `list_conversations`
  and `read_conversation` tools expose saved chats through the existing session
  store, with project-local discovery, explicit cross-project search, bounded
  transcript pages, and credential redaction. Raw provider payloads, hidden
  reasoning, and tool-result bodies are excluded.
- Independently buildable, non-root `toolbox` image target with Node 24 and
  the existing security/identity/Foxguard inventory. The default distribution
  target reuses it and adds the CLI. A real offline smolvm qualification checks
  37 tool startups, Python imports, guest-local Nmap/curl behavior, and Foxguard
  positive/clean fixtures. Architecture guidance distinguishes OCI packaging,
  worker isolation, global sandbox gaps, and a measured path to native execution.
- Opt-in Linux smolvm 1.14.6 execution for source evolution, including approval
  and pinned future workers. Archive bytes are pinned and copied before boot;
  source mounts are read-only, workspaces guest-local, and credentials/network
  access excluded. Host deadlines, cancellation, output caps, and verified
  teardown fail closed. Docker remains the default. A real microVM qualification
  script and smolvm mode for the provider-backed source lifecycle are available.
- `evolve exec` now forwards terminal interrupts to the running worker and waits
  for its cancellation result instead of abandoning execution on the first signal.
- Refresh the bundled model picker and pricing with GPT-6 Astra, DeepSeek V4.1
  Flash, Claude Fable 5.1 / Opus 5 / Sonnet 5, Gemini 3.1 and 3.5–3.8 text
  models, GLM-5.3-Flash, and Qwen 3.8 Flash / 3.7 Plus / 3.6 Plus and Flash.
  The offline Qwen catalog also includes the unpriced 3.8 Max preview.
  Qwen estimates now include published cache-read rates where available.
  Direct DeepSeek now defaults to its stable
  `deepseek-flash` API id; existing Azure and Token Plan routes are preserved.
  GPT-6 requests use the reasoning-model output cap and Responses reasoning
  defaults. Astra remains opt-in; estimates use base rates, not long-context,
  cache-write, or off-peak billing tiers.
- Console interaction improvements: curated/all model browsing, stable detail
  panes, searchable command navigation across control screens, and model changes
  that preserve the transcript and unsent draft. Fast input followed by Enter
  selects the current query rather than the previous highlight.
  Settings support paste, Unicode editing, immediate value cycling, and clearer
  changed-state/save feedback. Saved sessions default to the current project,
  retain recoverable errors, and require explicit, cancellable deletion.
  Worker monitoring adds search and clearer state labels; live plans prioritize
  active tasks without overflowing their sidebar. Working indicators honor
  reduced motion and no longer animate failed startup as connecting.
  OpenAI model selection retains configured custom API endpoints.
- Evolution passes recover compatible development feedback from retained
  proposals and evaluation receipts, including after promotion. Proposal and
  receipt digests are checked; held-out and negative-control feedback stays
  sealed. This does not add restart-safe campaign budget accounting.
- Interactive source findings with missing or out-of-range citations return
  repairable validation errors before persistence. Source reads and citation
  checks no longer count a terminal newline as an additional source line.
  A real-model citation-repair lane joins the trusted-main evolution E2E checks.
- Scoped native-API research can retain source-hashed codebase notes and reuse
  current notes in later runs. Verification stays cold, and changed or unsafe
  evidence is excluded. A real-model learning lifecycle check is available in
  the trusted-main evolution workflow.
- Canonical CLI documentation at `docs.0.security`, with task-oriented command
  navigation, source-audited workflow guides, neutral light/dark styling, and
  responsive navigation. Unreleased 0cloud and desktop guides remain contributor
  drafts, excluded from public routes and search.
  Existing product-guide URLs redirect to their roadmap status.
- Development desktop chat now renders streamed Markdown, expandable tool
  activity, and interruption states without duplicating final responses.
  Following output respects manual scrolling; code copying is limited to the
  focused local dashboard, while clipboard reads remain denied.
- Development desktop now uses a thread sidebar, an anchored composer, neutral
  system appearance, accessible dialogs, and per-thread drafts. macOS gets real
  window controls, native folder selection, menu shortcuts, and close/reopen
  behavior that keeps the existing sidecar alive. The sandboxed preload is
  compiled as CommonJS; native requests are restricted to the trusted main frame.
  Terminal turn failures remain visible even when no assistant text was produced.
- `pnpm docs:sync` refreshes registered CLI arguments, options, defaults, and
  aliases without replacing reviewed workflow or safety notes. `pnpm docs:check`
  blocks stale command references in CI and before documentation deployment.
- Source proposals can inspect recent retained worker versions without
  reopening removed source paths or applying edits against stale digests.
- Opt-in `ZERO_LOG_FORMAT=json` operational records on stderr, with
  allowlisted lifecycle/cost metadata and credential redaction. Existing
  stdout output and cloud event relay framing remain unchanged.
- Stateful `access_control_workflow` verification with isolated identities,
  explicit mutation consent, scoped multi-step requests, and owner-observed
  state transitions rather than HTTP-status-only claims.
- `review --fix-commit <sha> [--variants-only]` for bounded, heuristic
  JavaScript/TypeScript/Python incomplete-fix leads.
- Two-phase `verify --create-bundle` and `verify --bundle` with allowlisted
  snapshots, integrity and runtime checks, explicit runner selection, and
  vulnerable/patched negative controls. Failed processes never confirm a fix.
- Real Docker replay CI covering container isolation, workspace paths, timeout
  cleanup, scoped HTTP, and vulnerable/patched negative controls.

- `0 evolve` — autonomous self-improvement plane with config-driven source
  candidate proposals, three-lane (development/held-out/negative-control)
  evaluation in isolated Docker containers, and durable promotion with canary
  and rollback. Subcommands: `run`, `status`, `promote`, `rollback`, `exec`,
  `feedback capture`, `feedback approve`, `feedback status`, and `feedback release`. Source rewriting requires
  explicit `allowModelSourceAccess` consent; `autoPromote` replaces the
  previous blanket "no automatic source-code promotion" with configured
  autonomy. Config schema version 1 with zod-validated fields including
  `schemaVersion`, `sourceRoot`, `storePath`, `image`, `sourcePaths`,
  `editablePaths`, `kind`, `command`, `buildCommand`, `cases`, `repeats`,
  `maxIterations`, `maxModelTurns`, `maxModelCostUsd`, `maxEvaluationCostUsd`,
  `computeUsdPerSecond`, `timeoutMs`, `memoryMb`, `cpus`, `maxOutputBytes`,
  `maxSourceBytes`, `maxChangedBytes`, `model`, `objective`,
  `allowModelSourceAccess`, `autoPromote`, `canaryTrials`, and
  `promotionPolicy` with per-gate thresholds.
- Evaluation runs in network-none, read-only Docker containers with
  `--cap-drop=ALL`, `--security-opt no-new-privileges`, bounded CPU/memory/pid,
  and tmpfs output. Docker image tags resolve to immutable IDs retained in
  pinned worker configurations; resumed workers do not follow mutable tags.
- `runEvolution` acquires an exclusive PID-bound controller lock per store.
  Interrupted canaries are rolled back before the next evolution pass.
- Immutable, content-addressed snapshots under `storePath/snapshots/<id>/` with
  symlink, secret, and nested-store rejection. Edits are validated for path
  boundaries, bounded changed bytes, before/after digests, and duplicate
  prevention.
- `executeEvolutionVersion` pins code+stored config+input digest per run,
  rejects changed command, and validates known config cases — mismatch rolls
  active version back to parent (operator cancellation excluded). Unknown inputs
  have no ground truth and are never auto-labelled.
- Hash-chained registry event log (`recorded`, `canary_started`, `promoted`,
  `rolled_back`) with atomic O_EXCL artifact publication and fsync.
- `0 lens-synth --status` and `--rollback` — inspect and retire overlay
  lenses from the durable appsec-archetypes registry.
- `artifact-bridge.mjs` — CLI bridge for skill/router promotion authorization
  against the evolution registry. Used by skill-refine and active-learning loops
  with `--evolution-store`, `--evolution-version`, `--evolution-artifact` flags.
- Lens evaluation requires independent positive, held-out, and clean-control
  fixtures, conjunctive finding identity matching, measured usage and latency,
  repeated results, and content-bound receipts. Automated promotions archive
  the validation report beside the installed overlay version.
- Approved feedback preserves held-out separation and original miss provenance;
  completed outcomes are retained, with explicit recovery for crash-held claims.
- Future hunt outcomes and retained corpus rows identify the exact installed
  finder-lens version; changing an overlay cannot relabel an in-flight scan.
- Extension resume restores descriptor identities atomically and rejects
  non-reconstructible contributed guards instead of silently weakening policy.
- `deep-review --evolution-config` deploys a promoted source finder through the
  isolated worker path. Parent/child pins preserve one version per review;
  strict file-bound leads still pass through independent verification. Reports
  retain version identity and separately budgeted local compute estimates.

### Fixed

- Craft helpers pass model-provided paths as literal arguments rather than
  shell text. Replay container launches validate image references and keep
  mount paths and command arguments separate from shell syntax.

- Windows Cloud sign-in passes the browser URL as data to a fixed launcher
  command, so URL metacharacters are not interpreted as shell commands.

- Source evolution rejects candidates that lose an already-solved case, even
  when aggregate development and held-out scores improve. The retention check
  also applies to approval and canary evaluations.

- The toolbox image includes system `sbin` directories on `PATH`, making the
  packaged John executable available to the non-root CLI. Published-image
  smoke checks now exercise John startup.

- Source-evolution confidence intervals no longer treat repeated executions of
  the same fixtures as independent evidence; unstable repeats cannot produce
  an informative interval.
- Empty model refutations remain unresolved in the hunt ledger instead of
  becoming disproven claims that bias later runs' known-negative context.
- Target-history inference rejects repository metadata symlinks that resolve
  outside the authorized root, including intermediate `.git` directory links.
- Codebase-memory evidence uses bounded descriptor reads and rechecks canonical
  paths; changed source, symlink escapes, and multiply linked files are rejected.
- Source hunt finders and refuters use the scoped source-analysis runner instead
  of launching network discovery, attack, and verification phases for each file.
  Source prompts now describe the scoped enumeration/search tools actually available.
- The DeepSeek MCP profile now disables the web-fetch provider alongside its
  web service, preventing headless startup from waiting on a disabled service.
- Source enumeration no longer follows repository symlinks or includes
  multiply linked files. Deep-review also checks resolved subsystem paths
  against the prepared source tree before exposing source to a finder.
- Foxguard integration now consumes native v1 JSON reports instead of silently
  dropping their findings. The npm fallback is pinned to v0.13.0; provisioned
  binaries are used directly, and multi-path scans use valid CLI invocations.
- Installers, container builds, and scanner CI provision a checksum-verified
  FoxGuard companion from a shared version/hash pin; the default installer
  includes it unless `INSTALL_FOXGUARD=0` is set.
- Explicit package scans run from their source root, preventing a
  `node_modules` ancestor from causing all package files to be skipped.
- Invalid Foxguard JSON and scanner error exits no longer count as clean
  static scans. The default scanner no longer falls back implicitly to Semgrep;
  `ZERO_STATIC=semgrep` remains an explicit optional compatibility mode.
- Cross-validation and kernel variant hunting use the released Foxguard CLI
  syntax. SARIF file URIs are decoded, and cross-validation no longer matches
  unrelated source files solely by basename.
- Canary startup verifies the candidate's on-disk snapshot before changing
  registry state, rejecting altered code even when its retained receipt is valid.
- TUI evolution ignores stale callbacks after reconfiguration or stop and
  avoids releasing feedback claims already marked processed.
- Approved feedback claims record process ownership. Startup recovers only
  demonstrably dead owners in the same process scope; live or unverifiable
  owners remain claimed, and obsolete completion tokens cannot publish results.
- Benchmark fixtures now bind the `0` schema namespace introduced by the
  earlier rename. Recomputed commitments preserve the original labels and
  MSRC source-byte hashes; validators still reject tampered provenance.
- Finding and PoC JSON validation is shared between CLI ingestion and bundle
  replay rather than maintained as divergent schemas.
- Docker shell replay honors workspace-relative `cwd` and rejects absolute
  paths or traversal outside the mounted workspace before launch.

### Security

- Upgrade Astro to 7.2.8 and sharp to 0.35.4 (libheif 1.23.2), fixing
  AVIF-processing vulnerabilities GHSA-26w7-cxv4-gfx2 and GHSA-rgj7-g3m4-5g8c.
  Astro stays on the compatible 7.2 patch line for the existing Markdown peer.
- Require js-yaml 4.3.2 or later so empty merge sources count toward the parsing
  budget (GHSA-2883-xcg3-v3hh).
- Require Hono 4.13.5 or later for static-generation path containment, bounded
  dot-notation body parsing, and fragment-aware query parsing
  (GHSA-gqvv-2mrq-wpjv, GHSA-g6gw-c38x-mqfc, GHSA-crvj-82cr-hjcx).
- Require smol-toml 1.7.1 or later to reject malformed trailing comments
  instead of hanging during parsing (GHSA-7w5x-hrqm-74c2).

## [0.16.2] - 2026-09-09

### Fixed

- Native binary release smoke now verifies embedded dashboard assets on every
  supported platform without relying on a platform-specific database setup.


## [0.16.1] - 2026-09-09

### Fixed

- Standalone binaries now embed the dashboard's built assets and materialize
  them only while `0 dashboard` is running, so the dashboard works without
  a checkout or `node_modules`.


## [0.16.0] - 2026-09-09

### Added

- `0 lens-synth --watch --promote` now evolves additive appsec finder lenses
  from curated, corpus-gated misses into a user-owned registry. Promotions and
  rollbacks are hash-linked and hot-load only for future source engagements;
  active engagements remain pinned.
- `0` and `0 tui` retain chat as the primary OpenTUI surface. Chat-owned
  `/run` opens one explicit-target engagement pane rather than separate
  scan/audit/review/deep-review launch modes; a deep source engagement uses the
  current validated finder-lens strategy through the shared unified runner.
- Chat `/capabilities` now exposes the harness capability catalogue with
  explicit `ready`, `confirm`, and `blocked` safety tiers; every OpenTUI pane
  is routed through the typed chat navigation contract.
- ChatGPT Codex now uses `codex login --device-auth` from the chat-owned
  provider pane. It never enters the generic API-key store or asks for an
  OpenAI API key; OpenAI remains a separate API-key provider.

### Fixed

- Review-card selections now lead with the evidence record and preserve the
  Review context; operator controls remain available after the review detail.

## [0.15.0] - 2026-08-30

### Added

- A versioned `0.presentation/v1` contract now carries canonical reports,
  renderer-neutral console transcripts, and semantic events across the CLI,
  browser dashboard, and output adapters.
- The console can open a virtualized transcript review with `/transcript` (or
  `/review`), focus a live subagent's real transcript, and let an operator
  message that focused subagent.
- `--print`, `--resume`, `--continue`, and the `-p`, `-r`, `-c`, and `-m`
  aliases support one-shot and saved-session CLI workflows.
- The local dashboard provides a same-origin presentation-event SSE endpoint
  with resumable cursor replay.
- Framework packs, model-catalog synchronization, canonical benchmark
  integrations, and isolated replay runners expand the reusable assessment
  surface.

### Changed

- Terminal, JSON, Markdown, HTML, SARIF, PDF, dashboard, and native-console
  projections now consume shared presentation documents instead of deriving
  state from renderer-specific output.
- The OpenTUI console captures direct application stdout/stderr while it owns
  the terminal, preserving those writes as transcript events and preventing
  framebuffer corruption.
- Console defaults now use the Midnight theme; transcript, tool-card, composer,
  sidebar, and focused-subagent surfaces were refined for legibility.
- The optional `@0/cli` npm launcher downloads the matching platform-specific
  release asset on first invocation when published to npm.

### Fixed

- Packaged native binaries embed JIT skill YAML rather than failing to load
  source-only skill assets.
- Markdown rendering no longer damages generic or unlabeled fenced code blocks.
- Dependency overrides remove the previously reported audit advisories.
- Standalone release binaries embed tree-sitter's parser and C grammar addons;
  CI now removes build-host `node_modules` before its binary smoke test.

## [0.14.0] - 2026-08-25

### Added

- `/theme` switches the console colour theme with live preview (arrow to
  preview, Enter to keep, Esc to revert).
- `/settings` is now a tabbed screen (one tab per category) instead of one long
  scroll; a `/shortcuts` reference lists every keybinding (also reachable from
  settings via `?`).
- `0 console` gains `--yolo` / `--mode <standard|recon|copilot|yolo>` launch
  flags (YOLO still requires `--scope`).

- `bench improvement-assess` binds sealed improvement results to champion and
  challenger artifact digests, evaluates promotion gates, and writes a
  create-once decision plus hash-chained ledger snapshot. Generic artifacts
  require human approval; the command never executes or deploys a candidate.
- The stdio MCP server accepts `--tools <comma-separated-names>` to limit the
  model-visible 0 tool set. The source-checkout DSH runner defaults to the
  bounded recon profile rather than exposing every live tool schema.

### Changed

- Fresh `scan`, `audit`, `review`, legacy scanner, MCP, and persisted-ingest
  executions now own `~/.0/runs/<run-id>/state.db` rather than contending
  on one user-global SQLite file. `0 history` and `0 findings list`
  aggregate run-local state; `0 resume` resolves an unambiguous abbreviated
  run id.
- Managed workers bind the local run directory, database, and final report to
  their managed scan id. The worker controller retrieves that report after the
  engine exits and posts it through the retrying, idempotent final-report path,
  so transient per-finding webhook loss cannot silently erase the completed
  scan's findings.

### Changed

- The console top bar shows the running version (`v<VERSION>`, auto-tracked).
  Pressing Enter during a running turn now interrupts it and sends the message
  immediately, rather than only queuing it. The line-mode (non-TTY) fallback
  gained the `recon` mode and stops silently ignoring commands it can't run.

### Fixed

- Hardened the plugin registry fetch: refuse redirects (no http/SSRF downgrade),
  cap body size, add a timeout, and bound processed entries.
- Closed a self-extension reserved-name gate gap and fixed a console tool-schema
  bug that dropped array `items` (array tool params were mis-described).
- The full CLI test suite now gates CI (was an 8-of-114-file subset), fixing 27
  regressions that had accumulated unseen; revived the real-binary smoke test.

## [0.13.0] - 2026-08-19

### Changed — pwnkit is now 0

The engine and CLI are renamed from pwnkit to 0, matching the public
repository (`0sec-labs/0`):

- **Package identity:** the root bundle is `0`. The workspace CLI package is
  `@0/cli`; the binary shipped by both is **`0`**, with **`0`** as a
  short shell alias (`0 scan ...`). Neither package is published to npm yet.
- **Container image**: `ghcr.io/0sec-labs/0` (was `ghcr.io/0sec-labs/pwnkit`).
- **Standalone distribution:** GitHub Releases ship verified binaries for Apple
  Silicon macOS, Linux x64 and arm64, and Windows x64. Install with
  `curl -fsSL https://raw.githubusercontent.com/0sec-labs/0/main/install.sh | bash`
  on supported Unix hosts, or download the matching release asset directly.
- **Environment variables**: the public env contract moved from `PWNKIT_*` to
  `ZERO_*` (e.g. `ZERO_MODEL`, `ZERO_CLOUD_TOKEN`). At CLI startup, any legacy
  `PWNKIT_*` value is copied onto its `ZERO_*` equivalent when the new name is
  unset, so existing deployments keep working; the new name always wins
  (`packages/cli/src/env-legacy.ts`).
  Note: POSIX shells reject digit-leading variable names, so `ZERO_*` vars
  cannot be set or expanded in bash/sh directly — use `env ZERO_FOO=... 0
  ...`, or keep using the permanently supported `PWNKIT_*` names in shell
  contexts. Docker `-e`, CI env blocks, and systemd units are unaffected.
- **Workspace packages** moved from the `@pwnkit/*` scope to `@0/*`.
- Internal canary/marker strings (`PWNKIT-CANARY:`, `PWNKIT-INITRAMFS-*`,
  `PWNKIT-INJ-OK`) are wire protocol tokens between generated exploits and the
  verifier; they are unchanged and not part of the public interface.

## [0.12.0] - 2026-07-17

### Added — z-ai (GLM) and kimi (Moonshot) providers

pwnkit-cli can now drive scans through Z.ai's GLM models and Moonshot's Kimi K3
"coding" endpoint. Both are Anthropic-compatible: they ride pwnkit's existing
`/v1/messages` wire (`x-api-key` + `anthropic-version` headers, Anthropic-shaped
request body + response parser) rather than the OpenAI chat/completions path.
Each provider is selected by an explicit operator opt-in key, and either wins
over the global env priority when the requested model maps to it (e.g.
`glm-5.2` → z-ai, `k3` → kimi), so one process can fan calls across providers.

- **feat(llm-api): add Z.ai GLM provider — Anthropic-compatible wire.**
  Activated by `Z_AI_API_KEY`; base URL overridable via `Z_AI_BASE_URL`
  (default `https://api.z.ai/api/anthropic`), default model `glm-5.2`. GLM's
  hybrid reasoning is off by default on this endpoint, so pwnkit enables it via
  the Anthropic extended-thinking field; the budget is tunable through
  `PWNKIT_ZAI_THINKING_BUDGET` (default 2048, `0` disables).
- **feat(llm-api): add Kimi K3 (Moonshot) provider + pricing** (#68).
  Activated by `KIMI_API_KEY`; base URL overridable via `KIMI_BASE_URL`
  (default `https://api.kimi.com/coding` — distinct from Z.ai so kimi requests
  never hit api.z.ai), default model `k3`. K3 emits native `thinking` blocks on
  the Anthropic wire, so no thinking body param is applied.
- **note(runtime): prompt caching is opt-in and fails closed for these two.**
  Because their cache semantics are unverified, GLM and Kimi emit **no**
  `cache_control` markers by default (byte-identical bodies to before). Opt in
  per provider via `PWNKIT_PROMPT_CACHE_EXTRA_PROVIDERS` (comma-separated, e.g.
  `z-ai,kimi`).
- **fix(runtime): guard the Anthropic-wire routing with a positive predicate.**
  z-ai/kimi previously rode the Anthropic wire only by being absent from the
  `isOpenAICompat` getter while carrying a misleading `wireApi:"chat_completions"`
  tag. Routing now keys off an explicit `isAnthropicWire` predicate; the
  `wireApi` field for these two is an inert, intentionally-unused default.

## [0.11.0] - 2026-05-16

### Added — chatgpt-codex direct-API provider

pwnkit-cli can now drive scans through a user's ChatGPT Plus/Pro subscription
via the operator's existing `codex login` auth — no Platform API key required.
The new `chatgpt-codex` provider reuses pwnkit's own Responses-API path, OWN
prompts, OWN tools, OWN agent loop, and OWN cost/turn caps; the `codex` CLI
is **not** spawned as a child process, so all scan modes (web + audit + review)
keep native pwnkit control on top of the subscription-billed zero-marginal-cost
auth path.

- **feat(runtime): chatgpt-codex provider — direct API via ChatGPT OAuth** (#327)
  Activates when `PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN` is set; takes priority
  over api-key providers. Mirrors opencode's ChatGPT-Codex pattern with
  pwnkit-specific headers (`originator: pwnkit`, `ChatGPT-Account-Id` from JWT,
  stable `session_id`). `max_output_tokens` is intentionally omitted per the
  upstream convention.
- **fix(llm-api): send `instructions` field for chatgpt-codex Responses** (#330)
  System prompts were being dropped from the Codex `/responses` body; the
  provider now forwards them in the `instructions` field where Codex expects
  them.
- **fix(llm-api): capture chatgpt-codex tool calls from `output_item.done`** (#331)
  Tool calls were being missed when the Codex stream delivered them as
  `output_item.done` events rather than as deltas. The parser now reads from
  both paths.
- **fix(llm-api): prefer streamed items over empty Codex `output[]`** (#332)
  The terminal `response.completed` event sometimes ships an empty `output[]`;
  pwnkit now keeps the items accumulated from the stream instead of clobbering
  them with the empty terminal payload.
- **feat(llm-api): accept pre-issued ChatGPT Codex `access_token` via env** (#334)
  `PWNKIT_CHATGPT_OAUTH_ACCESS_TOKEN` lets the cloud orchestrator inject a
  short-lived access token directly, skipping the refresh-token exchange.
  Refresh-token flow remains the default for local operators.

### Added — audit `done` coverage gate

Audit and review sub-agents could previously emit `done` after a single
`read_file: package.json` and exit in 11 seconds with 0 findings. A recent
`@vercel/og` batch (also `@vercel/postgres`, `@vercel/kv`, `@vercel/blob`,
`@vercel/edge-config`, `@auth0/nextjs-auth0`) hit this failure mode; working
scans on the same pipeline made hundreds of tool calls and produced 26
findings each, so the bug was in the agent's `done` heuristic, not the
targets.

- **feat(audit): refuse `done` from sub-agents that haven't inspected source** (#335)
  When a sub-agent with role ∈ {audit, review} and a `scopePath` calls `done`,
  a coverage gate runs. It passes when **any** of:
    1. `>= PWNKIT_AUDIT_MIN_COVERAGE_FILES` (default 3) distinct source files
       have been read (extensions: `.ts/.tsx/.js/.mjs/.cjs/.jsx` plus
       `.py/.rs/.go/.java/.rb/.php/.c/.h/.cpp/.hpp`),
    2. at least one `run_command` invocation succeeded,
    3. wall-clock > 60s **and** >= 5 tool calls, or
    4. the agent has already been rejected twice in this session
       (no deadlock on a legitimately-empty audit).
  Rejections return a tool-result error with concrete next-step guidance
  ("read `src/index.*` or `lib/index.*`, or run a `run_command` with
  grep/rg"). The gate is scoped to source-code audits — flag-hunting against
  remote targets is unaffected, and discovery/attack/verify roles bypass it
  entirely. Threshold is tunable via `PWNKIT_AUDIT_MIN_COVERAGE_FILES`.

### Added — agent + scanner

- **feat(agent): `apply_patch` tool with structured DSL for reliable file edits** (#275)
- **feat(agent): per-finding verify loop + per-file research/audit loops** (#291,
  closes control-flow audit H2 #285)
- **feat(agent): preserve credential/exploit-bearing messages during compaction** (#270,
  closes #229)
- **feat(agent): XML-tag dispatch fallback for cheap-model resilience** (#279,
  closes #232)
- **feat(agent): journal writer foundation** (#321)
- **feat(scanner): gate Codex live scans behind MCP runner** (#295)
- **feat(executor): UUID-suffix container names + `--rm` for parallel sweeps** (#276,
  closes #233)
- **feat(events): include `cost_usd`, `cost_breakdown`, `cost_per_flag` in
  `scan_completed`** (#278, closes #231)

### Added — CLI surface

- **feat(cli): scaffold `pwnkit auth login/logout/status` + `cloud.env` loader** (#315)
- **feat(cli+core): zod-validate the remaining `JSON.parse` sites flagged in
  type-safety audit** (#308)
- **feat(cli): zod-validate `Finding` + `PocStep` JSON inputs in verify/disclose** (#300)
- **feat(h1): pwnkit h1 CLI foundation — auth, programs list/show, scope dump** (#265)
- **feat(review): linux-kernel profile — kernel-aware static review** (#277,
  closes #268)
- **feat(review): c-library profile for C/C++ source-code review** (#261)
- **feat(kernel): foxguard variant-hunt orchestration** (#297)

### Fixed

- **fix(audit, review): hard tool-call / turn budget in prompts** (#318)
- **fix(runtime): retry `isAvailable` on cold-sandbox first-exec slowness** (#317)
- **fix(runtime): handle `codex item.type=mcp_tool_call`** (#311)
- **fix(audit): emit cloud stream events for codex CLI fast-path** (#312)
- **fix(codex-mcp): unblock MCP tool calls + strengthen prompt + dedup stream** (#306)
- **fix(cli): `pwnkit dashboard --no-open` actually suppresses browser open** (#319,
  closes #316)
- **fix(tools): inject auth into bash `curl`/`wget` when scope + authConfig
  are set** (#290, closes #282)
- **fix(tools): dedup findings at `saveFinding` via similarity check** (#288,
  closes #281)
- **fix(tools): refuse empty-PoC findings at `saveFinding`** (#287, closes #283)
- **fix(parser): validate `file:line` existence in `parseStructuredBlocks`** (#289,
  closes #286)
- **fix(h1): contrast-clause aware automation-verdict heuristic** (#274,
  closes #266)
- **fix: resolve local targets with shell path semantics** (#294, closes #255)
- **fix(tui): constrain long text in opentui screens** (#320)

### Refactored

- **refactor(core): remove `Finding` enum `as any` casts** (#305)
- **refactor(cli) + docs: drop `run.ts` type-dup, add h1 docs, flip
  scope-ingestion to shipped** (#299)

### Tests

Coverage backfill for previously-zero CLI / core modules: `triage.ts` (#322),
`findings.ts` (#323), `dashboard.ts` (#314), `orchestrate.ts` (#313),
`mcp-server.ts` (#310), `db.ts` (#309), `disclose.ts` (#307),
`run.ts` + `scan.ts` (#301), and `unified-pipeline.ts` dispatch + ecosystem
paths (#326). Plus `crawl` no-redirect happy path + redirect-loop cap (#267)
and `cost.ts` model rate table + prefix stripping (#257).

### Docs + research

- **docs(research): journal orchestrator design doc** (#259, closes #224)
- **docs(research): cost-per-flag deep dive — the missing axis in agent
  reporting** (#256)
- **docs(blog): control-flow audit — 5 chokepoints gated in code** (#296,
  closes #280)
- **docs(agents): mandate worktrees for parallel top-level agent sessions** (#264)
- **docs(agents): issue-assignment claim-before-start rule** (#273)
- **docs(readme): trim Snapshot block to one-liner + link canonical benchmark
  page** (#260)
- **docs(readme): drop stale v0.9.0 'npm shim' heads-up; clarify binary
  names** (#262)
- **feat(bench): per-model cost aggregation in `consolidate-xbow` output** (#258)
