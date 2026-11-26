---
title: Configuration
description: Settings, environment variables, telemetry, updates and the security model.
---

0 reads settings from files, environment variables and command-line flags. This page covers those, plus telemetry, updates and the security model. Provider keys and model routing are on [Models](/models/).

## Quick start

```bash
0security config get                              # effective settings, each labelled default, global or project
0security config get --export ./settings.json     # write the effective settings as JSON
0security config set --from-file ./settings.json  # merge into the global layer
0security config doctor upgrade                   # install the latest release
```

0 resolves each setting in this order, highest first: command-line flag, environment variable, project settings, global settings, built-in default.

## Execution profile

`executionProfile` chooses where the agent and its tools run. It does not choose the model.

| Value | Meaning |
| --- | --- |
| `local` | Default. Helpers, browser and shell run on your computer. |
| `smolvm` | Everything runs inside a local Kali VM (the workbench). |

Set up the workbench, then start the app:

```bash
0security config doctor workbench setup --image /absolute/path/0-workbench-linux-arm64.tar --provider chatgpt-codex
0security config doctor workbench status --json
0
```

Setup downloads the pinned VM runtime and approves a local image archive by its digest. It never trusts a mutable registry tag. The native runtime is qualified on Apple Silicon macOS.

| `setup` option | Default | Effect |
| --- | --- | --- |
| `--image <archive>` | saved approved image | Local OCI or Docker archive to approve (limit 8 GiB). |
| `--state <directory>` | `~/.0/workbench` | VM state, image approval and guest data. |
| `--workspace <directory>` | current directory per launch | Host folder mounted at `/workspace` in the guest. |
| `--provider <id>` | none | Grant a host provider account to the guest. Repeat to grant several. `0security config doctor workbench providers` lists the IDs. |
| `--no-github` | | Revoke the GitHub token grant. 0 refuses to forward a GitHub token. |
| `--cpus`, `--memory <MiB>`, `--storage <GiB>` | `2`, `4096`, `20` | Guest resources. |
| `--sandbox-image <reference=archive>` | none | Approve a `repository@sha256:<64 hex>` image for isolated container actions. Repeat for more. |

Change the setup later:

```bash
0security config doctor workbench configure --provider openai,anthropic --no-github   # replace grants
0security config doctor workbench configure --provider none                           # revoke provider grants
0security config doctor workbench configure --current-workspace                       # drop a fixed workspace
0security config doctor workbench configure --clear-sandbox-images
0security config doctor workbench disable                                             # return to local; keeps image and state
```

- Your choices live in `~/.0/workbench.json`, readable only by you. It holds no credential values.
- The guest sees only the providers you grant. Your home folder, SSH keys, Docker sockets and other environment variables are not forwarded.
- If the runtime, image or admission check fails, 0 refuses to launch. It never falls back to the host.
- Project settings cannot change the profile. A change applies at the next launch.
- `0security config doctor workbench status` is read-only and downloads nothing.

## State directory

0 keeps per-user state in `~/.0`.

| Path | Purpose |
| --- | --- |
| `tui-settings.json` | Global settings. |
| `credentials.json` | Stored API keys, mode `0600`. |
| `console-sessions/` | One transcript JSON per thread. |
| `engines.json` | Registered remote computers. See [Computers](/computers/). |
| `workbench.json` | Workbench choices. |
| `metrics.ndjson` | One line per scan, fix and verify run: cost, duration and counts. See [findings metrics](/commands/#findings-metrics). |
| `last-update-check` | Cache for update checks. |
| `feedback.md` | Locally staged feedback. |
| `diagnostics/pending/` | Crash reports waiting for your review, mode `0600`. Used only when `diagnosticReporting` is `ask`. Holds at most 10, oldest removed first. |
| `analytics-id` | The random install ID for anonymous usage counts. Delete it to start a new one. |
| `analytics-sent.log` | A copy of every usage payload this machine sent. |
| `analytics-last-version` | The last version that ran, as a version string only (mode 0600). 0 uses it to send an `update` event. |
| `telemetry-notice` | Marks that the one-time telemetry notice was shown. Delete it to see the notice again. |

Project settings live in `<project>/.0/tui-settings.json`.

Set the database file with `--db-path` or `ZERO_DB_PATH`. `--db-path` wins. Moving one path does not move the others.

A running console is tied to one folder and owns its database. If you run `0security skills list` or `0security threads list` from another folder, it stops with `This console is for <folder>. Run the command there, or add --db-path <path>.`

Thread transcripts hold target hostnames, findings and raw request and response bodies, including any cookies or tokens a tool echoed. 0 does not scrub or encrypt them. File permissions (`0600` files, `0700` directory) are the only protection.

## Set a budget and model per workflow

Scan, fix and verify can each have a default budget in USD and a default model. Add a `workflows` key to `~/.0/tui-settings.json`:

```json
{
  "workflows": {
    "scan": { "budget": 2 },
    "fix": { "budget": 0.5, "model": "gpt-6-luna" },
    "verify": { "budget": 1 }
  }
}
```

The budget becomes the default for `--budget` and the model the default for `--model` of `0security scan`, `0security findings fix` and `0security findings verify`. A flag you pass always wins. For verify, the budget is the total for the run.

Only this file sets the defaults. A project settings file cannot, so a repository you open cannot pick your model or your spend. An invalid entry is ignored. `0security findings burndown` reads the `fix` entry: its budget becomes the default for `--per-fix` and its model the default for `--model`. The total `--budget` of a burndown run has no default here.

## The `0security config` command

`0security config` reads and writes computer settings. Set appearance in the browser app under Settings.

```bash
0security config get
0security config get <key>
0security config set <key> <value> [--project] [--yes]
0security config set --reset [keys...] --yes
0security config get --export [file] [--global]
0security config set --from-file <file> [--global | --project] [--yes]
```

Settings resolve in layers, highest first: project, global, default. When settings load, 0 drops unknown keys and resets invalid values to the default.

A project cannot change these settings: `analyticsLevel`, `diagnosticReporting`, `updatePolicy`, onboarding state, development source updates, `executionProfile`, `approvals`, `archiveIdleDays`, `findingsContext` and `executedPocImage`.

`0security config set --from-file <file>` refuses to change these security-sensitive settings unless you pass `--yes`: `executionProfile`, `allowModelSelfExtension`, `allowDevSourceUpdates`, `allowSubagentPeerMessaging` and `allowSubagentOperatorMessaging`. It prints each rejected change.

Two conversation settings are worth knowing:

- `titleInstructions` guides automatic thread titles, for example a language or style. It takes up to 500 characters.
- `archiveIdleDays` archives saved threads idle for that many days when the app starts. Use `0` for off and at most `365`. It is global only.
- `findingsContext` is the path of your business context file. Commands that order findings use it unless you pass `--context`. It is global only. See [Rank findings by what matters to you](/findings/#rank-findings-by-what-matters-to-you).
- `executedPocImage` is a container image pinned by digest (`name@sha256:...`) in which `0security scan` runs the proof of concept of each high or critical finding, network off. Empty keeps it off. `scan --poc-image` and the `ZERO_POC_IMAGE` variable win over it. A tag is refused. It is global only. See [Executed proof of concept](/findings/#executed-proof-of-concept).

### Ask before running commands

`approvals` is `auto` or `ask`. With `auto`, the default, threads and Sentinels run commands without asking. With `ask`, 0 puts each command or change to you first.

The same applies inside helpers. A subagent or a persistent worker that a thread starts also asks before each command or file change, so approving the spawn does not approve what the helper runs. An unattended Sentinel under `ask` waits for a decision on each call, and several workers at once queue several prompts. Use `auto` for runs nobody watches.

Set it with **Ask before running commands** under **Settings → Helpers**. To override it for one run, pass `--approvals ask|auto` to `0security -p`. Threads and Sentinels follow this one setting. Reset all leaves it alone.

### Development source updates

Enable **Development source updates** (`allowDevSourceUpdates`) only for a source checkout you trust. It reloads changed computer code between turns, and that code runs with the full access of the console process, including your credentials.

Start a development console from the checkout with `./scripts/0dev.sh web`. A build failure stops the launch. For frontend work, run `pnpm dev`.

## Environment variables

Set them inline, for example `env ZERO_LOG_FORMAT=json 0`.

### Output

| Variable | Effect |
| --- | --- |
| `ZERO_LOG_FORMAT=json` | Write operational records as NDJSON on stderr. They hold lifecycle and cost metadata only, and are not uploaded. |
| `ZERO_DB_PATH` | Database file. |
| `ZERO_SANDBOX_DIR` | Folder where `0security findings fix --sandbox docker` copies the work tree. It must be shared with the Docker VM. |
| `ZERO_SUPPRESS_PROVIDER_STARTUP_LOG=1` | Hide the `Provider:` startup line. |
| `ZERO_RUNTIME_TRACE=1` | Print the runtime, provider and model to stderr. |

### Sandbox

| Variable | Default | Effect |
| --- | --- | --- |
| `ZERO_SANDBOX` | `auto` | OS sandbox for extension scripts and MCP servers: `auto` (extensions that declare a `sandbox` block), `require` (every extension, refuse when none is available) or `off`. See [Sandboxing](/extensions/#sandboxing). |
| `ZERO_SANDBOX_NODE_PERMISSION` | on | Set to `off` to start sandboxed `node` programs without `--permission`. See [Node scripts and servers](/extensions/#node-scripts-and-servers). |
| `ZERO_SANDBOX_CPU_SECONDS` | unset | CPU time limit for a sandboxed run. |
| `ZERO_SANDBOX_MEMORY_MB` | unset | Memory limit for a sandboxed run. Linux only. |

### Retries and timeouts

| Variable | Default | Purpose |
| --- | --- | --- |
| `ZERO_LLM_STREAM_IDLE_TIMEOUT_MS` | `120000` | Abort a stream that stops sending bytes. |
| `ZERO_LLM_STREAM_EVENT_IDLE_TIMEOUT_MS` | `240000` | Abort a stream that sends only keep-alives. |
| `ZERO_LLM_MAX_RETRIES` | `6` | Retries for 429 and transient 5xx, with backoff. |
| `ZERO_LLM_MAX_RETRY_WAIT_MS` | `60000` | Total backoff cap. |
| `ZERO_LLM_429_MAX_RETRIES` | `12` | Retries for rate limits. |
| `ZERO_LLM_429_MAX_RETRY_WAIT_MS` | `300000` | Total backoff cap for rate limits. |

0 never retries auth errors (401, 403). The run fails with the provider error instead of reporting a clean "0 findings". Cancelling a run stops it for good.

### Parallel agents

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZERO_SUBAGENT_MAX_FANOUT` | `1024` | Helpers requested in one batch. |
| `ZERO_SUBAGENT_MAX_WORKERS` | `4096` | Queued and active workers in one audit tree. |
| `ZERO_SUBAGENT_CONCURRENCY` | `32` | Helpers running at once per batch. |
| `ZERO_SUBAGENT_MAX_DEPTH` | `8` | Nested subagent depth. |

Values are positive integers. Restart the computer after you change them. Provider rate limits still apply.

Three of these limits are also settings: `subagentConcurrency` (1-128, default 32), `subagentMaxDepth` (1-16, default 8) and `subagentFanOut` (1-4096, default 1024). The `ZERO_SUBAGENT_*` variables win over them. A project can only lower them.

### Feature gates

| Variable | Effect |
| --- | --- |
| `ZERO_FEATURE_MULTIMODAL` | Turn multimodal input on or off. |
| `ZERO_FEATURE_WEB_SEARCH` | Turn the `web_search` tool on or off. |
| `ZERO_WEB_SEARCH_PROVIDER` | Choose the search backend: `parallel` (default) or `keenable`. Any other value makes `web_search` refuse. |
| `KEENABLE_API_KEY` | Optional key for the Keenable backend. It raises the rate limit and is read only from the environment. |

A gate does not supply the credentials or tools its feature needs.

### Dashboard

Set this on the process that runs `0security`.

| Variable | Default | Effect |
| --- | --- | --- |
| `ZERO_CSP` | `enforce` | Content-Security-Policy mode: `enforce`, `report-only` or `off`. Leave it on, because the page embeds the control token. |

### Deprecated names

A deprecated name still works. 0 copies it to the new name and prints one notice on stderr. Set `ZERO_NO_DEPRECATION_WARNINGS=1` to silence the notice.

| Deprecated | Use |
| --- | --- |
| `ZERO_CHATGPT_AUTH_FILE` | `ZERO_CODEX_AUTH_JSON_PATH` |
| `ZERO_SKIP_PROVIDER_BANNER` | `ZERO_SUPPRESS_PROVIDER_STARTUP_LOG` |

## Telemetry

In official release builds, 0security sends anonymous usage counts and crash reports by default. Each has its own switch, and both follow the data boundary below.

| Setting | Default | Values |
| --- | --- | --- |
| **Usage metrics** (`analyticsLevel`) | `usage` | `off`, `usage` |
| **Problem reports** (`diagnosticReporting`) | `automatic` | `off`, `ask`, `automatic` |
| **Updates** (`updatePolicy`) | `automatic` | `off`, `notify`, `automatic` |

Each setting is global to your computer, and project settings cannot change it. 0 keeps a saved `off`, `ask` or `automatic`. An install with no recorded choice uses `automatic`. To choose `ask`, run `0security config set diagnosticReporting ask` or use the browser app under Settings, Privacy.

### First-run notice

The first time you run the CLI or the console, 0security prints one notice to stderr. It is one line. It says that usage counts, command names and crash reports are on, that they never include code or findings, and that `DO_NOT_TRACK=1` turns them off. It links here. 0 prints it once per install, and only when stderr is a terminal. It never prints in CI, with `--format json`, `--json` or other machine formats, with `ZERO_LOG_FORMAT=json`, or when telemetry is already off. The browser app shows the same disclosure under Settings, Privacy.

### Usage metrics

When `analyticsLevel` is `usage`, a release build sends anonymous events directly to 0security's PostHog project in the EU (`https://eu.i.posthog.com`). You need no account. There are five event types, and each carries only the fields listed for it.

Every event also carries these common fields:

| Field | Meaning |
| --- | --- |
| `version`, `channel` | 0security version and release channel (`beta` or `dev`). |
| `surface` | `web` for the console, otherwise `cli`. |
| `os`, `arch`, `runtime` | Operating system, CPU architecture, and `node` or `bun`. |
| `$lib`, `$geoip_disable`, `$process_person_profile`, `$ip` | Fixed values (`0security`, `true`, `false`, `null`) that turn off IP lookup and person profiles. |

**`usage`** is sent while a command or the console does work:

| Field | Meaning |
| --- | --- |
| `tool_counts` | How many times each built-in tool ran. MCP tools count as `mcp`, any other name as `other`. |
| `error_counts` | Tool failures by category (`timeout`, `network`, `permission`, `not-found`, `rate-limit`, `parse`, `resource`, `nonzero-exit`, `stream-incomplete`, `tool-error`, `other`). |
| `finding_severity_counts` | Findings by severity (`critical`, `high`, `medium`, `low`, `info`, `unknown`, `other`). |
| `finding_class_counts` | Findings by vulnerability class: `sql-injection`, `xss`, `ssrf`, `rce`, `path-traversal`, `auth`, `crypto`, `secrets`, `deserialization`, `misconfiguration`, `dependency` or `other`. Counts only. |
| `turn_count`, `duration_ms`, `cost_usd` | Agent turns, time spent, and model spend in USD when known. |

**Lifecycle events** say that something happened, not what it was about:

| Event | When | Fields |
| --- | --- | --- |
| `first_run` | Once, the first time an install runs. | None beyond the common fields. |
| `command_invoked` | Each time you start a command or the console. | `command`: the command name from a fixed list of known commands. Anything else is `other`. Arguments are never sent. |
| `update` | The first run after the version changed. | `from_version`, `to_version`. |
| `error_exit` | A command ends with an error. | `error_category`: one of the error categories above. The message is never sent. |

Each event also has a timestamp and a `distinct_id`, which is a random UUID (the install ID). It is not derived from your name, email, hostname, MAC address or machine ID. 0 sends counts as increments, shortly after they happen and when the process exits. A send has a 3 second limit and no retries, and failures are silent.

PostHog discards IP addresses, and 0security disables GeoIP lookup. To get a new install ID, delete `~/.0/analytics-id`. `~/.0/analytics-sent.log` records every payload sent, without the project key.

Lifecycle events are not sent for `--help`, `--version`, `help`, shell completion, or the `config`, `reports` and `workbench` commands. They are also not sent in CI (`CI` set) or with machine output (`--json`, `--format json`, `ZERO_LOG_FORMAT=json`), because the notice is not shown there. To send them anyway, run `0security config set analyticsLevel usage`.

`DO_NOT_TRACK=1` stops every event. So does `ZERO_ENTERPRISE=1`.


### What is never collected

No telemetry includes any of these: targets, URLs, hostnames, IP addresses, file paths, finding titles, descriptions or evidence, prompts, model output, chat messages, tool arguments or results, source code, credentials, environment variables, usernames, or error message text.

Every string passes through one redaction step before it leaves the process. The fields above are an explicit allowlist per event, so a new field or event cannot be sent without a deliberate change.

### Crash reports

The terminal and the browser app share one crash reporter and one destination. A report carries a `surface` tag (`cli` or `web`) and nothing else about which interface produced it. 0 captures reports in two places:

- Computer process. A last-resort handler catches uncaught exceptions and unhandled rejections. The error is still printed to stderr and the exit code is still `1`. The exit waits at most two seconds for reporting.
- Browser app. An error boundary and window error listeners send only a closed error category and locations inside the built app bundle. The computer validates them again. 0 collapses repeated errors to one report per minute, at most five per page session.

Your `diagnosticReporting` choice decides what happens to a report:

| Value | What happens |
| --- | --- |
| `off` | 0 drops the report. Nothing is stored or sent. |
| `ask` | 0 stores the report in `~/.0/diagnostics/pending/`. It sends nothing until you preview the exact body in the browser app (Settings, Feedback) and confirm. |
| `automatic` | 0 sends the report once, with a short timeout, and ignores a failure. This is the default. |

A report contains the error class (for example `TypeError`), the 0security version and release channel, Node version, operating system, CPU architecture, the surface, and the name of the running command from the built-in list, never its arguments. It also holds scrubbed locations inside 0security's own code. It never contains error messages, command output, file paths, targets, hostnames, findings, source code or credentials.

`0security config doctor` prints one line when reports are waiting. `0security config doctor --discard-reports` deletes them without sending anything.

### Opt out of telemetry

`DO_NOT_TRACK=1` is the switch. `ZERO_ENTERPRISE=1` also turns telemetry off. Both beat every saved setting.

| How | Effect |
| --- | --- |
| `DO_NOT_TRACK=1` | Turns off usage metrics, lifecycle events and crash reports. Any value except empty, `0`, `false` or `no` counts. An organization can set it for every operator, and it overrides each person's settings. |
| `ZERO_ENTERPRISE=1` | No-egress mode. It turns off telemetry, lifecycle events, crash reports, update checks, model catalog and price lookups, web search, remote extension sources and the other third-party calls. Project settings cannot change it. See [Data flow and no-egress mode](/data-flow/). |
| `0security config set analyticsLevel off` | Turns off usage metrics and lifecycle events. |
| `0security config set diagnosticReporting off` | Turns off crash reports. Use `ask` to review each one first. |
| Browser app, Settings, Privacy | The same two switches. |

```bash
export DO_NOT_TRACK=1
0security config set analyticsLevel off
0security config set diagnosticReporting off
```

### Send telemetry to your own projects

Release builds embed the PostHog project key and the Sentry DSN, and so does the published Docker image. Source builds, pull-request builds and a `docker build` without the build secrets embed neither, so they send nothing. To send telemetry to your own projects, set:

- `ZERO_ANALYTICS_POSTHOG_KEY`: a PostHog project key (`phc_` followed by letters and digits). An empty value turns off the direct PostHog path.
- `ZERO_ANALYTICS_POSTHOG_HOST`: the PostHog host. It must be `https`, or `http` on `localhost`, `127.0.0.1` or `::1`. Any other value turns off the path.
- `ZERO_SENTRY_DSN`: your own HTTPS Sentry project for crash reports. An empty value turns them off.

`/feedback <message>` in a thread saves a note in `~/.0/feedback.md`. 0 sends nothing until you confirm a staged payload. To send feedback to your own HTTPS relay, set `ZERO_FEEDBACK_URL`. Do not put a Slack webhook URL there.

## Update checks

At startup, 0 checks GitHub for a newer release, at most once every 24 hours. What happens next depends on `updatePolicy`.

| Policy | Behavior |
| --- | --- |
| `automatic` | Default. Runs the installer before starting, then tells you to restart. This can delay startup by a few seconds. A running console also updates in the background ([see below](#update-a-running-console)). |
| `notify` | Prints `Update available: <old> → <new>. Run 0security config doctor upgrade.` In the console, the update card waits for your click. |
| `off` | Makes no request. |

Only an explicit global choice moves the setting off `automatic`.

The check runs only in an interactive terminal. It is skipped when `CI`, `ZERO_NO_UPDATE_CHECK` or `ZERO_OFFLINE` is set to a non-empty value other than `0` or `false`. Project settings cannot change the policy. Windows has no automatic installation, so download a release instead. A Windows install has a single `0.exe`, with no `0security` alias.

```bash
0security config doctor upgrade                    # install the latest release now
0security config doctor upgrade --version v0.10.0  # pin a release
env ZERO_NO_UPDATE_CHECK=1 0               # skip the check for one run
```

The upgrade runs the same `install.sh` as a fresh install. 0 rate limits repeated attempts for one release tag. It replaces the folder the running binary lives in when that folder is writable. Otherwise it installs to `~/.0/bin`. Override the folder with `--install-dir` or `ZERO_INSTALL_DIR`.

If GitHub is offline, rate limited or unreachable, 0 starts with the old version and checks again the next day.

To point the check and the installer at a mirror, set `ZERO_UPDATE_ORIGIN`. The mirror must serve `/latest`, `/install.sh` and `/releases/download/<tag>/<asset>`.

### Update a running console

The console can run for days, so it does not wait for the next start. This applies to a standalone binary in a writable folder (a managed install).

- Every six hours, with up to ten percent random spread, the console asks for the newest release and caches the answer in `last-update-check`. With **Automatic**, it installs the verified release in the background only while no thread is running. Then it shows **Restart to finish updating**.
- The **Update available** card has **Update and restart**. It runs the same installer as `0security config doctor upgrade`, with a checksum check and an atomic swap. Then it restarts the same command with the same port, `--db-path` and `--asset-dir`. The page shows **Updating…**, reconnects on its own and reports **Updated to <version>**. If threads are running, it asks first, because the restart stops them.
- With **Automatic**, server mode off and no service manager, the console also restarts by itself after 10 minutes of inactivity. In [server mode](/server-mode/) it never restarts itself and shows the card instead.
- Under launchd, systemd or pm2, the console exits with code 0 after installing and expects the service manager to start it again. 0 detects these from the environment. You can set `ZERO_SUPERVISED=1` or `0` to override. Use `KeepAlive` (launchd), `Restart=always` (systemd) or pm2's default.

Only the browser console can start an update. An attached engine or tool is refused. Only one update runs at a time.

The card offers a button only when it can work:

- Docker images are replaced, not changed in place. Run `docker pull ghcr.io/0sec-labs/0security:latest`, then recreate the container.
- A source checkout updates with `git pull` and a rebuild.
- An npm install must move to the standalone binary.
- A binary in a read-only folder, or on Windows, shows `0security config doctor upgrade`.

## Execution boundary

The default shell executor runs on your host. It is not a firewall, container or VM. Use a disposable environment for untrusted code and targets.

## Cost estimates

0 shows estimated model cost on each thread. Provider and infrastructure costs are yours. Set a spending limit with your provider.

The estimator prices input, output, cached-input and cache-write tokens from a bundled rate table. An unknown model price is unknown, not zero.

- Gateway prices can differ from direct-provider prices, even for the same model name.
- Subscription routes (ChatGPT Codex, coding plans) have their own allowances. Token-dollar estimates do not show remaining quota.
- Failed or cancelled requests can use provider capacity without usage reaching the CLI. Check your provider invoice.

## Security model

0 runs as you, with bash. The agent can do what you can do in a terminal. Your defences are approvals, the sandbox when you use one, and the controls below. This section covers third-party code and text: extensions, MCP servers and skills.

### Extensions and MCP

An extension or MCP server you add runs other people's code as your user. 0 puts an explicit review in front of it. An extension can also declare an OS sandbox, which you approve with it and which `ZERO_SANDBOX` controls. Setup is in [Extensions](/extensions/).

- Commit pins. 0 fetches a git extension without running anything and pins it to a full 40-character commit. It refuses branches, tags and short SHAs. It hashes the installed folder and blocks the extension until you review it again if the folder changes. It pins local folders by content hash.
- The install prompt. It shows `repo @ commit`, the licence, the file list, hidden-Unicode flags and what the extension can do: scripts it ships, MCP servers (command or URL, variable names), and services it calls (hosts, read or write). Your click echoes the commit, and the server checks that the revision it installs is the one you saw. Only you can approve. 0 refuses an install requested by a thread or without a terminal. The audit log records `extension.install` with the commit and capabilities.
- Updates prompt again. Any change, even one new script, shows the folder diff and a capability delta and asks again. Third-party extensions never update silently. Built-ins update with the binary.
- Per-tool MCP pins. The first time an MCP server connects, you approve its tools. 0 stores a sha256 of each tool's name, description, input schema and annotations. If any tool is changed, new or removed, 0 blocks the whole server until you approve again. MCP servers start only when the model first loads them, and run through `beforeCommand` (your approvals). 0 labels their output untrusted and caps it. See [MCP servers in extensions](/extensions/#servers-bundled-in-an-extension).
- Environment allowlist. A process gets a scrubbed environment plus only the variable names the extension declared and you approved. 0 never passes provider keys unless the extension declares them and the prompt shows them. 0 always rejects loader variables (`LD_PRELOAD`, `DYLD_*`, `NODE_OPTIONS`). A connection token reaches only a declared variable.
- Sandbox. An extension that declares a `sandbox` block runs its scripts and MCP servers with no network, no access to your home folder and writes only to a scratch folder, unless it declared more and you approved it. `ZERO_SANDBOX=require` applies this to every extension. See [Sandboxing](/extensions/#sandboxing) for the limits.
- Repo config is a suggestion. A repository's `.0/` or `.claude/` files cannot install or enable anything.
- Network. Remote MCP servers need https (plain http only to loopback). 0 refuses hosts that resolve to private, loopback, link-local or metadata addresses, and does not follow redirects.

#### Residual risk

- An approved extension or MCP server without a sandbox can read your files, use your network and run programs as your user. Approval is informed consent, not isolation. The OS sandbox narrows this but is not a container. Use a Computer or SmolVM when you need isolation.
- A commit pin shows you got the code you reviewed, not that it is safe. Review the repository, not only the manifest.
- Extensions have no signatures or publisher identity. A catalog entry marked verified means 0 curated it and pinned its commit.
- An MCP server sees what the agent sends it. Its tool names, descriptions and results can contain prompt injection.

Skills from GitHub get the same treatment: a pinned snapshot, a preview and an explicit click. See [Skills](/skills/#adding-skills-from-github).

### Who can approve

Approval routes work only from the browser. Agent callers get `403 browser_only`, so an agent cannot add or approve its own tools. In team mode, only the workspace owner can use them (`403 owner_required`).

Report problems through the [security policy](https://github.com/0sec-labs/0security/blob/main/.github/SECURITY.md).

## Limits

- Cost figures are estimates, and unknown model prices count as unknown, not zero.
- 0 writes operational logs to stderr. Collect them with your runner or container logging.
