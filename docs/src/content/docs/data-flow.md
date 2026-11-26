---
title: Data flow and no-egress mode
description: Every outbound network destination of 0, when it is used, what is sent, and how to turn it off. One switch, ZERO_ENTERPRISE, keeps everything off except the model endpoint you configure.
---

This page lists every place 0 can send data off the computer it runs on. It exists so a security team can check the claim "nothing leaves the network except the model endpoint we configured" instead of taking it on trust.

## What leaves your machine

Your code stays on your machine. 0 sends what you choose to your model provider. By default it also sends anonymous usage counts and lifecycle events (first run, which command ran, an update, an error exit) and crash reports, and it checks GitHub for updates. `DO_NOT_TRACK=1` stops the telemetry and crash reports. `ZERO_NO_UPDATE_CHECK=1` stops the update check. `ZERO_ENTERPRISE=1` is the no-egress mode below. It blocks every automatic outbound call, including telemetry, lifecycle events and crash reports.

## No-egress mode

Set one environment variable on every computer or container that runs 0:

```bash
export ZERO_ENTERPRISE=1
```

Any value except empty, `0`, `false` or `no` turns it on. With it on, 0:

- sends no telemetry, lifecycle events or crash reports;
- makes no update check and refuses `0security doctor upgrade`;
- skips the public model catalog and price lookups, so models without a built-in price show no cost;
- removes the `web_search` tool and refuses the advisory lookup, remote extension sources, the sandbox runtime download, GitHub repository and skills directory reads, SARIF upload through `gh`, and remote worker provisioning;
- still talks to the model endpoint you configured, and to the destinations in the "Chosen by you" table, because you named them.

It is read from the process environment only. A project file such as `<project>/.0/tui-settings.json` cannot set or clear it, so a repository you open cannot switch egress back on. It also counts as an opt-out for the public model and price lookups, which already honor `ZERO_OFFLINE` and `DO_NOT_TRACK`, so those gates cannot drift apart from it.

### Internal Bitbucket Data Center

A self-hosted review or fix workflow can reach one explicitly approved Bitbucket installation while `ZERO_ENTERPRISE=1` stays on:

```bash
export ZERO_ENTERPRISE=1
export ZERO_BITBUCKET_URL=https://bitbucket.internal.example/bitbucket
export BITBUCKET_URL="$ZERO_BITBUCKET_URL"
```

`ZERO_BITBUCKET_URL` comes only from the process environment. It authorizes that exact origin (scheme, host and port) and its context path, including REST and HTTPS git endpoints. It does not enable any other outbound destination. HTTPS is required except on loopback for local testing. Pagination and redirects cannot move credentials outside that origin or context path. Git reviews reject URL rewrites and mismatched repository origins and disable HTTP redirects; use a direct HTTPS origin such as `https://bitbucket.internal.example/bitbucket/scm/PROJECT/repo.git`. Supply git credentials through the runner's trusted credential setup; the review scan does not receive the Bitbucket API token.

This is an application allowlist, not a network firewall. Configure DNS, TLS trust and network policy for the installation you approved. Public advisory lookup and other automatic third-party calls stay disabled. Bitbucket Cloud's separate API and git origins are not implicitly enabled by this setting.

The switch is off by default. An ordinary install keeps its current behavior. For a container, set it in the container environment; for a managed laptop, set it in the shell profile or the device policy.

`DO_NOT_TRACK=1` stops telemetry on its own, without the rest of the mode. For belt and braces, set both on a no-egress install. `~/.0/analytics-sent.log` records every analytics payload that leaves, so it stays empty.

## Verify it yourself

The repository tests this in the engine and CLI test suites. Each test starts a local stub model server, turns on the switch, runs the call sites that the switch blocks, and patches `fetch`, `node:http`, `node:https`, sockets and the `gh`, `curl`, `git` and `ssh` launchers to record every attempt. It fails when anything other than the stub is contacted. A control case runs the same lookups with the switch off and checks that the recorder sees them, so a silent recorder cannot pass. A second check fails when a source file adds an outbound call that is not in the inventory below.

To check a real install, run `node scripts/airgap/verify-no-egress.mjs`. See [Air-gapped installation](/self-hosting/#air-gapped-installation).

For a stronger guarantee than a test, also block egress at the network: run 0 in a container or network namespace whose only route is your model gateway, then run a scan with `ZERO_ENTERPRISE=1`. The switch gives you the same result without relying on the block, and the block catches a mistake the switch could not.

## Telemetry

`DO_NOT_TRACK=1` or `ZERO_ENTERPRISE=1` stops every row here. `ZERO_OFFLINE` does not.

| Entry | Destination | When | What is sent | How to disable |
| --- | --- | --- | --- | --- |
| `usage-analytics-posthog` | `eu.i.posthog.com` | Batched while a command or the console runs, in a release build. Lifecycle events are skipped for `--help`, `--version`, shell completion, `config`, and CI or machine-output runs unless you set `analyticsLevel usage` yourself. | Anonymous counters, plus lifecycle events (`first_run`, `command_invoked`, `update`, `error_exit`) that name a known command or an error category and nothing else. The field list is under [Usage metrics](/configuration/#usage-metrics). | `DO_NOT_TRACK`, `ZERO_ENTERPRISE`. |
| `crash-and-feedback` | Sentry (embedded project or `ZERO_SENTRY_DSN`), the feedback endpoint | A crash with `diagnosticReporting automatic`, or feedback you send. | A redacted crash envelope or the feedback text you reviewed. | `diagnosticReporting off`, `DO_NOT_TRACK`, `ZERO_ENTERPRISE`. |

## Blocked by `ZERO_ENTERPRISE`

| Entry | Destination | When | What is sent | How to disable without the switch |
| --- | --- | --- | --- | --- |
| `update-check` | `api.github.com`, `github.com`, `raw.githubusercontent.com` | Interactive start-up, console update status, `0security doctor upgrade`. | A GET for the latest release tag; the installer on upgrade. | `updatePolicy off`, `ZERO_NO_UPDATE_CHECK`, `ZERO_OFFLINE`. |
| `model-catalog-sync` | `models.dev` | Console model picker refresh. | A GET of a public list. | `DO_NOT_TRACK`, `ZERO_OFFLINE`. |
| `pricing-discovery` | `openrouter.ai` | A model has no built-in price. | A GET of a public list. | The same. |
| `web-search-tool` | `mcp.parallel.ai`, `html.duckduckgo.com`, `api.keenable.ai` | The agent calls `web_search`. `api.keenable.ai` replaces `mcp.parallel.ai` only when `ZERO_WEB_SEARCH_PROVIDER=keenable`. | The search query the model wrote, and `KEENABLE_API_KEY` if you set it. | `ZERO_FEATURE_WEB_SEARCH=0`. |
| `osv-advisory-lookup` | `api.osv.dev` | `0security sbom check` and evidence bundles with advisories. | Package URLs from the SBOM. | Skip the check. |
| `foxguard-sca-osv` | `api.osv.dev` | Foxguard runs with `--sca`, or reads `scan.sca` from a `.foxguard.yml` you let it read with `--repo-ignores`. 0 never passes `--sca`. | Package names, versions and ecosystems from the lockfiles in the scanned folder. | Do not pass `--sca`. Foxguard skips the lookup when `ZERO_ENTERPRISE` or `ZERO_OFFLINE` is set. |
| `sbom-outdated-lookup` | `api.deps.dev` | `0security sbom check --outdated`. | Package names from the SBOM (at most 200). | Do not pass the flag. |
| `sbom-slopsquat-registry` | `registry.npmjs.org`, `api.npmjs.org`, `pypi.org` | `0security sbom check --registry`. | Package names of npm and PyPI components (at most 200). No versions, paths or project details. | Do not pass the flag. `ZERO_ENTERPRISE` and `ZERO_OFFLINE` refuse it. |
| `sbom-licenses-resolve` | `api.deps.dev` | `0security sbom licenses --resolve`. | Package names and versions of components with no stated license. | Do not pass the flag. |
| `sbom-resolve-build-tools` | The repositories the project's build files name (Maven Central by default) | `0security sbom generate --resolve`, after you confirm. | Whatever the project's own `mvn` or `gradle` sends. It also runs the project's build scripts. | Do not pass the flag. |
| `team-sign-in-saml` | The SAML metadata address you configured | Team sign-in with SAML, only with a `metadataUrl`. | A GET of the provider's public metadata. Use `metadataFile` to avoid it. |
| `extension-git-source` | `github.com` or the https git host you give | Installing or updating an extension from a remote source. | A shallow fetch of one pinned commit. | Install from a local folder. |
| `extension-connector-health` | Hosts an installed connector declares | The console shows connector status. | A GET carrying the connector token. | Do not install connectors. |
| `smolvm-provision` | `github.com` | Explicit setup of the macOS sandbox runtime. | A GET of a pinned archive, checked against a fixed hash. | Preinstall the runtime. |
| `skills-catalog` | `api.github.com` | Previewing or installing from the console skills directory. | Read-only API calls through your `gh` login. | Do not use the directory. |
| `github-repository-list` | `api.github.com` | The console repository picker and GitHub account status. | Read-only API calls through your `gh` login. | Use local paths. |
| `github-gh-commands` | GitHub, through `gh` | `0security findings upload` and host integrations. | The request you asked for. | Do not run them. |
| `remote-worker-provisioning` | `nodejs.org`, apt and npm registries, from the remote computer | `0security computers add`. | Package downloads. | Prepare the remote computer yourself. |

## Dependency audit

Generating an SBOM and checking licenses from the SBOM make no network request. The lookups in the table above are the only network use of the dependency checks:

- `sbom check` sends package URLs to `api.osv.dev`.
- `sbom check --outdated` sends package names to `api.deps.dev`.
- `sbom licenses --resolve` sends package names and versions to `api.deps.dev`.
- `findings evidence --check-advisories` sends package URLs to `api.osv.dev`.
- `sbom generate --resolve` runs your own `mvn` or `gradle`, which contacts the repositories your build names.
- `sbom generate --generator syft` or `trivy` with `--image` runs that tool, which may pull the image.

`sbom generate --resolve-from`, `sbom java-usage`, `sbom scan-models` and `sbom agent-config` send nothing. See [Dependency audit](/dependency-audit/).

## Your model endpoint

| Entry | Destination | When | What is sent |
| --- | --- | --- | --- |
| `llm-model-endpoint` | The provider base URL or gateway you configured | Every model call and model-list discovery. | Prompts, tool results and code excerpts the model needs. |
| `azure-entra-token` | `login.microsoftonline.com` or the authority in `AZURE_AUTHORITY_HOST`, the Azure instance metadata address `169.254.169.254`, or the `IDENTITY_ENDPOINT` your host injects. The token is for `cognitiveservices.azure.com`. | Only with `AZURE_OPENAI_AUTH=entra`, at the first model call and shortly before the token expires. | A token request. No prompts or code. |
| `bedrock-aws-credentials` | `bedrock-runtime.<region>.amazonaws.com` or `BEDROCK_BASE_URL`; `sts.<region>.amazonaws.com` and the AWS SSO endpoints, depending on your credential source; `169.254.169.254` (EC2 instance metadata); `169.254.170.2` or the `AWS_CONTAINER_CREDENTIALS_FULL_URI` host (container task role). | Only with `ZERO_SELECTED_PROVIDER=bedrock`, at the first model call and again before credentials expire. | A credential request and the model requests. No other code or files. `ZERO_ENTERPRISE` does not block them, because the AWS SDK makes them and you chose the account. Use a LiteLLM gateway to keep AWS credentials out of 0. |
| `provider-sign-in` | The provider you sign in to with OAuth or a subscription | Only when you choose that sign-in. | The OAuth exchange and that provider's model requests. |
| `provider-health` | The API of a provider you connected | The console shows connection status. | A key-validation or usage GET. |

To keep model traffic in your network, point the provider at an in-network gateway and use an API key. `ZERO_ENTERPRISE` does not choose the endpoint for you and does not block it.

## Chosen by you

These are not blocked, because you name the destination, except where a row says `ZERO_ENTERPRISE` refuses it. Leave them unused to keep the set closed.

| Entry | Destination | When | What is sent |
| --- | --- | --- | --- |
| `team-sign-in` | The OIDC issuer you configured | Team sign-in on a server you run. | OIDC discovery and token exchange. |
| `remote-engines` | Engine URLs you configured | The console or CLI talks to an engine on another computer. | Console API requests with a bearer token. |
| `mcp-remote-server` | Remote MCP servers you added | An installed extension with an http or sse transport runs. | MCP requests and tool arguments. |
| `scan-and-probe-targets` | The git remote or URL on the command line | `0security scan` with a git URL, `0security probe`, authorized proof-of-concept steps. | A git clone, or HTTP requests to that target. `0security probe` sends to a public host only with `--i-own-this <host>`, never to link-local or cloud metadata addresses, and follows no redirect to another origin. `ZERO_ENTERPRISE` leaves it on, because you name the target. See [Probe a live endpoint](/commands/#probe). |
| `nuclei-target-scan` | The URL you pass with `--target-url` | `0security scan --scanner nuclei --target-url`, with a scope file or the typed host. 0 starts Nuclei, which you installed; Nuclei sends the requests. | HTTP requests from Nuclei to that one target, at 10 requests per second by default, from http templates only, with no redirect followed, without intrusive, dos or fuzz templates and without out-of-band callbacks. A public host needs `--acknowledge-host` with the exact host. Link-local and cloud metadata addresses are always refused. `ZERO_ENTERPRISE` refuses every target that is not loopback. |
| `audit-siem-sink` | The https collector or syslog-over-TLS host you set in `ZERO_AUDIT_SINK_URL` | Server mode, only when you set that variable. Off by default. | Audit events: action, actor, subject, outcome and redacted detail. Plain http and plain TCP syslog are refused except to this machine, and UDP is refused. `ZERO_ENTERPRISE` leaves it on, because the collector is yours. See [Send the audit log to a SIEM](/server-mode/#send-the-audit-log-to-a-siem). |
| `redteam-decoy-alert` | The https URL you set with `--alert-url` | `0security redteam honeypot --decoy --alert-url ...`, once per call an agent makes to a decoy tool. Off unless you pass the URL. | The time, the decoy tool name, its privilege class, the call number, the arguments the agent passed (each cut to 300 characters) and one line of text. Plain http is refused except to this machine, and no redirect is followed. `ZERO_ENTERPRISE` leaves it on, because the URL is yours. See [redteam](/commands/#redteam). |
| `redteam-brain` | The https URL you set with `ZERO_BRAIN_URL` or `--url`; never a default | `0security redteam generate`, only when a URL is set and you are not offline. | The shape of the agent: tool names, a coarse privilege and gate for each, kinds of input source, and optionally a framework name and a count. A bearer token goes in the Authorization header only. Never source code, paths, prompts, secrets or findings. `--dry-run` prints the exact request. No redirect is followed. `ZERO_ENTERPRISE` blocks it. See [redteam generate](/commands/#redteam-generate). |
| `redteam-attack-model` | The OpenAI-compatible endpoint you set with `--attacker-url` or `OPENAI_BASE_URL` (default api.openai.com): your own model | `0security redteam attack` with `--attacker adaptive`, `refine` or `tree`. | The attacker prompt: the objective, a harmless marker, the clipped conversation with your agent and the names of the tools it called. Your key goes in the Authorization header only. https only (plain http to this machine). No redirect is followed. `--attacker crescendo` and `manyshot` send nothing. See [redteam attack](/commands/#redteam-attack). |
| `redteam-attack-brain` | The https URL you set with `ZERO_BRAIN_URL`; never a default | `0security redteam attack` with `--attacker brain`, only when the URL is set and you are not offline. | The objective and, each turn, the clipped conversation and the recorded calls from the fake environment. A bearer token goes in the Authorization header only. No redirect is followed. `ZERO_ENTERPRISE` blocks it. See [redteam attack](/commands/#redteam-attack). |
| `source-control-writes` | The git remote and GitHub host of your repository | `0security findings fix`, threat-model publishing, findings import, sentinel reviews, and Sentinel release, check and pull request triggers with `report` or `results` turned on. | The branch push, comment, commit status or code scanning upload (SARIF) you asked for. The upload holds severity, title, category and file location only. Sentinel triggers also read releases, tags, check runs and open pull requests through `gh`. `ZERO_ENTERPRISE` refuses every `gh` call. |
| `fix-sandbox-docker` | The registry of the image you name, pulled by the Docker daemon. With `--sandbox-network` or `--sandbox-setup`, whatever the build downloads. | `0security findings fix --sandbox docker`. The container has no network unless you pass `--sandbox-network` or `--sandbox-setup`, which `ZERO_ENTERPRISE` refuses. | Nothing from 0. |
| `bitbucket-code-insights` | `api.bitbucket.org`, or the Bitbucket Data Center URL you pass | `0security findings upload --to bitbucket-cloud` or `--to bitbucket-dc` with `BITBUCKET_TOKEN` set. | A Code Insights report and annotations from the scan's findings. A plain `http://` URL is refused unless the host is this machine or you pass `--allow-insecure-http`. |
| `jira-issues` | The Jira Cloud site or Jira Data Center URL you pass (`--url` or `JIRA_URL`) | `0security findings upload --to jira-cloud` or `--to jira-dc` with `JIRA_TOKEN` set. `--dry-run` sends nothing. | A label search and one issue per open finding: title, severity, location, description, impact, fix advice and finding id. The token goes only in the Authorization header. A plain `http://` URL is refused unless the host is this machine or you pass `--allow-insecure-http`. `ZERO_ENTERPRISE` blocks it. |
| `bitbucket-pr-review` | `api.bitbucket.org`, or the Bitbucket Data Center URL you pass, and the git remote of the clone you name | `0security sentinels bitbucket review` or `watch` with `BITBUCKET_TOKEN` set, or an enabled `bitbucket-pr` Sentinel trigger whose token variable is set. | Reads of pull requests, diffs and comments. Comments and a Code Insights report. The scan fetches the pull request's commit from the clone's remote. `ZERO_ENTERPRISE` blocks it unless `ZERO_BITBUCKET_URL` explicitly approves the exact origin and context path; restricted git must use direct HTTPS. |
| `bitbucket-fix-pr` | `api.bitbucket.org` for Cloud REST, `bitbucket.org` for Cloud git, or the configured Data Center origin and context path | Explicit fix PR creation and updates. | The fix branch, PR text, draft state and reviewers; reads of PRs, commits and build status. REST uses the Bitbucket token; git uses its own credentials. `--no-pr` avoids publishing. `ZERO_ENTERPRISE` blocks both transports unless `ZERO_BITBUCKET_URL` approves the actual destination; restricted git requires HTTPS and rejects URL rewrites or changed/differing push origins. |
| `code-host-fix-status` | GitHub through `gh`, `api.bitbucket.org`, or the configured Data Center origin and context path | Opening a finding's fix review (30-second cache), or explicitly refreshing run-metrics host observations (at most 20 PRs per invocation). | Repository, PR and commit identifiers with authentication, for status/lifecycle reads only. No source code, findings bodies or checkout paths are uploaded. `ZERO_ENTERPRISE` blocks GitHub; Bitbucket reads require the explicit `ZERO_BITBUCKET_URL` exception. |
| `ha-shared-database` | The PostgreSQL server you set in `ZERO_HA_DATABASE_URL` or `ZERO_HA_DATABASE_URL_FILE` | Server mode with the high availability license feature, only when you set one of those variables. Off by default. | Server sign-in sessions (hashed keys, account IDs, roles, expiry times), queued jobs (kind, JSON payload, status, lease owner and times, last error text) the scheduler election (one advisory lock on one held connection, retried every few seconds), a readiness check that reads the schema version every 2 seconds, and the schema version, over a connection to your database. A database on another machine needs TLS. `ZERO_ENTERPRISE` leaves it on, because the database is yours. |
| `findings-server-upload` | The https URL of your own shared findings server, named with `--to` | `0security findings upload <file> --to https://...` with `ZERO_FINDINGS_API_KEY` set. | The SARIF or findings JSON file you name, with repository, source, commit and ref labels, and the key as a bearer token. A plain `http://` URL is refused unless the host is this machine or you pass `--allow-insecure-http`. `ZERO_ENTERPRISE` leaves it on, because the server is yours. |

## Local only

| Entry | Destination | What happens |
| --- | --- | --- |
| `dashboard-dev-proxy` | Loopback, or the browser page's own server | Nothing leaves the computer. |
| `local-socket` | A local unix socket | Nothing leaves the computer. |
| `no-network-matches` | None | Source text that classifies git commands or parses PR URLs and repository origins into local identities. These modules make no network request. |

The enterprise license check makes no network call. It verifies a signed key on your computer with the local clock. Nothing is registered, reported or looked up, so it needs no entry in the inventory.

## Keeping this page honest

The inventory lives in `scripts/egress-inventory.json`. `pnpm check:egress-inventory` fails when a source file under `packages/engine/src` or `packages/cli/src` makes an outbound call that the inventory does not list, when a listed file stops matching, when a new `https://` host appears in code that is not reviewed, and when this page does not mention an entry or one of its hosts. When you add a call site, add it to the inventory, document it here, and decide how `ZERO_ENTERPRISE` treats it.

## Defaults

The defaults of an ordinary install did not change: usage metrics stay on at the `usage` level in release builds, and the update check stays on for interactive terminals. The Helm chart and the AWS reference set `ZERO_ENTERPRISE` and `DO_NOT_TRACK` for you. The Docker Compose files set neither, because pull request reviews need GitHub. Set them in `.env` for a no-egress install.
