---
title: Data flow and no-egress mode
description: Every outbound network destination of 0, when it is used, what is sent, and how to turn it off. One switch, ZERO_ENTERPRISE, keeps everything off except the model endpoint you configure.
---

This page lists every place 0 can send data off the computer it runs on. It exists so a security team can check the claim "nothing leaves the network except the model endpoint we configured" instead of taking it on trust.

## What leaves your machine

Your code stays on your machine. 0 sends what you choose to your model provider. By default it also sends anonymous usage counts, and it checks GitHub for updates. `ZERO_OFFLINE=1` turns both off, along with crash reports and the public model and price lookups. `ZERO_NO_TELEMETRY=1` (or `DO_NOT_TRACK=1`) stops the counts and crash reports, and `ZERO_NO_UPDATE_CHECK=1` stops the update check. `ZERO_ENTERPRISE=1` is the strict mode below.

## No-egress mode

Set one environment variable on every computer or container that runs 0:

```bash
export ZERO_ENTERPRISE=1
```

Any value except empty, `0`, `false` or `no` turns it on. With it on, 0:

- sends no usage metrics, crash reports, feedback or run contributions, and never loads cloud credentials;
- makes no update check and refuses `0security doctor upgrade`;
- skips the public model catalog and price lookups, so models without a built-in price show no cost;
- removes the `web_search` tool and refuses the advisory lookup, remote extension sources, the sandbox runtime download, GitHub repository and skills directory reads, SARIF upload through `gh`, and remote worker provisioning;
- still talks to the model endpoint you configured, and to the destinations in the "Chosen by you" table, because you named them.

It is read from the process environment only. A project file such as `<project>/.0/tui-settings.json` cannot set or clear it, so a repository you open cannot switch egress back on. It also counts as an opt-out for every gate that already honors `ZERO_OFFLINE`, `ZERO_NO_TELEMETRY` or `DO_NOT_TRACK`, so those gates cannot drift apart from it.

The switch is off by default. An ordinary install keeps its current behavior. For a container, set it in the container environment; for a managed laptop, set it in the shell profile or the device policy.

Nothing is sent when the switch is on, so `~/.0/analytics-sent.log`, which records every analytics payload that does leave, stays empty.

## Verify it yourself

The repository tests this in the engine and CLI test suites. Each test starts a local stub model server, turns on the switch, runs the call sites that the switch blocks, and patches `fetch`, `node:http`, `node:https`, sockets and the `gh`, `curl`, `git` and `ssh` launchers to record every attempt. It fails when anything other than the stub is contacted. A control case runs the same lookups with the switch off and checks that the recorder sees them, so a silent recorder cannot pass. A second check fails when a source file adds an outbound call that is not in the inventory below.

For a stronger guarantee than a test, also block egress at the network: run 0 in a container or network namespace whose only route is your model gateway, then run a scan with `ZERO_ENTERPRISE=1`. The switch gives you the same result without relying on the block, and the block catches a mistake the switch could not.

## Blocked by `ZERO_ENTERPRISE`

| Entry | Destination | When | What is sent | How to disable without the switch |
| --- | --- | --- | --- | --- |
| `usage-analytics-posthog` | `eu.i.posthog.com` | Batched while a command or the console runs, at the `usage` level, in a release build. | Anonymous counters. The field list is under [Usage metrics](/configuration/#usage-metrics). | `analyticsLevel off`, `ZERO_NO_TELEMETRY`, `DO_NOT_TRACK`, `ZERO_OFFLINE`. |
| `usage-analytics-cloud` | `cloud.0.security` | Only with a cloud token. | The same usage events. | The same switches. |
| `run-contribution` | `cloud.0.security` | Only with a cloud token and a contribution permission. | A sealed run capture. | The same switches. |
| `crash-and-feedback` | Sentry (embedded project or `ZERO_SENTRY_DSN`), the feedback endpoint | A crash with `diagnosticReporting automatic`, or feedback you send. | A redacted crash envelope or the feedback text you reviewed. | `diagnosticReporting off`, the same switches. |
| `update-check` | `api.github.com`, `github.com`, `raw.githubusercontent.com` | Interactive start-up, console update status, `0security doctor upgrade`. | A GET for the latest release tag; the installer on upgrade. | `updatePolicy off`, `ZERO_NO_UPDATE_CHECK`, `ZERO_OFFLINE`. |
| `model-catalog-sync` | `models.dev` | Console model picker refresh. | A GET of a public list. | `ZERO_NO_TELEMETRY`, `DO_NOT_TRACK`, `ZERO_OFFLINE`. |
| `pricing-discovery` | `openrouter.ai` | A model has no built-in price. | A GET of a public list. | The same. |
| `web-search-tool` | `mcp.parallel.ai`, `html.duckduckgo.com`, `api.keenable.ai` | The agent calls `web_search`. `api.keenable.ai` replaces `mcp.parallel.ai` only when `ZERO_WEB_SEARCH_PROVIDER=keenable`. | The search query the model wrote, and `KEENABLE_API_KEY` if you set it. | `ZERO_FEATURE_WEB_SEARCH=0`. |
| `osv-advisory-lookup` | `api.osv.dev` | `0security sbom check` and evidence bundles with advisories. | Package URLs from the SBOM. | Skip the check. |
| `sbom-outdated-lookup` | `api.deps.dev` | `0security sbom check --outdated`. | Package names from the SBOM (at most 200). | Do not pass the flag. |
| `sbom-licenses-resolve` | `api.deps.dev` | `0security sbom licenses --resolve`. | Package names and versions of components with no stated license. | Do not pass the flag. |
| `sbom-resolve-build-tools` | The repositories the project's build files name (Maven Central by default) | `0security sbom generate --resolve`, after you confirm. | Whatever the project's own `mvn` or `gradle` sends. It also runs the project's build scripts. | Do not pass the flag. |
| `extension-git-source` | `github.com` or the https git host you give | Installing or updating an extension from a remote source. | A shallow fetch of one pinned commit. | Install from a local folder. |
| `extension-connector-health` | Hosts an installed connector declares | The console shows connector status. | A GET carrying the connector token. | Do not install connectors. |
| `smolvm-provision` | `github.com` | Explicit setup of the macOS sandbox runtime. | A GET of a pinned archive, checked against a fixed hash. | Preinstall the runtime. |
| `skills-catalog` | `api.github.com` | Previewing or installing from the console skills directory. | Read-only API calls through your `gh` login. | Do not use the directory. |
| `github-repository-list` | `api.github.com` | The console repository picker and GitHub account status. | Read-only API calls through your `gh` login. | Use local paths. |
| `github-gh-commands` | GitHub, through `gh` | `0security findings upload` and host integrations. | The request you asked for. | Do not run them. |
| `windows-evidence-worker` | The base URL in a cloud-issued grant | A cloud Windows evidence job. | A bounded evidence envelope. | Do not accept cloud jobs. |
| `remote-worker-provisioning` | `nodejs.org`, apt and npm registries, from the remote computer | `0security computers add`. | Package downloads. | Prepare the remote computer yourself. |

## Your model endpoint

| Entry | Destination | When | What is sent |
| --- | --- | --- | --- |
| `llm-model-endpoint` | The provider base URL or gateway you configured | Every model call and model-list discovery. | Prompts, tool results and code excerpts the model needs. |
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
| `scan-and-probe-targets` | The git remote or URL on the command line | `0security scan` with a git URL, `0security probe`, authorized proof-of-concept steps. | A git clone, or HTTP requests to that target. |
| `source-control-writes` | The git remote and GitHub host of your repository | `0security findings fix`, threat-model publishing, findings import, sentinel reviews. | The branch push or comment you asked for. |
| `audit-siem-sink` | The https collector or syslog-over-TLS host you set in `ZERO_AUDIT_SINK_URL` | Server mode, only when you set that variable. Off by default. | Audit events: action, actor, subject, outcome and redacted detail. Plain http and plain TCP syslog are refused except to this machine, and UDP is refused. `ZERO_ENTERPRISE` leaves it on, because the collector is yours. See [Send the audit log to a SIEM](/server-mode/#send-the-audit-log-to-a-siem). |
| `source-control-writes` | The git remote and GitHub host of your repository | `0security findings fix`, threat-model publishing, findings import, sentinel reviews, and Sentinel release and check triggers with `report` turned on. | The branch push, comment or commit status you asked for. Sentinel triggers also read releases, tags and check runs through `gh`. |
| `fix-sandbox-docker` | The registry of the image you name, pulled by the Docker daemon. With `--sandbox-network`, whatever the build downloads. | `0security findings fix --sandbox docker`. The container has no network unless you pass `--sandbox-network`, which `ZERO_ENTERPRISE` refuses. | Nothing from 0. |
| `bitbucket-code-insights` | `api.bitbucket.org`, or the Bitbucket Data Center URL you pass | `0security findings upload --to bitbucket-cloud` or `--to bitbucket-dc` with `BITBUCKET_TOKEN` set. | A Code Insights report and annotations from the scan's findings. A plain `http://` URL is refused unless the host is this machine or you pass `--allow-insecure-http`. |
| `bitbucket-pr-review` | `api.bitbucket.org`, or the Bitbucket Data Center URL you pass, and the git remote of the clone you name | `0security sentinels bitbucket review` or `watch` with `BITBUCKET_TOKEN` set. | Reads of pull requests, diffs and comments. Comments and a Code Insights report. The scan fetches the pull request's commit from the clone's remote. `ZERO_ENTERPRISE` refuses all of it. |

## Local only

| Entry | Destination | What happens |
| --- | --- | --- |
| `dashboard-dev-proxy` | Loopback, or the browser page's own server | Nothing leaves the computer. |
| `local-socket` | A local unix socket | Nothing leaves the computer. |
| `no-network-matches` | None | Source text that looks like a network call but is not one. |

The enterprise license check makes no network call. It verifies a signed key on your computer with the local clock. Nothing is registered, reported or looked up, so it needs no entry in the inventory.

## Keeping this page honest

The inventory lives in `scripts/egress-inventory.json`. `pnpm check:egress-inventory` fails when a source file under `packages/engine/src` or `packages/cli/src` makes an outbound call that the inventory does not list, when a listed file stops matching, when a new `https://` host appears in code that is not reviewed, and when this page does not mention an entry or one of its hosts. When you add a call site, add it to the inventory, document it here, and decide how `ZERO_ENTERPRISE` treats it.

## Defaults

The defaults of an ordinary install did not change: usage metrics stay on at the `usage` level in release builds, and the update check stays on for interactive terminals. Whether the container image and install script should ship with `ZERO_ENTERPRISE` on, or with analytics off, is a product decision that this page does not make.
