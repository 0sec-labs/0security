# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub private vulnerability reporting:

<https://github.com/0sec-labs/0security/security/advisories/new>

For email reporting, contact **admin@0.security**. Do not open a public issue, pull request or discussion for a suspected vulnerability. Include the affected version (`0security --version`), what you observed, and the steps or proof of concept needed to reproduce it. If the report concerns the `0` engine, the CLI, the container image or the install script, it belongs here. Vulnerabilities in the companion scanner are best reported in its own repository (<https://github.com/0sec-labs/foxguard>); we will forward anything that lands here by mistake.

## What to expect

These are targets, not guarantees. We are a small team.

| Step | Target |
| --- | --- |
| Acknowledge your report | within 3 business days |
| Initial assessment and severity | within 10 business days |
| Fix or mitigation for confirmed high and critical issues | within 90 days, sooner where we can |

We will keep you informed as the report progresses, and we are glad to credit you in the advisory unless you prefer to stay anonymous. We ask that you give us a reasonable chance to ship a fix before you disclose publicly, and we will coordinate the disclosure date with you.

## What to include for execution-boundary reports

For reports about tool approval or the execution boundary, name the entrypoint (web console, CLI command, or 0verse), the autonomy mode, the executor or runtime, and any feature flags. Redact tokens, provider credentials, private target paths and sensitive artifacts from logs. A minimal synthetic reproducer is better than a production target or a live exploit. Do not include customer data or exploit material for systems you are not authorized to test.

## Extension and MCP server trust

Extensions and the MCP servers inside them run code as you on the engine host. The main guardrails are review and pinning. An extension can also declare an OS sandbox for its scripts and servers (see [Sandboxing](https://docs.0.security/extensions/#sandboxing)); without one, or with `ZERO_SANDBOX=off`, they are not isolated.

- Nothing runs on install. You read one prompt (the repository at the full commit, its files, and what it can run, connect to or call) and approve the exact revision from your own terminal or the browser, never from a command a thread ran.
- Git extensions are fetched without executing anything, pinned to a full commit SHA, installed disabled, and never update on their own. Any change asks again.
- An MCP server's tools are hashed per tool. A changed, new or removed tool blocks the whole server until you approve it again, and this is never auto-approved.
- These routes are browser-only (agent and engine-bearer callers are refused) and owner-only in team mode. A process gets a scrubbed environment plus only the variable names you approved.
- An approved extension or server can still read files it can reach, use the network and prompt-inject the agent through tool names, descriptions and output. MCP tool results are labelled as untrusted, fenced and capped.

Reports that bypass the review, pinning, caller, sandbox or secret-handling rules are in scope. Behaviour of an approved third-party extension is not a flaw in 0. See the [security model](https://docs.0.security/configuration/#security-model).

## Self-edit preview

`ZERO_SELF_EDIT=1` (off by default) lets the web console create a `self/*` git worktree and run a preview of an agent-edited copy of 0 on loopback ports, with an empty scratch home and an allow-listed environment.

- It is owner-only in team mode and unavailable to engine-bearer callers.
- A protected-path gate, evaluated by the live console and not the agent, fails closed. It rejects diffs touching authentication, approvals, session and credential storage, the self-edit code itself, dependencies and lockfiles, build config, CI and agent instructions.
- Apply is not implemented: nothing is promoted to the running console.
- Framing is limited to an exact loopback origin (`ZERO_PREVIEW_FRAME_ANCESTORS`, set by the launcher). Everything else stays `frame-ancestors 'none'`.

The preview backend is agent-edited code running as the same OS user. It is not a filesystem or network sandbox, so enable it only on a machine and account where that is acceptable. Escapes from the protected-path gate or the scratch home are in scope.

## Supported versions

Security fixes are made against the latest release. Older releases are not patched; upgrade to the latest release to receive fixes. The independent 0verse Python package does not share the CLI's release version; identify its checkout revision in a report. Self-hosted deployments should follow the upgrade steps in the [self-hosting guide](https://docs.0.security/self-hosting/#upgrades-and-rollbacks).

## Verifying what you run

Every release publishes SHA-256 checksums, a CycloneDX SBOM and GitHub build-provenance attestations for each asset. See [Verify a release](https://docs.0.security/self-hosting/#verify-a-release).

## Safe harbor

We will not pursue legal action against people who make a good-faith effort to follow this policy: test only against your own installations and accounts, avoid privacy violations and service disruption, do not access or modify other people's data, and report what you find promptly. This is a statement of intent and not a legal waiver. It does not authorize testing of systems we do not own or operate.
