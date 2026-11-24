# Surfaces: CLI, chat and platform

This note says which surface owns which job, so a feature lands in one place. It answers issue 517.

There are three surfaces. The CLI and CI are the engine and the open-source surface. A chat is a thread where a person talks to the agent about one scan or fix. The platform is the web console for what a conversation cannot do. Pull requests, code scanning and issues stay the way individual findings reach the people who fix them.

## What lives where

| Job | CLI and CI | Chat (a thread) | Platform |
| --- | --- | --- | --- |
| Run a scan, a diff scan, a policy check | Yes: `0security scan`, the Action | Start one with `/scan` | Not the place to start one |
| Import other tools' findings | Yes: `0security findings import`, `--known` | Ask about one finding | Not the place |
| Fix a finding and open a pull request | Yes: `0security findings fix` | Steer one fix | Not the place |
| Evidence, SBOM, reports | Yes | Ask for a different cut of one scan | Show them |
| Investigate one scan: why, is it real, what next | Prints the report | Yes | Link to the thread |
| Steer one scan: what to weigh, what to skip | Flags and `--context` | Yes | No |
| Deliver one finding to its owner | Upload to code scanning | No | No: pull requests, code scanning and issues do |
| Roll up findings across repositories | No | No | Yes |
| Trends over time | No | No | Yes |
| Ownership: who answers for a repository | No | No | Yes |
| Approvals: who may accept a risk or merge a fix | Records the decision it was given | No | Yes |
| Policy and tier management for an organisation | Reads an operator-owned file (`--tiers`, `--org-policy`) | No | Yes |
| Audit: who ran what, who approved it | Local logs | No | Yes |

## What is deliberately not on each surface

The CLI and CI do not hold state about an organisation. They read operator-owned files and the repository, and they write reports. They have no accounts, no dashboard and no memory of other repositories.

A chat does not own a rule. A conversation can explain a finding or change how one scan weighs the code, but an instruction given in chat does not become policy and does not apply to the next scan. Anything that should apply every time belongs in a file the operator owns or in the platform.

The platform does not run a scan on its own terms and does not become the only way to see a finding. It does not duplicate the pull request, code scanning or the issue tracker as a second inbox. It does not take decisions out of the CLI: a result you can get in CI stays available in CI.

## Rule for new features

1. Build it in the CLI first. If it is a scan, an import, a fix or a report, it is a command or an option with a documented output, so it works in CI and in a script.
2. Put it in chat only if it helps a person investigate or steer one scan or one fix. A chat feature reads what the CLI produced and talks to the agent; it does not hold the only copy of a result.
3. Put it in the platform only if a conversation cannot do it: roll-ups across repositories, trends, ownership, approvals, audit, and policy and tier management for an organisation.
4. A platform feature that changes how a scan runs does it through the same file or flag the CLI reads, so a local run and a platform run agree.

## Tiers as an example

The tier map decides how much a repository is scanned. Today it is an operator-owned file read by `0security scan --tiers`. That is the CLI-first form: it works in CI, and the file comes from the base branch, not from the change under review. A platform that manages tiers for an organisation would write and version that same file; it would not add a second source of truth.

The platform pages for policy, tier and ownership management are not built. This note is the direction, not a description of shipped behavior.
