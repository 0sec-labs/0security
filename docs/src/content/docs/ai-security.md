---
title: AI security
description: Find the AI in your code, check model files and agent configuration, review LLM apps and MCP servers, and probe a live model endpoint.
---

AI security covers the parts of a project that call models, run agents or give a model tools. You use seven commands and skills for it. Three need no model key and make no network request.

## Find the AI in a project

```bash
0security sbom generate . --ai -o sbom.cdx.json
```

This adds the AI in the folder to the CycloneDX SBOM: model files, hub references such as `from_pretrained`, hosted model ids with their provider, datasets, and MCP servers. Files are read as text and nothing is downloaded. A reference the patterns do not recognize is missed, so read the list as what was seen. `--ai` does not work with `--format spdx`.

## Check model files

```bash
0security sbom scan-models ./models
```

Pickle-based model files can run code when you load them. This command reads the bytes and lists imports that run code, such as `os.system` or `subprocess`. It loads nothing and needs no Python. It exits 1 when a file imports something dangerous.

"No dangerous imports found" is not a statement that a file is safe. Safetensors, GGUF, ONNX and TFLite are not pickle formats and are reported as such.

## Check agent configuration

```bash
0security sbom agent-config . --fail-on high
```

AI coding tools read rules, MCP and settings files from the repository. This command reads them as text and flags hidden characters, unpinned MCP launchers, secrets, broad permissions, hooks and insecure remote servers. It calls no model and makes no network request, so it works with `ZERO_ENTERPRISE` set. The rule list is under [Check agent files in a repository](/extensions/#check-agent-files-in-a-repository).

To run it on every pull request, see [Check agent files](/ci/#check-agent-files).

## Review an LLM app or an MCP server

Two bundled skills read source code. Pass one to a scan:

```bash
0security scan . --skill llm-app-review
0security scan . --skill mcp-server-review
```

`llm-app-review` maps where untrusted content reaches a model with tools, where model output is trusted as code or markup, secrets in prompts, retrieval that mixes tenants, tools with too much power and unbounded cost. `mcp-server-review` covers tool poisoning, over-broad permissions, unpinned launchers, missing authentication, command and path injection in tool handlers and secrets in configuration. A model does the review, so a result is a lead to check, not a proof.

Bundled skills for prompt injection, insecure output handling, excessive agency, RAG poisoning and stored system prompts guide a thread against a live LLM app. Use them only on systems you own or may test. See [Skills](/skills/).

## Probe a live model endpoint

```bash
0security probe https://chat.example.com/api \
  --i-own-this chat.example.com --format sarif -o probe.sarif
```

Probe sends ten attack messages to a chat endpoint and reports the ones whose reply shows the attack worked. Each message carries a unique canary, so a hit is a check on the reply. A public host is refused unless you type its name with `--i-own-this`. See [probe](/commands/#probe) for the attacks and options.

A miss does not show the endpoint is safe against other attacks.

## Find where an agent can be steered

```bash
0security scan . --skill agent-toxic-flow
```

This reads the source of an agent and lists its toxic flows: places where text an attacker can influence reaches a model that holds a powerful tool, with no approval or restriction in between. For each one it writes the path, what an attacker gets, and a scenario that can be replayed. A model does the reading, so a result is a lead to check, not a proof.

## Test whether an agent obeys poisoned text

```bash
0security redteam config --trace /tmp/redteam.jsonl > mcp.json
0security redteam judge --trace /tmp/redteam.jsonl --canary <canary from config>
```

`redteam` serves a fake MCP server whose data carries a poisoned instruction and records every tool call the agent makes. `judge` reads the recording and says whether the agent sent the canary out or called a forbidden tool. No model decides the result. `judge --format sarif` reports a hit as a finding with OWASP LLM Top 10 and MITRE ATLAS tags, and `redteam scenarios report.json` lists the scenarios the skill wrote so you can replay them. See [redteam](/commands/#redteam). Run the agent in a sandbox and only agents you may test.

## Run the test from one command

```bash
0security redteam run --agent "my-agent --mcp-config {mcp_config}" --runs 5 --unsafe-no-isolation
```

`redteam run` starts your agent several times with the honeypot as a tool server, judges each run from the recorded calls, and exits 1 if the agent obeyed. A run in which the agent never used the honeypot is reported as inconclusive. There is no isolation yet, so use a throwaway machine; see [redteam run](/commands/#redteam-run). To make scenarios from the shape of your agent, use `redteam generate`; it sends only tool names, a coarse privilege and gate for each, and kinds of input, and never code or secrets. See [redteam generate](/commands/#redteam-generate).

## Catch a steered agent while it runs

```bash
0security redteam honeypot --decoy --trace /var/log/agent-decoy.jsonl --alert-url https://hooks.example.com/services/abc
```

Give a running agent the decoy server as one more tool server, next to its real ones. The decoys are tools that nothing legitimate should call, such as a request for administrator credentials or a send to an outside address. If an agent calls one, an alert goes to the URL you named. This is deception: it catches an agent that has been steered into reaching for power it was not given, with very few false alarms, and nothing sits between the agent and its model or tools.

It does not prevent anything. An agent can be steered without ever calling a decoy, and an agent that has been steered may call decoys it was not aimed at. A decoy whose description is too tempting can also be called by an agent doing honest work, so treat the first alerts as a check on the decoys. Use it with testing and with limits on what the agent can do, not instead of them.

## What 0 does and does not do

0 reads code and configuration, runs the checks above and sends probe messages to an endpoint you name. It does not train or evaluate models, measure model bias or jailbreak resistance beyond the ten probes, or watch an app in production. It does not run model files or MCP servers to inspect them.

Import any SARIF output with `0security findings import` to keep the results in one list. See [Findings](/findings/).
