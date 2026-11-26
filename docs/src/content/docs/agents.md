---
title: Use 0 from Claude Code or Codex
description: Drive 0 from another coding agent through its shell. There is no MCP server to install.
---

Another coding agent, such as Claude Code or Codex, can use 0 the way a person does: it runs `0security` in a shell and reads the output. 0 does not ship an MCP server for this. The CLI already does the job, it needs no setup, and it adds nothing to the agent's context until the agent runs it.

0 can still connect to MCP servers that other people publish. See [Extensions](/extensions/#mcp-servers).

## Run a scan

```bash
0security scan . --format json -o scan.json
```

Read `scan.json` for the findings. `--format sarif` writes SARIF for code scanning, and `--diff origin/main` scans only what a branch changed. Add `--fail-on high` to make the exit code say whether anything serious was found.

## Read and change findings

```bash
0security findings list --severity high --format json
0security findings show <id>
0security findings update <id> --status false-positive --reason "not reachable from outside"
```

`findings update` sets a status of `accepted`, `suppressed`, `open` or `false-positive`; a false positive needs `--reason`. Run `0security findings --help` for the rest, including `fix`, `verify` and `export`.

## Ask a question

```bash
0security -p "Review ./app for injection bugs"
```

Only the answer goes to standard output. Add `--format json` for a machine-readable result, or `--format ndjson` for events as they happen. `-c` continues the most recent thread and `-r <id>` a saved one.

## Run a longer job and wait for it

```bash
0security threads start "Map the login flow" --wait
0security threads list
0security threads show <id>
```

## Exit codes

For `scan`, an agent can rely on these:

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | A finding at or above `--fail-on`, or the scan failed. |
| 2 | Usage error: fix the command and run it again. |
| 3 | Not finished. The scan stopped at its budget or time limit, so the report is partial. Findings so far are kept, and `--resume` continues. |

See [the scan reference](/commands/#scan) for the details and `--allow-partial`. Any other command that fails with an error message, for example an unexpected failure, prints the message to standard error and exits 2. With `--json` or `--format json`, a failure is one line of `{"error": "..."}` on standard error instead of plain text.

## Tell the agent about it

Add a line to the agent's instructions, for example in `AGENTS.md` or `CLAUDE.md`:

```markdown
For security review, run `0security scan . --format json -o scan.json` and read the findings.
Use `0security findings list --format json` to see what is open. Run `0security --help` for more.
```

An agent that can run shell commands needs nothing else. Run it in a folder you trust: 0 runs its own tools under its own approvals and sandbox, and the other agent's permissions do not change that.

## When an MCP server would be needed

Some hosts, such as chat apps, cannot run shell commands. They can only call MCP tools, so they cannot use 0 this way. If that blocks you, [open an issue](https://github.com/0sec-labs/0security/issues) and say which host you use.
