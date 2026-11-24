---
title: Threads
description: Run a job in the browser app, from the terminal or headless.
---

A thread is a conversation with the agent. You describe a job in plain words, and the agent plans it, reads files, runs commands and records findings. Threads are saved, so you can resume or archive them.

## Start the app

```bash
0
```

`0security` starts the browser app on this computer and opens it. No account is needed. It binds to `127.0.0.1:48123`.

| Flag | Default | Effect |
| --- | --- | --- |
| `--port <port>` | `48123` | Port to bind. `0` picks a free loopback port. |
| `--host <host>` | `127.0.0.1` | Loopback address to bind. |
| `--no-open` | | Start without opening a browser. |
| `--db-path <path>` | local store | SQLite database for findings and runs. |
| `--ready-json` | | Print the bound URL as JSON, for scripts. |

Run `0security --help` for the full list.

## Run a thread

1. Press **New thread**.
2. Pick a folder if the job involves code.
3. Choose a model under the composer. If the list is empty, connect a provider first. See [Models](/models/).
4. Describe the job, for example "Review this repo for auth bypasses and verify anything you find".
5. Watch tool activity in the transcript. Findings land in **Findings**.

The sidebar holds **New thread** and your history, **Findings**, **Skills**, **Computers**, **Extensions** and your **Sentinels**. Press `?` outside a text field for the keyboard shortcuts.

In the composer you can attach images or text files, set a thinking effort for models that support it, and type slash commands.

A message you send while the agent works is queued and goes out when the response ends. **Send now** interrupts instead. **Stop response** stops the agent. If a model connection drops, the thread reconnects and continues from its last completed tool result.

### Slash commands

Type `/` for a menu. Each entry mirrors a CLI command, and anything that changes or deletes asks first.

| Slash command | CLI |
| --- | --- |
| `/threads start`, `/threads list`, `/threads export` | `0security threads start`, `0security threads list`, `0security threads list <id> --export` |
| `/findings list`, `/fix [finding-id]` | `0security findings list`, `0security threads start` |
| `/scan <folder>` | `0security scan <folder>`; in chat it scans in this thread instead of a new one |
| `/sentinels list`, `/sentinels create` | `0security sentinels list`, `0security sentinels set --create` |
| `/computers list`, `/models list`, `/skills list` | the same words after `0security` |
| `/config get`, `/doctor` | `0security config get`, `0security config doctor` |

Chat-only commands are `/help`, `/status`, `/tools`, `/explain [topic]`, `/feedback <message>`, `/shortcuts` and `/usage`.

### Approvals and instructions

A thread has shell access and runs commands as your user in the folder you chose. An optional sandbox limits it. One global setting, **Ask before running commands** under **Settings → Helpers**, puts each command or change to you first. It is off by default. See [Configuration](/configuration/#ask-before-running-commands).

The agent has a `web_search` tool. It uses Parallel's anonymous hosted search, with DuckDuckGo as a fallback, and needs no key. Results are links and snippets, not proof that a page was read in full. Set `ZERO_FEATURE_WEB_SEARCH=0` to turn it off by default.

0 never loads `AGENTS.md` or `CLAUDE.md` files from inside a target repository, because whoever wrote the target controls that text. Put your own instructions under **Settings → Instructions**: a global `~/.0/AGENTS.md` and one file per folder, each up to 32,000 characters.

### Saved threads

A saved thread opens read-only at `/chats/saved/<id>`, with its transcript and panels. It resumes when you send a message.

Search with ⌘K. It matches message text and titles, and skips tool payloads and private reasoning.

**Settings → Threads** sets title instructions, idle archiving (off, 7, 14, 30 or 90 days) and the helper limits:

- concurrent helpers: 1-128, default 32
- nesting depth: 1-16, default 8
- helpers per call: 1-4096, default 1024

## Control threads from the terminal

`0security threads` works on the app that `0security` started:

```bash
id=$(0security threads start "Map the login flow" --folder ~/code/app)
0security threads list "$id" --set --effort high
0security threads stop "$id"
0security threads send "$id" --retry
0security threads list "$id" --rename "Login flow"
0security threads list "$id" --export --format md -o login-flow.md
0security threads list "$id" --delete --yes
```

`threads start` creates the thread, runs one turn and prints the thread ID. Add `--force` to `stop` if owned execution does not drain.

Add `--wait` to block until the turn ends. It prints only the reply on stdout and the thread ID, tokens and cost on stderr. It exits 1 if the turn errored. `threads send <id> ... --wait` and `threads show <id> --wait` work the same way on an existing thread.

Every `0security threads` command needs a running app. Without one it prints `No console running. Start one with: 0 --headless` and exits non-zero.

## Run a prompt headless

`0security -p` runs one prompt through the same app process and exits.

```bash
0security -p "Review the selected folder"
0security -p "Summarize the open findings" --format json
printf '%s' 'Summarize the selected findings' | 0security -p
```

| Option | Effect |
| --- | --- |
| `--format <text\|json\|ndjson>` | Output format. Default `text`. |
| `-m, --model <id>` | Model to use. |
| `--approvals <ask\|auto>` | With `ask`, each command is put to you first. A headless run cannot answer, so effectful tools are refused. Default `auto`, or your `approvals` setting. |
| `--finding <id>`, `--finding-intent <intent>` | Focus on one saved finding: `investigate`, `verify`, `draft_fix` or `impact`. |
| `--resume <id>`, `--continue` | Continue a saved thread by ID or prefix, or the most recent one (`0security -r <id>`, `0security -c`). |

A task that needs a human decision cannot finish headless. Open it in the browser. To continue a live thread, pass `--chat <id>`. The thread keeps its own model, so `--model` is rejected, and pending decisions are reported, not approved.

On a server or in CI, start the app without a browser:

```bash
0security --headless --ready-json
```

This serves the API only. To drive a running app from scripts, use `0security api`. It calls the backend HTTP API with the normal authentication and approval checks. Keep the token in an environment variable, for example `--engine-token-env ZERO_AGENT_TOKEN`, never on the command line.

## Commands, skills and Sentinels

- The CLI commands (`findings`, `threads`, `sentinels`, `skills`, `models`, `computers`, `config`) are built into 0. They are not skills. The `/` commands in a thread are a shorter list that mirrors them, and a few exist only in chat.
- A skill is know-how a thread loads when a task needs it: a `SKILL.md` folder, which extensions can also supply. See [Skills](/skills/).
- A Sentinel is a standing thread that wakes on a schedule or a pull request. See [Sentinels](/sentinels/).
- A skill can declare a check that the engine runs itself, so a thread cannot claim Verified without it. See [Findings](/findings/#verified-and-not-verified).

## Limits

- Tools run on the host of the computer you use. Your model endpoint can still be remote.
- A provider connection does not authorize a target.
- A source build serves the app from built assets. Rebuild after you change source.

## Next

- [Models](/models/): connect a provider and pick models per role.
- [Findings](/findings/): triage what a thread found.
- [Computers](/computers/): run threads on another machine.
