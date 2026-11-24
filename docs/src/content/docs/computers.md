---
title: Computers
description: Run 0 on a server or VM, connect to it from the browser or CLI, and keep work running on the machine that owns it.
---

A computer is a machine that runs 0 and owns its Threads, workspace paths and execution. Choose a computer to decide where work runs. It does not pick a model or copy a repository.

## Deploy a worker

`0security computers add` installs 0 on a Linux host, starts a computer, opens a tunnel and registers it.

```bash
0security computers list                       # registered computers
0security computers hosts                      # SSH hosts from ~/.ssh/config
0security computers add --ssh user@host        # any SSH host with key auth
0security computers add --lima zero-worker     # a Lima VM (default name zero-worker)
```

| Option | Meaning |
| --- | --- |
| `--ssh <user@host>` | SSH target. Uses BatchMode and key auth. |
| `--ssh-config <path>` | OpenSSH config file for the target. |
| `--lima <name>` | Lima instance. Default `zero-worker`. |
| `--target-git <url>` | HTTPS URL of a Git repository the worker clones into its workspace. Other schemes are refused. |
| `--engine-port <port>` | Port on the worker. Default is stable per host. |
| `--trust-new-host` | Trust and remember the SSH host key on first connect. Without it, 0 refuses an unknown host and tells you to check it with `ssh <host>`. |
| `--forward-provider-key` | Forward this machine's `OPENAI_API_KEY` to the worker. Use only on hosts you own. |
| `--engines-config <path>` | Registry file to update. |

Manage a deployed worker by its computer ID:

```bash
0security computers repair <id>   # reconnect the tunnel and restart the engine if needed
0security computers stop <id>     # stop the engine and tunnel; keeps remote files and registration
0security computers remove <id>   # forget the computer on this machine; remote files stay
```

The target must be Linux with `sudo`. The first deploy uses it to install Node 24 and a C compiler.

0 copies its own bundle to the worker, so it must find `dist/0.js` and `vendor/`. In a source checkout, run `pnpm run build:bundle` once. An installed binary has no such files, so set `ZERO_WORKER_ASSETS` to a folder that has them, or use the container image.

The browser app also deploys workers from its computer selector.

## Run a computer by hand

Install 0 on the server and give it its own model connection (see [Models](/models/)). Prepare its repositories and any VM or Docker prerequisites there.

Set a secret of 32 to 4096 non-whitespace characters in an environment variable on the server and on the machine that connects. This page uses `ZERO_REMOTE_ENGINE_TOKEN`, but any name works. It is separate from the browser control token. Then start a computer admitted to one repository:

```bash
0security --host 127.0.0.1 --port 48123 --no-open \
  --engine-token-env ZERO_REMOTE_ENGINE_TOKEN \
  --engine-workspace /srv/repos/app
```

| Server option | Meaning |
| --- | --- |
| `--engine-workspace <path>` | Authorize a source workspace on the computer. |
| `--engine-allow-apply` | Admit requests to apply an exact, approved fix candidate. |
| `--engine-time-cap <ms>` | Limit per automation run. Default `600000`. |
| `--engine-cost-cap <usd>` | Limit per automation run. Default `5`. |

These options need `--engine-token-env` or `--team-config`. Clients can ask for lower limits. They cannot raise them or replace the server's workspace, provider or model.

Keep the listener on loopback and reach it through an SSH tunnel:

```bash
ssh -N -L 48124:127.0.0.1:48123 user@server
```

HTTPS endpoints work too. Plain HTTP works only on loopback. The endpoint must speak the computer handshake and authenticated control API. A model provider URL does not qualify.

## Register the computer

Create `engines.json` in `~/.0/`, or pass another file with `--engines-config`:

```json
{
  "schemaVersion": 1,
  "engines": [
    {
      "id": "staging",
      "name": "Staging engine",
      "url": "http://127.0.0.1:48124",
      "bearerTokenEnv": "ZERO_REMOTE_ENGINE_TOKEN"
    }
  ]
}
```

The file holds the name of the environment variable, never the token. It allows up to 32 computers and 64 KiB. Add `expectedEngineId` to pin the computer's identity across restarts. Without it, the first identity accepted stays pinned while the connection service runs, and 0 rejects a different one.

Start the browser app with the registry, then pick the computer in the selector:

```bash
0 --engines-config /absolute/path/engines.json
```

Threads, workspaces and approvals belong to the computer you chose. `/srv/repos/app` resolves on the server, not on your laptop. If a computer is unreachable or incompatible, 0 does not fall back to local execution.

### Use your local Codex model on a remote thread

A browser Thread can run its tools on a remote computer while its model requests use your local ChatGPT Codex sign-in. Pick the remote host for execution and the local model source for that Thread. Provider tokens stay on your machine. Prompts, tool results and responses pass through a Thread-scoped relay, and they can contain remote workspace data.

If this machine is not signed in to ChatGPT, creating the Thread fails and says so. A computer added with `--forward-provider-key` can run Threads on its own `OPENAI_API_KEY` through the commands in [Continue the same work](#continue-the-same-work).

Only `chatgpt-codex` works, with the remote computer's host-local execution profile. Reconnect the relay after a computer or owner restart. CLI calls use the server's own provider.

## Use it from the CLI

Select a registered computer with `--engine`. The CLI never uses your laptop's provider, filesystem or database for a remote target, and it rejects `--workspace`, `--db-path` and `--model` on remote calls.

```bash
0security threads list --engine staging --engines-config /abs/engines.json --format json
```

To call a computer's API directly, use `0security api`:

```bash
0security api                                   # engine handshake
0security api <path> --method POST --data @body.json --engine-url http://127.0.0.1:48124 --engine-token-env ZERO_REMOTE_ENGINE_TOKEN
```

`--data` takes JSON or `@file`, up to 1 MB.

### Continue the same work

```bash
0security threads list --engine staging --format json
0security threads send <session-id> "Summarize the retained evidence" --engine staging
```

Sending attaches to a live Thread. It does not restore an archived one. The Thread keeps its model and permissions, and 0 rejects local overrides. A pending decision returns exit status 2 and stays pending in the browser.

## Work lifecycle

- The computer owns Thread state and results. Closing a browser tab or the tunnel disconnects the client but does not complete or cancel anything. Reconnect and read the snapshot.
- Cancel on the owning computer. Ctrl-C in the foreground CLI sends the request. Losing a proxy does not.
- An approval for one computer, Thread or request cannot authorize another.
- Keep the computer process running. There is no crash recovery or detached executor. Stopping the computer ends its in-process work. Saved records and files survive.
- A remote computer uses its own local or VM executors. A local computer cannot use an arbitrary remote executor.

## Next

[Sentinels](/sentinels/#automations), [Threads](/threads/), [Server mode and Docker](/server-mode/).
