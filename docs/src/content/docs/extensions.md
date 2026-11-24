---
title: Extensions
description: Connect 0 to your tools and services with reviewed, commit-pinned extensions.
---

An extension is a git folder pinned to one commit. It connects 0 to a service such as GitHub, starts MCP servers, or adds rules such as a verifier. Add, review and manage extensions from the CLI or the **Extensions** page.

An extension has no runtime of its own. Its MCP servers and scripts are ordinary commands under the same approvals and sandbox as anything the agent runs. An extension never updates on its own. Themes are not extensions. Read the [security model](/configuration/#security-model) before you add third-party code.

[Skills](/skills/) are instructions the model loads, and contain no code. An extension can bring a skill along. That skill appears on the Skills page with its source.

## Add one

```sh
0security skills add owner/repo@<full 40-character commit>
0security skills extensions add ./my-extension
0security skills extensions mcp docs --url https://example.com/mcp
0security skills extensions mcp docs -- npx some-mcp-server@1.2.3
```

Each command first shows a prompt with the repository at the full commit, the licence, the files, hidden-Unicode flags, and what the extension can do. That covers the service it connects to, the MCP servers it starts, the rules it adds, and any skills it adds. Nothing installs without `--yes` from your own terminal, and a flag alone never approves. `--yes` is refused without a pinned commit.

In the browser app, **Add extension** on **Extensions** takes a git source. **Add MCP server** takes a command or an https URL and creates a local extension with the same prompt.

## Manage extensions

```sh
0security skills extensions list
0security skills extensions info <name>
0security skills extensions enable <name>
0security skills extensions disable <name>
0security skills extensions update <name>
0security skills extensions remove <name> --yes
```

An extension installs disabled. Enabling asks you to approve the exact revision once. `update` shows the folder diff and what the extension can now do, then asks again. Any change re-prompts, even one new script. Built-in extensions such as `github` update with the 0 binary.

`info` also shows each MCP server's tools with the approved and last-seen hash. See [MCP servers](#mcp-servers).

## Repo files are suggestions

A repository's `.0/` or `.claude/` folder (settings, `.mcp.json`, skills) never installs or enables an extension or MCP server. On first open, the app shows what the repo asks for, with the install prompt for each. If you ignore it, nothing runs. A plain `SKILL.md` is still read as instructions.

## MCP servers

In the browser app, open **Extensions**, press **Add**, then choose **MCP server**. Enter the command that starts it, or an https URL. It becomes a local extension with the same review as any other. Nothing runs until you read the exact command and approve it, and it is saved turned off. Once enabled, it starts only when a Thread first uses it, and its tools are pinned.

From the command line:

```sh
0security skills extensions mcp docs --url https://example.com/mcp
0security skills extensions mcp docs -- npx some-mcp-server@1.2.3        # shows the review; add --yes to approve it
0security skills extensions info docs
0security skills extensions enable docs
0security skills extensions remove docs --yes
```

Do not type secrets on the command line. An extension declares the variable names it needs, and the review lists them. Add `--format json` for JSON output.

The browser app and headless Threads also read a JSON array in `ZERO_MCP`. Local entries take `id`, `command` and optional `args`, `env` and `cwd`. Remote entries take `id`, `url` and optional `headers`. Local entries can also take `sandbox` (see [Sandbox your own MCP servers](#sandbox-your-own-mcp-servers)). 0 skips malformed entries and failed connections.

Tools appear as `mcp__<server-id>__<tool-name>`, and results are untrusted. Starting a stdio server runs its code as you, so give it only the credentials and files it needs.

### Servers bundled in an extension

An extension can bundle MCP servers, so one reviewed install covers them. Declare them in `extension.json` under `"0": { "mcp": { ... } }`, or ship a Claude-style `.mcp.json`. The shape is the same as `.mcp.json`:

- A `command` and `args` for a local server, or a `url` (with `"type": "http"` or `"sse"`) for a remote one.
- The names of environment variables the server needs, under `env`.
- An optional one-line `description`.

The extension never stores values. The install prompt lists every server, command, argument, URL and variable name, and changing any of them asks again.

Commands and network: starting a local server is a `process` command, and connecting to a URL is a `network` command. Both go through `beforeCommand` with your "Ask before running commands" setting, and a deny keeps the server from starting. Local servers run in the extension's folder with only their declared variable names plus a small base set. 0 does not pass model provider keys unless the server declares them and you approve.

Pinned tools: the first time a server connects, 0 asks you to approve its tools. It records a sha256 of each tool's name, description, input schema and annotations, and compares the hashes on every later connection. If any tool changes, appears or disappears, 0 blocks the whole server. Nothing from it is advertised or callable, and the Thread shows a line such as `changed: echo; blocked until you approve them again`. Approve again in the Thread, or review it on the Extensions page, which shows Changed, New and Removed. With no approval channel, the server stays blocked.

Pinned packages: a server started with `npx`, `bunx`, `pnpm dlx`, `npm exec`, `uvx`, `uv tool run`, `pipx run` or `pip install` downloads code on every start. Its arguments must pin an exact version: `pkg@1.2.3`, `pkg==1.2.3` or a full git commit. Otherwise 0 refuses it and says what to change. The install prompt lists what it fetches and from where.

Remote servers: HTTPS only. Plain `http` works only for `localhost`, `127.0.0.1` or `[::1]`. 0 resolves the host name before connecting and before each request, and refuses a name that points to a private, loopback, link-local or cloud-metadata address. It refuses redirects. 0 declares no sampling, elicitation or roots capability, so a server cannot ask the model or you for anything.

Secrets: a server receives a connector's stored token only for a variable name that its extension declared and you approved (the connector's `env`). The value comes from the connection store, never the model's environment, and 0 masks it if the server echoes it back. Commands that change approvals or connections refuse to run from inside a server or from any Thread.

## Sandboxing

A sandbox limits what an extension's scripts and MCP servers can touch at the operating system level. It is off for an extension until the extension declares a `sandbox` block, and you approve it in the install prompt.

Declare the block in `extension.json`, next to `connector` (or under `"0"` when you use that object):

```json
{
  "name": "docs-search",
  "version": "1.0.0",
  "sandbox": { "network": false, "process": false, "readPaths": ["data"], "writePaths": [] }
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `network` | `false` | Allow network connections. |
| `process` | `false` | Allow starting programs from the system folders. By default only interpreters (`sh`, `bash`, `zsh`, `python`, `python3`, `node`, `bun`) and the extension's own files can start. |
| `readPaths` | `[]` | Extra read-only paths, relative to the extension folder. `$WORKSPACE` adds the folder you run the extension in. |
| `writePaths` | `[]` | Extra writable paths, in the same form. |

An unknown key, an absolute path, `~` or `..` makes the manifest invalid. A path must exist inside the extension folder. A symlink that leaves the folder is refused.

Inside the sandbox a process can read the system, its own folder and the extension's declared paths. It can write only to a scratch folder (its `TMPDIR`) and to declared `writePaths`. It cannot read your home folder, `~/.0`, `~/.ssh`, `~/.aws`, other repositories or the scanned folder, and it has no network. The scratch folder is deleted when the run ends. Its working folder is the extension folder, or the workspace when `$WORKSPACE` is declared.

The block is part of what you approve. Adding network access, widening a path list or turning on `process` in a new revision asks again.

### Choose when it applies

Set `ZERO_SANDBOX` to `auto`, `require` or `off`:

```sh
env ZERO_SANDBOX=require 0
```

- `auto` is the default. A script or server of an extension with a `sandbox` block runs in the sandbox when this computer has one. Otherwise it runs as before and 0 says so. An extension without a block runs as before.
- `require` sandboxes every extension script and server. An extension without a block gets the defaults above, with no network. If no sandbox works on this computer, 0 refuses to run it.
- `off` never uses the sandbox.

Every script run starts its output with a line such as `[sandbox: applied (seatbelt, network off, ...)]` or `[sandbox: not applied (...)]`. A server's load result carries the same line. Run `0security doctor` to see what this computer offers.

When a sandboxed run fails because it needs something it did not declare, the error is the operating system's, for example `Operation not permitted`. Add the missing permission to the `sandbox` block, or set `ZERO_SANDBOX=off` to run without it.

### Node scripts and servers

When the program is `node` and it supports the permission model (Node 20 or later), 0 also starts it with `--permission`. The process can read its own folder, declared paths and scratch, and write scratch and declared `writePaths`. It can start child programs only with `process`, and never starts workers. This layer runs inside the operating system sandbox when there is one.

It is the only layer on Windows and on Linux hosts where bubblewrap cannot start, such as a container without user namespaces. Node cannot block the network, so this layer does not. In that case the status line says the network is not restricted. `require` still refuses to run without an operating system sandbox, unless the extension declares `network: true`.

Set `ZERO_SANDBOX_NODE_PERMISSION=off` to leave the flags out, for example for a program that loads a native addon.

Scripts started by `sh` or `python` get no Node layer. A Linux host without a working sandbox runs them unsandboxed, and 0 says so. Windows has no operating system backend.

Optional limits apply to sandboxed runs: `ZERO_SANDBOX_CPU_SECONDS` (macOS and Linux) and `ZERO_SANDBOX_MEMORY_MB` (Linux only; macOS does not enforce it). The timeout of the bash tool still applies.

### Sandbox your own MCP servers

Servers you configure in `ZERO_MCP` run as before. Add `"sandbox": true` to one to run it in the sandbox with the defaults, or a declaration with the fields above:

```json
[{ "id": "notes", "command": "node", "args": ["server.js"], "cwd": "/path/to/notes-server", "sandbox": true }]
```

A sandboxed entry needs `cwd`, which becomes its read-only folder. Paths in a declaration are relative to `cwd`. This setting applies whatever `ZERO_SANDBOX` says, and the server does not start if no sandbox works. A server that downloads packages at start, such as one run with `npx`, needs `network` and cannot write its package cache, so it does not fit.

### What the sandbox does not do

- It is not a container or a virtual machine. It does not hide the system, other users' public files or the kernel.
- On macOS it uses `sandbox-exec` (Seatbelt). Apple marks it deprecated. It works today, and a future macOS can remove it. Reads under your home folder are denied, including whether a file exists. Outside it, a process can see that a file exists but cannot read it.
- On Linux it uses `bwrap` (bubblewrap) and needs user namespaces. Without `process`, only the allowed program files are mounted, so nothing else can start. With `process`, the system program folders are mounted read-only, so any program there can start.
- On macOS, `process` allows programs from `/bin`, `/usr/bin`, `/usr/local` and `/opt/homebrew`. The macOS profile always lets a process read `/opt/homebrew` and `/usr/local`, because interpreters from Homebrew load libraries from there.
- Windows has no sandbox backend. `ZERO_SANDBOX=require` refuses to run extensions there.
- Network is all or nothing. 0 does not filter by host.
- The sandbox does not stop a script from misusing what you declared: a script with network access can send out anything it can read.
- The sandbox covers the scripts an extension ships and the MCP servers it declares. It does not cover commands the model writes itself.
- Tested: macOS Seatbelt (reads, writes, program starts and loopback network, with `curl` and `node`) and Linux bubblewrap inside a privileged Linux container. Not tested: other Linux distributions, kernels with user namespaces disabled, and Windows.

## Connect a service

A connection links 0 to a service such as GitHub. Connections belong to extensions. GitHub is built in, and other services come as connector extensions you install.

### Connect GitHub

1. Run `0security` and open **Extensions**. GitHub is the first row.
2. Press **Connect** and pick one way:
   - **Sign in with GitHub** shows a one-time code to enter at github.com/login/device.
   - **Use a token** links to GitHub's token page with the permissions pull requests need. Paste the token.

GitHub cannot be removed, because pull request Sentinels use it. Turning it off pauses them and asks you to confirm.

GitHub stores the credential in `gh`'s own store. 0 never reads it, and no script receives it. The card lists what the connection can do: read pull requests, pull request diffs, repository contents and the repository list, and write comments on pull requests.

### Connect another service

Install the connector extension with `0security skills add <source>` or **Add** in the browser app. The install prompt shows the connector's declared read and write list, the hosts it can reach and the variable its token fills. After you approve, its card appears on **Extensions** with one **Connect** button.

Paste the token. If the connector declares a health URL, 0 checks the token against it. 0 stores the token on this computer in `~/.0/extensions/connections.json`, readable only by you. **Disconnect** deletes it.

A script in the extension receives the token only if the extension declared that variable name and you approved the prompt. When the bash tool runs a command that names a file inside an enabled extension's folder, 0 adds the declared and approved variables, the stored token included, to the command's environment and masks the value in the output. An extension whose approval does not cover a variable it declares does not run. Its MCP servers get the token the same way. Model provider keys and every other secret stay out. The script's environment is built from scratch: a short list of basics (`PATH`, `HOME`, `USER`, `SHELL`, locale and `TERM`, `TMPDIR`, `TZ`) plus the approved variables. It does not get the bash tool's environment, the scan target, or target-auth variables such as `TARGET` and `AUTH_HEADER`, so a script that needs one must declare it and be approved.

### Connector reference

The `connector` block of an extension manifest (`extension.json`, or the `"0"` object of `plugin.json`):

| Field | Meaning |
| --- | --- |
| `service` | Short lower-case id, such as `github` or `chat`. |
| `title`, `description`, `category` | Shown on the card. `title` defaults to `service`. |
| `auth` | The default way to connect: `token`, `oauth-device` (one-time code), `cli-login` (a program already signed in, such as `gh`) or `none`. `cli` is accepted as `cli-login`. |
| `methods` | Every way to connect. The first is preselected. Defaults to `[auth]` and must include `auth`. |
| `env` | Variable names the connection fills for the extension's scripts, for example `["CHAT_TOKEN"]`. A `token` connector must declare one. The name must be an allowed credential name (upper case, ending `_TOKEN`, `_KEY` and similar). Loader variables are never allowed. |
| `hosts` | Hosts it can reach. A health URL must be https on one of them. |
| `access.read`, `access.write` | What it can read and write, in plain words. Shown in the install prompt and on the card. Changing them asks again. |
| `health` | `{"type": "none"}` (default), `{"type": "adapter"}` (ask the sign-in adapter, as GitHub does) or `{"type": "http", "url": "https://..."}` (GET with the token as a bearer token; 401 or 403 means rejected). |
| `connectLabel` | Text of the Connect button. Defaults to `Connect`. |

Example:

```json
{
  "name": "chat-notify",
  "version": "1.0.0",
  "connector": {
    "service": "chat",
    "title": "Chat",
    "auth": "token",
    "env": ["CHAT_NOTIFY_TOKEN"],
    "hosts": ["chat.example.com"],
    "access": { "read": ["channels"], "write": ["messages"] },
    "health": { "type": "http", "url": "https://chat.example.com/api/auth.test" }
  }
}
```

A `scripts/notify.sh` in the same folder reads `$CHAT_NOTIFY_TOKEN`. Scripts run through bash under the usual approvals and sandbox.
