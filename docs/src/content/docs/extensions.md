---
title: Extensions
description: Connect 0 to your tools and services with reviewed, commit-pinned extensions.
---

An extension is a git folder pinned to one commit. It connects 0 to a service such as GitHub, starts MCP servers, or adds rules such as a verifier. Add, review and manage extensions from the CLI or the **Extensions** page.

An extension has no runtime of its own. Its MCP servers and scripts are ordinary commands under the same approvals and sandbox as anything the agent runs. An extension never updates on its own. Themes are not extensions. Read the [security model](/configuration/#security-model) before you add third-party code.

[Skills](/skills/) are instructions the model loads, and contain no code. An extension can bring a skill along. That skill appears on the Skills page with its source.

## Add one

```sh
0 skills add owner/repo@<full 40-character commit>
0 skills extensions add ./my-extension
0 skills extensions mcp docs --url https://example.com/mcp
0 skills extensions mcp docs -- npx some-mcp-server@1.2.3
```

Each command first shows a prompt with the repository at the full commit, the licence, the files, hidden-Unicode flags, and what the extension can do. That covers the service it connects to, the MCP servers it starts, the rules it adds, and any skills it adds. Nothing installs without `--yes` from your own terminal, and a flag alone never approves. `--yes` is refused without a pinned commit.

In the browser app, **Add extension** on **Extensions** takes a git source. **Add MCP server** takes a command or an https URL and creates a local extension with the same prompt.

## Manage extensions

```sh
0 skills extensions list
0 skills extensions info <name>
0 skills extensions enable <name>
0 skills extensions disable <name>
0 skills extensions update <name>
0 skills extensions remove <name> --yes
```

An extension installs disabled. Enabling asks you to approve the exact revision once. `update` shows the folder diff and what the extension can now do, then asks again. Any change re-prompts, even one new script. Built-in extensions such as `github` update with the 0 binary.

`info` also shows each MCP server's tools with the approved and last-seen hash. See [MCP servers](#mcp-servers).

## Repo files are suggestions

A repository's `.0/` or `.claude/` folder (settings, `.mcp.json`, skills) never installs or enables an extension or MCP server. On first open, the app shows what the repo asks for, with the install prompt for each. If you ignore it, nothing runs. A plain `SKILL.md` is still read as instructions.

## MCP servers

In the browser app, open **Extensions**, press **Add**, then choose **MCP server**. Enter the command that starts it, or an https URL. It becomes a local extension with the same review as any other. Nothing runs until you read the exact command and approve it, and it is saved turned off. Once enabled, it starts only when a Thread first uses it, and its tools are pinned.

From the command line:

```sh
0 skills extensions mcp docs --url https://example.com/mcp
0 skills extensions mcp docs -- npx some-mcp-server@1.2.3        # shows the review; add --yes to approve it
0 skills extensions info docs
0 skills extensions enable docs
0 skills extensions remove docs --yes
```

Do not type secrets on the command line. An extension declares the variable names it needs, and the review lists them. Add `--format json` for JSON output.

The browser app and headless Threads also read a JSON array in `ZERO_MCP`. Local entries take `id`, `command` and optional `args`, `env` and `cwd`. Remote entries take `id`, `url` and optional `headers`. 0 skips malformed entries and failed connections.

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

## Connect a service

A connection links 0 to a service such as GitHub. Connections belong to extensions. GitHub is built in, and other services come as connector extensions you install.

### Connect GitHub

1. Run `0` and open **Extensions**. GitHub is the first row.
2. Press **Connect** and pick one way:
   - **Sign in with GitHub** shows a one-time code to enter at github.com/login/device.
   - **Use a token** links to GitHub's token page with the permissions pull requests need. Paste the token.

GitHub cannot be removed, because pull request Sentinels use it. Turning it off pauses them and asks you to confirm.

GitHub stores the credential in `gh`'s own store. 0 never reads it, and no script receives it. The card lists what the connection can do: read pull requests, pull request diffs, repository contents and the repository list, and write comments on pull requests.

### Connect another service

Install the connector extension with `0 skills add <source>` or **Add** in the browser app. The install prompt shows the connector's declared read and write list, the hosts it can reach and the variable its token fills. After you approve, its card appears on **Extensions** with one **Connect** button.

Paste the token. If the connector declares a health URL, 0 checks the token against it. 0 stores the token on this computer in `~/.0/extensions/connections.json`, readable only by you. **Disconnect** deletes it.

A script in the extension receives the token only if the extension declared that variable name and you approved the prompt. When the bash tool runs a command that names a file inside an enabled extension's folder, 0 adds the declared and approved variables, the stored token included, to the command's environment and masks the value in the output. An extension whose approval does not cover a variable it declares does not run. Its MCP servers get the token the same way. Model provider keys and every other secret stay out.

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
