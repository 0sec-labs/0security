---
title: Server mode and Docker
description: Run one-shot prompts from the 0 container image, or run the app on a server for a team (experimental, single node).
---

The 0 container image runs one-shot prompts, or the web console on a server for a team. The image is Linux amd64 only. Its entry point is the `0security` CLI, so arguments after the image name are `0security` arguments. With no arguments it starts the web console (see [Run the app on a server](#run-the-app-on-a-server-experimental-single-node)).

## One-shot prompts

Run a prompt against the current folder:

```bash
docker run --rm -e OPENAI_API_KEY=$KEY -v "$PWD:/work" -w /work \
  ghcr.io/0sec-labs/0security:latest -p "Review this folder for injection bugs"
```

Pick a tag:

```
ghcr.io/0sec-labs/0security:latest
ghcr.io/0sec-labs/0security:<sha>
ghcr.io/0sec-labs/0security:edge      # nightly build of the newest green main commit
ghcr.io/0sec-labs/0security:v0.44.0   # releases only
ghcr.io/0sec-labs/0security:0.44.0    # releases only, same image as v0.41.0
ghcr.io/0sec-labs/0security:0.44      # releases only, follows the latest 0.41.x
```

`latest` is the most recent release. For repeatable runs, use a version tag, a digest or a short-SHA tag. The sources are the [Dockerfile](https://github.com/0sec-labs/0security/blob/main/deploy/docker/Dockerfile) and [docker-publish.yml](https://github.com/0sec-labs/0security/blob/main/.github/workflows/docker-publish.yml).

## Image contents

The image is based on `ubuntu:24.04` and includes:

| Category | Tools |
|----------|-------|
| Node.js runtime | Node 24, npm, npx |
| Static analysis | FoxGuard (checksum-pinned) |
| Web pentesting | sqlmap, nmap, nikto, gobuster, hydra, ffuf, wfuzz, whatweb, wafw00f, dirb |
| Active Directory | impacket (0.13.1), certipy-ad (5.1.0), bloodhound-ce (1.9.1), ldap-utils, krb5-user |
| Cloud identity | AzureHound (v3.0.0, checksum-pinned) |
| Source analysis | ripgrep, jq, git |
| Container analysis | skopeo |
| Scripting | python3, python3-requests, python3-bs4 |
| Optional | SecLists wordlists (`INSTALL_SECLISTS=1` build arg, about 1 GB extra) |

## Mounts and state

Mount your working directory at `/work` so the container can read source and write reports:

```bash
docker run --rm \
  -e OPENAI_API_KEY=$KEY \
  -v "$PWD:/work:ro" -w /work \
  ghcr.io/0sec-labs/0security:latest -p "Check the login flow"
```

The container runs as the `ubuntu` user (uid 1000). State lives in `/data` (`HOME=/data`, so `/data/.0`). To keep findings after the container exits, mount a volume there with `-v zero-data:/data`.

## Run the app on a server (experimental, single node)

This is the supported way to run the web console for more than one person. It is experimental: one node, one container, one volume, no high availability. See [Teams and enterprise](#teams-and-enterprise).

For AWS or Azure with persistent disks, secret stores, backups and TLS ingress, see [Self-hosting on Azure and AWS](/self-hosting/).

### Start it

```bash
git clone --depth 1 https://github.com/0sec-labs/0security && cd 0security/deploy/compose
cp .env.example .env            # set ZERO_ACCESS_TOKEN (openssl rand -base64 32) and your provider key
docker compose up -d
```

The console answers on `http://127.0.0.1:48123` on that machine. To reach it from elsewhere, use the proxy profile, which adds Caddy with automatic HTTPS. Point a DNS name at the server, open ports 80 and 443, and set these in `.env`:

```bash
ZERO_DOMAIN=0.example.com
ZERO_PUBLIC_URL=https://0.example.com
ZERO_ALLOWED_HOSTS=0.example.com
```

```bash
docker compose --profile proxy up -d
```

Without Compose:

```bash
docker run -d --name zero -p 127.0.0.1:48123:48123 -v zero-data:/data -e ZERO_ACCESS_TOKEN=... ghcr.io/0sec-labs/0security:v0.44.0
```

Open the address and enter the access token. If you left `ZERO_ACCESS_TOKEN` empty, the first start generates one. It prints the token once in `docker compose logs zero` and stores it in `/data/.0/access-token` (mode 0600). If you configure [team accounts](#teams) with `ZERO_TEAM_CONFIG`, people sign in with those instead.

### Server mode flags

`0security --host 0.0.0.0 --server-mode` is the image default. A plain `0security` binds loopback only.

| Flag | Environment | Purpose |
|---|---|---|
| `--server-mode` | `ZERO_SERVER_MODE=1` | Allow a network bind and require sign-in. |
| `--allowed-host <name>` | `ZERO_ALLOWED_HOSTS` | Host names the console answers to. Any other `Host` gets 403. Required with `0.0.0.0`. |
| `--trusted-proxy <cidr>` | `ZERO_TRUSTED_PROXY` | Proxy addresses whose `X-Forwarded-*` headers are trusted. |
| `--public-url <url>` | `ZERO_PUBLIC_URL` | The public https address, for secure cookies and single sign-on. |
| `--access-token-env <name>` | `ZERO_ACCESS_TOKEN` | The access token, 32 characters or more. |
| `--shutdown-timeout <seconds>` | | How long `docker stop` lets running requests finish. Default 20. |

The server refuses to start with no credential, an access token under 32 characters, or a network bind with no allowed host. It warns if you publish the port without a trusted TLS proxy. Plain HTTP sends the access token and session cookie in clear text.

`GET /healthz` (the process is up) and `GET /readyz` (the database answers; 503 while starting or stopping) need no sign-in. `/readyz` returns only `{"status": ...}`. `/healthz` also returns `modelTransport` counters: consecutive and total model-call connection failures, pool rebuilds and the last failure code. They contain no secrets. The image health check uses `/healthz`.

### Sizing

- Minimum is 2 vCPU, 4 GB of memory and an SSD volume. Add about 1 vCPU and 1 to 2 GB for each Thread that runs at the same time, and more disk for large reports.
- Run one replica. The SQLite database has one owner process, and two containers on one volume corrupt it.
- The compose file has commented example limits. Model calls go to your provider with your keys.

### Back up

Stop the container and copy the volume:

```bash
docker compose stop zero
docker run --rm -v zero_zero-data:/data -v "$PWD:/backup" ubuntu:24.04 tar czf /backup/zero-data-$(date +%F).tgz -C /data .
docker compose start zero
```

Or take an online SQLite backup while it runs:

```bash
docker compose exec zero node -e "const {DatabaseSync,backup}=require('node:sqlite');(async()=>{const db=new DatabaseSync('/data/.0/0.db',{readOnly:true});await backup(db,'/data/backup.db');db.close()})()"
docker compose cp zero:/data/backup.db ./zero-backup.db && docker compose exec zero rm /data/backup.db && chmod 600 zero-backup.db
```

To restore, stop the container, extract the archive into the volume and start it again. A backup contains your findings, so store it securely.

### Upgrade

Set `ZERO_IMAGE_TAG=v0.44.0` in `.env`, or keep `latest`, then pull and recreate:

```bash
docker compose pull && docker compose up -d
```

Database migrations run on start. Take a backup first. There is no in-place rollback: to go back, restore the backup and pin the older tag.

The container never updates itself. On Docker, the console's update card shows `docker pull ghcr.io/0sec-labs/0security:latest` instead of an **Update and restart** button, and the background installer is off.

### Remote computers over SSH

The image includes the OpenSSH client. Settings or `0security computers add --ssh user@host` can install and connect a [remote computer](/computers/) from inside the container. Host key checking stays on, so the remote host must already be in `known_hosts`.

1. Create a dedicated key without a passphrase, because the deploy runs non-interactively. Add `zero_ed25519.pub` to the remote user's `authorized_keys`.

   ```bash
   ssh-keygen -t ed25519 -f zero_ed25519 -N ""
   ```

2. Record the host key and verify its fingerprint out of band before you trust it. Run the last command on the server and compare its fingerprint with the one from `known_hosts`.

   ```bash
   ssh-keyscan -t ed25519 host.example.com > known_hosts
   ssh-keygen -lf known_hosts
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

3. Mount both files read-only. OpenSSH reads `/home/ubuntu/.ssh`, not `$HOME`.

   ```bash
   docker run -d ... \
     -v "$PWD/zero_ed25519:/home/ubuntu/.ssh/id_ed25519:ro" \
     -v "$PWD/known_hosts:/home/ubuntu/.ssh/known_hosts:ro" \
     ghcr.io/0sec-labs/0security:v0.44.0
   ```

The container runs as uid 1000. On a Linux host, make the key readable by that user only:

```bash
sudo chown 1000:1000 zero_ed25519 && chmod 600 zero_ed25519
```

OpenSSH refuses a key that is group- or world-readable, or that the container user cannot read. The compose file has the same mounts, commented out.

To avoid a key file in the container, forward an agent socket and still mount `known_hosts`. The socket must be accessible to uid 1000. On Linux:

```bash
-v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent
```

On Docker Desktop for Mac:

```bash
-v /run/host-services/ssh-auth.sock:/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent
```

The remote computer needs Linux, Node.js, an SSH account that can run `bash`, and outbound access to your model provider. The container opens an SSH tunnel (`-L`) to it, so the remote needs no inbound port besides SSH. The deployment record is kept in `/data`, but the tunnel does not survive a container restart. Reconnect from Computers after a restart.

### Pull request reviews

A Sentinel with a `github-pr` trigger polls `gh pr list`. It needs no inbound address, so it works from a container behind a proxy. It needs GitHub access from the container. Either set `GH_TOKEN` or `GITHUB_TOKEN` in `.env` to a fine-grained token limited to the repositories you review (read access to Contents, Pull requests and Metadata), or sign in once:

```bash
docker compose exec -it zero gh auth login
```

The credential is kept under `/data/.config/gh`. Reviews are drafts in the app and post nothing to GitHub unless you turn on comments. See [Sentinels](/sentinels/#github-pull-request-trigger).

With a public HTTPS address (`ZERO_PUBLIC_URL`), an optional GitHub webhook at `https://<your domain>/api/webhooks/github` makes pull request Sentinels react right after a push. It requires a valid `X-Hub-Signature-256` on every request. The only other address that answers without sign-in is `/api/webhooks/trigger/<trigger-id>` for [webhook triggers](/sentinels/#webhook-trigger), which needs that trigger's own secret. Set it up as described in [Sentinels](/sentinels/#faster-with-a-github-webhook-server-mode). Keep `--trusted-proxy` set so the rate limit sees the real sender.

If the secret leaks, rotate it. The old secret works for 5 minutes.

```bash
docker compose exec zero 0 sentinels webhook secret rotate --yes
```

### Send the audit log to a SIEM

The audit log records privileged actions: settings changes, extension installs, connections and denied attempts. Export it as a file, or push it from a server to your collector.

Export a day of events as NDJSON, CEF or RFC 5424 syslog lines:

```bash
0security config audit-export --since 24h
0security config audit-export --format cef --type extension -o audit.cef
0security config audit-export --format syslog --follow
```

Events print oldest first. `--since` and `--until` take a duration such as `24h` or `7d`, or a date. `--type` takes an action or a prefix, so `extension` matches `extension.install`. `--limit` keeps the newest events. `-o` writes a file only you can read. `--follow` keeps printing new events until you press Ctrl+C. Flags are in [config audit-export](/commands/#config-audit-export).

To push events from a server, set the destination in the server's environment:

```bash
ZERO_AUDIT_SINK_URL=https://siem.example.com/ingest
ZERO_AUDIT_SINK_TOKEN=...
```

A syslog collector uses `ZERO_AUDIT_SINK_URL=syslog+tls://logs.example.com:6514`. The sink is off unless you set the URL. Only the server's environment sets it. A repository, a project file or the database cannot.

- An `https://` URL receives NDJSON by default. Set `ZERO_AUDIT_SINK_FORMAT` to `cef` or `syslog` for those lines instead. The token, if set, goes in an `Authorization: Bearer` header.
- A `syslog+tls://` URL receives RFC 5424 lines over TLS, one per line. The server checks the certificate against the system and Node.js trust store.
- Plain `http://` and `syslog+tcp://` work only for this machine. UDP syslog is refused.
- The server refuses to start when the setting is refused, so a feed you expect is never silently off.
- `ZERO_ENTERPRISE` does not block the sink, because you name the destination. See [Data flow](/data-flow/).

The sink sends events in batches every two seconds. It retries a failed batch five times with growing delays, then drops it. It never slows or fails the action it records. The server prints a status line when it drops events and when it stops, and the audit log API shows the same counters:

```text
audit sink https://siem.example.com: sent 120, dropped 3, last error: collector answered HTTP 503
```

The sink starts after the newest event when the server starts. Use `0security config audit-export --since` to load earlier history. A restart can lose events written while the server was down. The log keeps the newest 50,000 events.

#### Event fields

Every format carries the same fields.

| Field | Meaning |
| --- | --- |
| `schema` | `0.audit.v1`. |
| `eventId` | A 32-character hash of the event. It stays the same across exports and the sink, so use it to deduplicate. |
| `seq` | Position in the local log. It grows by one for each event. |
| `ts` | Time in ISO 8601 UTC with milliseconds. |
| `actor` | Who acted, for example `operator (browser)`, `engine` or `cli`. |
| `action` | What happened, for example `extension.install`, `settings.change`, `decision.approved` or `access.browser_only`. |
| `subject` | What it happened to, for example an extension name, a setting key or a route. |
| `outcome` | `ok`, `denied` or `error`. |
| `detail` | A small object. Only these keys are kept: key, keys, old, new, scope, enabled, approved, decision, fingerprint, name, transport, envKeys, headerKeys, callerKind, route, method, status, code, kind, id, sentinelId, triggerId, trigger, reason, role, autonomy, seed, preset, count, source, repo, sessionId, decisionId, path, version, client. |

The log never stores secrets, tokens, evidence bodies or prompts. Text fields are cut at 200 characters, and values that look like keys or tokens become `[redacted]`. The export applies the same redaction again.

In CEF the header is `CEF:0|0security|0|<version>|<action>|<action>|<severity>`, with severity 3 for `ok`, 6 for `denied` and 7 for `error`. The extension carries `externalId` (the event id), `rt` (epoch milliseconds), `suser` (actor), `act`, `outcome`, `cs1` (subject), `cs2` (detail as JSON), `cn1` (seq) and `dvchost`.

In syslog the line is `<PRI>1 <ts> <host> 0 - <action> [audit@32473 eventId seq actor action subject outcome] <event as JSON>`. The facility is authpriv, and the severity is informational, warning or error for `ok`, `denied` and `error`. The structured-data ID uses the documentation enterprise number 32473 because 0 has none registered.

The TLS sink is tested against a local listener with a self-signed certificate. It is not tested against a commercial collector. Collectors that need their own envelope, such as Splunk HEC, are not supported directly.


### Check the audit log for tampering

Each audit event stores a hash of the event before it and a hash of its own content. Changing, removing or reordering an event breaks the chain from that point on. Check it:

```bash
0security config audit-verify
```

The command prints the first break and exits 1 when the chain is broken. It is free, runs offline and needs no license.

When the log reaches 50,000 events, the oldest are removed. A rotation checkpoint keeps the hash of the last removed event, so the rest still verifies. Events written before this feature existed are counted but cannot be verified.

The check proves the log is consistent. It does not prove the log is honest: someone who can rewrite the whole database can rewrite the chain too. Copy the head hash that the command prints, or send the log to a SIEM, to keep a record they cannot reach. Removing the newest events with no new event after them is caught only when the database still records that they existed.

### Not supported

- High availability, failover, or more than one replica.
- Sharing the volume between containers or hosts.
- Webhooks other than the optional GitHub pull request webhook. Pull request triggers poll without it.
- Shared sandboxes or per-customer isolation inside one container. Everyone who signs in shares the same computer and data.
- A hosted service. Dedicated and on-premises deployments are arranged by contract.
- Internet access without a TLS-terminating proxy in front.

### Threat model in short

The console can run security tools and use your model keys, so access to it is full control. In server mode:

- An anonymous visitor sees only a sign-in page and never receives the console's control token.
- Sign-in sets an `HttpOnly`, `SameSite=Strict` cookie, and `Secure` over HTTPS.
- Wrong tokens are throttled with growing delays.
- 0 refuses requests for unknown host names, from other origins, or without same-origin evidence on changes.
- Forwarded headers count only from `--trusted-proxy`.
- Sign-ins, failures and refusals go to the audit log.

Keep the access token secret, use HTTPS, and restrict who can reach the port.

## Supply chain

- Commands run as the `ubuntu` user.
- Ubuntu packages follow the configured apt repositories. The Dockerfile pins the AD Python packages and verifies the AzureHound and FoxGuard downloads.
- Changing `AZUREHOUND_VERSION` also needs matching checksums in the Dockerfile.
- The AD tools venv is not on `PATH`, so it cannot shadow system Python packages.

## Build your own

```bash
docker build -f deploy/docker/Dockerfile -t 0:local .
docker build -f deploy/docker/Dockerfile --build-arg INSTALL_SECLISTS=1 -t 0:full .
```

The published image embeds the project's telemetry keys, like the release binaries. Your own build embeds none unless you pass the `zero_release_sentry_dsn` and `zero_release_posthog_key` BuildKit secrets.

## Teams

Local use needs no account. Use team mode when several people share one computer and its Threads.

In the browser app, choose **Team**, then enter a workspace name, your display name, account ID and password. You are signed in as owner. Owners add editors and viewers from **Team settings** in the account menu.

From a terminal:

```bash
0security config set team init --config ./team.json --name "Security" --owner alex --display-name "Alex"
0security config set team add-user --config ./team.json --user morgan --display-name "Morgan" --role editor
0security config get team --config ./team.json
0 --team-config ./team.json
```

0 reads passwords from a prompt or stdin, never from arguments. The file stores salted scrypt hashes, so keep it private (`0600`). `init` never overwrites an existing file. Edits to the file apply when the computer restarts, and a restart ends open Threads.

Owners and editors can change work. Viewers can read. Messages keep their authors, and avatars show who is viewing or typing.

Members share one computer workspace, not separate tenants. Each team gets its own Thread directory, findings database and reports by default. Existing personal Threads are not imported. Use `--db-path` to choose the database to share. The computer binds to loopback, so remote access and a reverse proxy are your deployment work.

### OIDC sign-in

Add an `oidc` object and give each member the provider's verified `oidcSub`. Names and email claims never grant membership or roles.

```json
{
  "workspace": { "id": "your-workspace-id", "name": "Security" },
  "users": [
    { "id": "alex", "name": "Alex", "role": "owner", "oidcSub": "provider-subject-id" }
  ],
  "oidc": {
    "issuer": "https://identity.example.com",
    "clientId": "your-client-id",
    "clientSecretEnv": "ZERO_TEAM_OIDC_SECRET",
    "redirectUri": "http://127.0.0.1:48123/api/team/auth/callback"
  }
}
```

Register the exact callback URL with your provider. Omit `clientSecretEnv` for a public client. Sign-in uses the authorization code flow with PKCE and checks issuer, audience, nonce and signature. Session cookies are HTTP-only and last eight hours.

## Teams and enterprise

0 is open source under MIT OR Apache-2.0. The CLI, engine, browser app and team workspace are all in the [`0sec-labs/0security`](https://github.com/0sec-labs/0security) repository. None of them needs an account, a license key or a 0security-hosted service. Model calls go to the provider you choose with your own key. Findings stay on your computer, CI runner or servers. The only automatic upload is the anonymous telemetry described in [Configuration](/configuration/#telemetry).

### Free and paid

Everything you use today is free: scans, fixes, findings, SBOMs, the web console, the team workspace and audit log export. Verifying a compliance bundle or an audit log is always free.

The `enterprise/` folder in the same repository holds the paid features:

- A shared findings server for many repositories and teams.
- Finer roles, SCIM provisioning and SAML sign-in.
- Signed compliance evidence bundles, a tamper-evident audit log and retention policies.

You can read that code. Running it in production needs a license key. Development and testing need none. See [LICENSING.md](https://github.com/0sec-labs/0security/blob/main/LICENSING.md).

A key is a signed string. 0 checks it on your machine and never contacts a server. Set it in the environment of the process that runs 0:

```bash
export ZERO_LICENSE="<your key>"
```

Or point to a file that holds the key:

```bash
export ZERO_LICENSE_FILE=/etc/0security/license.txt
```

See what your key unlocks:

```bash
0security config get license
```

When a key expires, paid features keep working for 30 days with a warning. After that, paid writes stop. You can still read, export and verify your data, and the server still starts. `ZERO_ENTERPRISE` is the separate no-egress switch and does not need a key.

A team workspace shares one computer between members. It is not multi-tenant. Sessions are held in memory, so members sign in again after a restart. Results from several computers are not merged.

Enterprise is arranged with us, not self-served. We can help you run 0 on your own infrastructure, or operate a dedicated deployment for you, one customer per deployment, by contract. We publish no Helm chart or Terraform module and offer no shared multi-tenant cloud. [Book a demo](https://0.security/enterprise/).
