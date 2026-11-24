---
title: Self-hosting on Azure and AWS
description: Deploy the 0security container on Azure and AWS with persistent volumes, cloud secret stores, TLS ingress, automated backups, and upgrades.
---

Run 0 in your own cloud tenant to keep code analysis, findings and model conversations inside your perimeter. This guide runs the official image (`ghcr.io/0sec-labs/0security`) on AWS and Azure with a persistent disk, a secret store, TLS ingress, backups and upgrades.

:::caution[Cloud steps are untested]
We checked the container, compose files, data-disk override, and backup and restore procedure against the repository. We rendered the override with `docker-compose config`. We have not run the AWS and Azure steps against real accounts: instance and disk setup, IAM and Key Vault, ECS, S3 and Blob uploads, and snapshot policies. Each is marked untested. Try them in a scratch account and adjust names, device paths and policies.
:::

## Architecture and constraints

0 is a single-node application:

```
                  Internet / Corporate Network
                               │
                               ▼
               ┌───────────────────────────────┐
               │    TLS Ingress (Ports 80/443) │
               │     Caddy, AWS ALB, or AGW    │
               └───────────────┬───────────────┘
                               │ HTTPS / Reverse Proxy
                               ▼
               ┌───────────────────────────────┐
               │   0 Server Container (Docker) │
               │   Runs as non-root (uid 1000) │
               │      Binds 127.0.0.1:48123    │
               └───────────────┬───────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       ┌───────────────┐               ┌───────────────┐
       │   /data       │               │ Cloud Secrets │
       │  EBS / Azure  │               │ AWS SSM / SM  │
       │ Managed Disk  │               │ Azure KeyVlt  │
       └───────────────┘               └───────────────┘
```

### The single-node rule

- The console stores its data in an embedded SQLite database at `/data/.0/0.db`. With the data-disk override below, that file is on the host's mounted disk.
- Run one replica. SQLite needs a single owner process, so never mount the volume in more than one container.
- For recovery, rely on VM auto-recovery, volume snapshots and scheduled database backups.

### Sizing

| Sizing | vCPU | RAM | Storage | Typical Cloud Instance |
|---|---|---|---|---|
| Minimum | 2 | 4 GB | 30 GB SSD | AWS `t3.medium`, Azure `Standard_B2s` |
| Standard | 4 | 8 GB | 60 GB SSD | AWS `t3.xlarge` / `m7g.large`, Azure `Standard_D2s_v5` |
| High load | 8 | 16 GB | 120 GB SSD | AWS `m7g.xlarge`, Azure `Standard_D4s_v5` |

Add about 1 vCPU and 1 to 2 GB of memory for each concurrent scan or fix Thread.

---

## AWS

### Run on EC2 with Docker Compose

This is the simplest setup: an EC2 instance with an attached EBS volume.

For a build from source with usage metrics off, OIDC sign-in and a teardown, see [Reference deployment on AWS](/aws-reference/).

#### 1. Provision storage and compute (untested)

1. Launch an Ubuntu 24.04 LTS instance, for example `t3.xlarge` or `m7g.large`.
2. Attach an EBS `gp3` volume of about 50 GB as `/dev/sdf` for application state.
3. Format and mount it. The device is `/dev/nvme1n1` or `/dev/xvdf`, depending on the instance generation.
   ```bash
   sudo mkfs -t ext4 /dev/nvme1n1
   sudo mkdir -p /data
   sudo mount /dev/nvme1n1 /data
   echo "/dev/nvme1n1 /data ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab
   sudo chown -R 1000:1000 /data
   sudo chmod 700 /data
   ```

#### 2. IAM role and secrets (untested)

Keep credentials out of git. Use AWS Systems Manager (SSM) Parameter Store or AWS Secrets Manager.

1. Store the secrets:
   ```bash
   aws ssm put-parameter --name "/zero/ZERO_ACCESS_TOKEN" --type "SecureString" --value "$(openssl rand -base64 32)"
   aws ssm put-parameter --name "/zero/ANTHROPIC_API_KEY" --type "SecureString" --value "sk-ant-..."
   aws ssm put-parameter --name "/zero/GH_TOKEN" --type "SecureString" --value "ghp_..."
   ```

2. Attach an IAM role with read access to the EC2 instance:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ssm:GetParametersByPath",
           "ssm:GetParameter"
         ],
         "Resource": "arn:aws:ssm:*:*:parameter/zero/*"
       }
     ]
   }
   ```

3. Write the secrets to `.env` before the container starts:
   ```bash
   mkdir -p /opt/zero
   aws ssm get-parameters-by-path --path "/zero/" --with-decryption \
     --query "Parameters[*].[Name,Value]" --output text | \
     while read -r name val; do
       var_name=$(basename "$name")
       echo "${var_name}=${val}"
     done > /opt/zero/.env
   chmod 600 /opt/zero/.env
   ```

#### 3. Run the application

Download the compose files:

```bash
cd /opt/zero
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0security/main/deploy/compose/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0security/main/deploy/compose/Caddyfile -o Caddyfile
```

Download the data-disk override. It puts the database on the disk you mounted at `/data`, not in the Docker named volume `zero-data` on the root disk:

```bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0security/main/deploy/compose/docker-compose.data-disk.yml -o docker-compose.data-disk.yml
```

Add your domain and network settings to `/opt/zero/.env`:

```bash
ZERO_DOMAIN=zero.internal.yourcompany.com
ZERO_PUBLIC_URL=https://zero.internal.yourcompany.com
ZERO_ALLOWED_HOSTS=zero.internal.yourcompany.com
ZERO_IMAGE_TAG=v0.44.0
COMPOSE_FILE=docker-compose.yml:docker-compose.data-disk.yml
ZERO_DATA_DIR=/data
```

`COMPOSE_FILE` makes every later `docker compose` command in this guide use both files. `ZERO_IMAGE_TAG` accepts `v0.41.0` or `0.41.0` (see [Tags](/server-mode/#one-shot-prompts)).

Start the container with automatic TLS through Caddy:

```bash
docker compose --profile proxy up -d
```

Check that the service is ready and the database is on the data disk:

```bash
curl -fsS http://127.0.0.1:48123/readyz     # {"status":"ready"}
ls -l /data/.0/0.db                          # the database file is on the mounted disk
```

`/readyz` returns `{"status":"ready"}` once the database answers, and 503 while the service starts or stops. `/healthz` returns `{"status":"ok"}` and says only that the process is up.

---

### Run on ECS (untested)

Use ECS to avoid managing host operating systems.

1. Create an ECS cluster with the EC2 launch type, which allows EBS attachments.
2. Define one container task using `ghcr.io/0sec-labs/0security:v0.44.0`:
   - Mount host `/data` at container `/data`.
   - Map `secrets` from Secrets Manager or SSM Parameter Store to environment variables such as `ZERO_ACCESS_TOKEN` and `ANTHROPIC_API_KEY`.
   - Set the health check to `curl -fsS http://127.0.0.1:48123/healthz || exit 1`.
3. Create a service with `desiredCount: 1`. Set minimum healthy percent to `0` and maximum percent to `100`, so ECS never starts a second container on the same volume during a deploy.

---

## Azure

### Run on a VM with Docker Compose

#### 1. Compute and disk setup (untested)

1. Deploy an Ubuntu 24.04 LTS VM, for example `Standard_D2s_v5`.
2. Attach a Premium SSD managed data disk, for example 64 GB, LRS.
3. Mount the disk:
   ```bash
   sudo parted /dev/sdc --script mklabel gpt mkpart xfspart ext4 0% 100%
   sudo mkfs.ext4 /dev/sdc1
   sudo mkdir -p /data
   sudo mount /dev/sdc1 /data
   echo "/dev/sdc1 /data ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab
   sudo chown -R 1000:1000 /data
   sudo chmod 700 /data
   ```

#### 2. Key Vault (untested)

1. Enable a system-assigned managed identity on the VM.
2. In Key Vault, grant that identity the Key Vault Secrets User role.
3. Store these secrets in Key Vault:
   - `ZERO-ACCESS-TOKEN`
   - `AZURE-OPENAI-API-KEY`
   - `GH-TOKEN`
4. Write the secrets to `.env` at startup:
   ```bash
   az login --identity --allow-no-subscriptions
   TOKEN=$(az keyvault secret show --vault-name "kv-zero-prod" --name "ZERO-ACCESS-TOKEN" --query value -o tsv)
   KEY=$(az keyvault secret show --vault-name "kv-zero-prod" --name "AZURE-OPENAI-API-KEY" --query value -o tsv)

   cat <<EOF > /opt/zero/.env
   ZERO_ACCESS_TOKEN=${TOKEN}
   AZURE_OPENAI_API_KEY=${KEY}
   ZERO_DOMAIN=zero.azure.yourcompany.com
   ZERO_PUBLIC_URL=https://zero.azure.yourcompany.com
   ZERO_ALLOWED_HOSTS=zero.azure.yourcompany.com
   EOF
   chmod 600 /opt/zero/.env
   ```

#### 3. Ingress and firewall (untested)

- In the network security group, allow inbound TCP 80 and 443.
- Run `docker compose --profile proxy up -d` to terminate TLS with Caddy.
- Or put an Application Gateway or Front Door in front of port 48123, and set `ZERO_TRUSTED_PROXY` to the gateway subnet.

---

## Scheduled backups and restore

Findings and audit logs live in the SQLite database `/data/.0/0.db`. This section assumes the data-disk override above, so the host's `/data` is the container's `/data`. With the plain compose file (named volume `zero-data`), use the volume steps in [Server mode: Back up](/server-mode/#back-up).

### 1. Online safe database backup

Never copy a live SQLite file with `cp`. Take the online backup in [Server mode: Back up](/server-mode/#back-up): the `node:sqlite` backup command, then `docker compose cp`. It leaves `./zero-backup.db`. Date it for retention:

```bash
mv ./zero-backup.db ./zero-backup-$(date +%F).db
```

### 2. Offsite upload to cloud object storage (untested)

Run the backup daily from cron and upload it.

AWS S3:

```bash
aws s3 cp ./zero-backup-$(date +%F).db s3://my-org-zero-backups/$(date +%Y)/$(date +%m)/backup-$(date +%F).db \
  --sse aws:kms --sse-kms-key-id alias/zero-backup-key
```

Azure Blob Storage:

```bash
az storage blob upload \
  --account-name "zeroorgbackups" \
  --container-name "db-backups" \
  --file "./zero-backup-$(date +%F).db" \
  --name "$(date +%Y)/$(date +%m)/backup-$(date +%F).db" \
  --auth-mode login
```

### 3. Cloud disk snapshots (untested)

A snapshot taken while 0 runs is crash-consistent only. Use it as a second line behind the database backup, or stop the service briefly first with `docker compose stop zero`.

- AWS: create an Amazon Data Lifecycle Manager policy for daily snapshots of the `/data` EBS volume, kept 14 days.
- Azure: configure Azure Backup or a disk snapshot policy for the data disk.

### 4. Restore procedure

You need `sqlite3` on the host (`sudo apt-get install -y sqlite3`). Run these steps from `/opt/zero`. We ran the file and database commands against a sample database. We did not run the compose steps and the data-disk override on a cloud host.

1. Stop the service so nothing writes to the database:
   ```bash
   docker compose stop zero
   ```

2. Move the current database aside and remove its journal files. A leftover `-wal` or `-shm` file from the old database would be applied to the restored one and corrupt it:
   ```bash
   sudo mv /data/.0/0.db /data/.0/0.db.before-restore
   sudo rm -f /data/.0/0.db-wal /data/.0/0.db-shm
   ```
   If the `mv` fails because there is no database yet, continue.

3. Restore the backup and set the owner and mode:
   ```bash
   sudo cp ./zero-backup-2026-11-21.db /data/.0/0.db
   sudo chown 1000:1000 /data/.0/0.db
   sudo chmod 600 /data/.0/0.db
   ```

4. Check the restored file before you start. The output must be exactly `ok`. If it is anything else, or an error such as `file is not a database`, do not start the service. Repeat step 3 with another backup. Your previous database is still at `0.db.before-restore`.
   ```bash
   sudo sqlite3 /data/.0/0.db 'PRAGMA integrity_check'
   ```

5. Start the service and confirm it is ready:
   ```bash
   docker compose up -d zero
   for i in $(seq 1 30); do curl -fsS http://127.0.0.1:48123/readyz && break; sleep 2; done
   ```
   A good restore prints `{"status":"ready"}`. If the loop ends without it, read `docker compose logs --tail 50 zero`.

6. Delete `0.db.before-restore` after you confirm the restored data in the app. It contains findings.

---

## Verify a release

Each release publishes the standalone binaries, `checksums.txt`, and a CycloneDX SBOM (`0-sbom.cdx.json`). The binaries are named `0security-<platform>`. The same bytes are also published as `0-<platform>`, which is kept so existing installs can update. `checksums.txt` lists both names. The release workflow also creates a GitHub build-provenance attestation for every one of those assets, so you can prove that a file was built by this repository's release workflow and not just that it matches a hash someone served you.

With the [GitHub CLI](https://cli.github.com/) installed and logged in (`gh auth login`), download an asset from the [release page](https://github.com/0sec-labs/0security/releases) and verify it:

```bash
gh attestation verify 0security-linux-x64 --repo 0sec-labs/0security
gh attestation verify checksums.txt --repo 0sec-labs/0security
```

Then check the binary against the verified checksums:

```bash
sha256sum --check --ignore-missing checksums.txt
```

On macOS use `shasum -a 256 --check --ignore-missing checksums.txt` instead.

The install script does the same for you. When `gh` is installed and logged in it verifies the `checksums.txt` attestation before it trusts any hash, and it prints a clear note and falls back to the plain `checksums.txt` check when `gh` is missing. Set `INSTALL_ATTESTATION=require` to fail instead of falling back, or `INSTALL_ATTESTATION=0` to skip the attestation on an air-gapped host or an internal mirror. Neither setting disables the checksum comparison. The FoxGuard companion is always checked against a SHA-256 pinned in the install script.

To audit the dependencies of a release, run the SBOM through the advisory check:

```bash
0security sbom check 0-sbom.cdx.json
```

Reproducibility: builds run on GitHub-hosted runners with pinned tool versions and a frozen lockfile, but the binaries are not bit-for-bit reproducible, so the attestation, not a local rebuild, is the evidence of origin. The SBOM lists lockfile dependencies of the tagged source and does not enumerate the bundled runtime.

To report a vulnerability, see the [security policy](https://github.com/0sec-labs/0security/security/policy).

---

## Upgrades and rollbacks

### Upgrades

1. Take a fresh backup, as in [Backups](#1-online-safe-database-backup). Keep it until the upgrade is verified.
2. Set the new tag in `/opt/zero/.env` (`ZERO_IMAGE_TAG=v` followed by the new version). Then pull and recreate, as in [Server mode: Upgrade](/server-mode/#upgrade):
   ```bash
   docker compose pull zero && docker compose up -d zero
   docker compose logs --tail 50 zero
   ```
   Database migrations run on start.

### Rollbacks

Migrations only go forward, so a rollback needs the pre-upgrade database. Pin the previous tag in `/opt/zero/.env`, for example `ZERO_IMAGE_TAG=v0.44.0`. Then run the [restore procedure](#4-restore-procedure) with the pre-upgrade backup. Step 5 runs `docker compose up -d`, which applies the pinned tag.

---

## Security hardening checklist

- Run as the `ubuntu` user (uid 1000). Never set `user: root`.
- Mount the host volume with mode `0700`, owned by `1000:1000`.
- Behind a local reverse proxy such as Caddy, bind the container port to `127.0.0.1:48123` only. Never expose port 48123 on `0.0.0.0` without TLS termination.
- Set `ZERO_ALLOWED_HOSTS` to exactly your public hostname. A request with any other `Host` header gets 403.
- Set `ZERO_PUBLIC_URL=https://...` so session cookies carry the `Secure` attribute.
