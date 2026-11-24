---
title: Reference deployment on AWS
description: Run the console on one EC2 instance built from source, with usage metrics off, single sign-on and an audit trail, and tear it down again.
---

This page describes a single-node 0 console on EC2 that makes no outbound calls except to your model endpoint. You build the image from source, sign in through your identity provider and check the audit log. Then you remove everything with one command.

:::caution[Not run on AWS]
We wrote this from the repository and the compose files. We have not applied the Terraform, built the image on EC2 or signed in through a real identity provider on AWS. Treat each step as untested, try it in a scratch account and expect to adjust names and sizes. The [Azure and AWS guide](/self-hosting/) has the longer procedures for backups, restores and upgrades.
:::

## What you get

- One EC2 instance with a gp3 data volume mounted at `/data`.
- An image built on the instance from a pinned tag of the repository. A build with no build secrets contains no telemetry keys.
- `ZERO_ENTERPRISE=1`, so 0 refuses every call outside the model endpoint you configure. See [Data flow](/data-flow/).
- Caddy for HTTPS, or an SSH tunnel with no public port.
- OIDC sign-in, recorded in the audit log.

## Before you start

You need an AWS account, Terraform 1.6 or newer, a DNS name you control and an OIDC client from your identity provider. For the model, use an in-network gateway or a provider key kept in Parameter Store.

Register this callback URL with your identity provider. Use your own name:

```text
https://zero.example.com/api/team/auth/callback
```

## Create the infrastructure

This sketch uses the default VPC. Save it as `main.tf`, set the variables and run `terraform apply`.

```hcl
variable "region"        { default = "eu-central-1" }
variable "domain"        { description = "DNS name of the console, for example zero.example.com" }
variable "admin_cidr"    { description = "Your network, for SSH. Use 127.0.0.1/32 to close SSH and use SSM Session Manager." }
variable "ingress_cidr"  { description = "Networks allowed to reach HTTPS" }
variable "release_tag"   { description = "Release tag to build, for example v0.44.0" }

provider "aws" { region = var.region }

data "aws_vpc" "default" { default = true }

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

resource "aws_security_group" "zero" {
  name   = "zero-reference"
  vpc_id = data.aws_vpc.default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.ingress_cidr]
  }
  # Caddy needs port 80 to get a certificate.
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.ingress_cidr]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  # The build needs the package mirrors, the GitHub clone and the container registries.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "zero" {
  name = "zero-reference"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy" "parameters" {
  role = aws_iam_role.zero.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:GetParametersByPath", "ssm:GetParameter"], Resource = "arn:aws:ssm:*:*:parameter/zero/*" }]
  })
}

resource "aws_iam_role_policy_attachment" "session_manager" {
  role       = aws_iam_role.zero.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "zero" {
  name = "zero-reference"
  role = aws_iam_role.zero.name
}

resource "aws_instance" "zero" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = "t3.xlarge"
  iam_instance_profile   = aws_iam_instance_profile.zero.name
  vpc_security_group_ids = [aws_security_group.zero.id]
  user_data              = templatefile("${path.module}/cloud-init.sh", { domain = var.domain, release_tag = var.release_tag, region = var.region })
  user_data_replace_on_change = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "zero-reference" }
}

resource "aws_ebs_volume" "data" {
  availability_zone = aws_instance.zero.availability_zone
  size              = 50
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "zero-reference-data" }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.zero.id
}

output "public_ip"   { value = aws_instance.zero.public_ip }
output "instance_id" { value = aws_instance.zero.id }
```

Point a DNS record for your domain at `public_ip`.

## Store the secrets

Put the secrets in Parameter Store before the instance starts. Parameter names become environment variable names.

```bash
aws ssm put-parameter --name /zero/ZERO_ACCESS_TOKEN --type SecureString --value "$(openssl rand -base64 32)"
aws ssm put-parameter --name /zero/ZERO_TEAM_OIDC_SECRET --type SecureString --value "<client secret from your identity provider>"
aws ssm put-parameter --name /zero/OPENAI_API_KEY --type SecureString --value "<model key>"
```

Use the key variable of whichever model provider you run. See [Models](/models/).

## Start the console on the instance

Save this as `cloud-init.sh` next to `main.tf`. It formats the data volume, builds the image from the pinned tag and starts the console.

```bash
#!/bin/bash
set -euo pipefail

apt-get update
apt-get install -y docker.io docker-compose-v2 git awscli

# The data volume appears as /dev/nvme1n1 on Nitro instances.
DEV=/dev/nvme1n1
until [ -b "$DEV" ]; do sleep 2; done
blkid "$DEV" || mkfs -t ext4 "$DEV"
mkdir -p /data
mount "$DEV" /data
echo "$DEV /data ext4 defaults,nofail 0 2" >> /etc/fstab
chown 1000:1000 /data
chmod 700 /data

mkdir -p /opt/zero && cd /opt/zero
git clone --depth 1 --branch "${release_tag}" https://github.com/0sec-labs/0security.git src
docker build -f src/deploy/docker/Dockerfile -t 0:local src
cp src/deploy/compose/docker-compose.yml src/deploy/compose/docker-compose.data-disk.yml src/deploy/compose/Caddyfile .

REGION="${region}"
aws ssm get-parameters-by-path --region "$REGION" --path /zero/ --with-decryption \
  --query "Parameters[*].[Name,Value]" --output text |
  while read -r name value; do echo "$(basename "$name")=$value"; done > .env

cat >> .env <<EOF
ZERO_DOMAIN=${domain}
ZERO_PUBLIC_URL=https://${domain}
ZERO_ALLOWED_HOSTS=${domain}
ZERO_DATA_DIR=/data
ZERO_ENTERPRISE=1
ZERO_NO_TELEMETRY=1
COMPOSE_FILE=docker-compose.yml:docker-compose.data-disk.yml:docker-compose.reference.yml
EOF
chmod 600 .env

# Team file with OIDC. Replace the subject with your own after you read it from the identity provider.
cat > /data/team.json <<EOF
{
  "workspace": { "id": "reference", "name": "Reference" },
  "users": [{ "id": "owner", "name": "Owner", "role": "owner", "oidcSub": "REPLACE_WITH_PROVIDER_SUBJECT" }],
  "oidc": {
    "issuer": "https://identity.example.com",
    "clientId": "REPLACE_WITH_CLIENT_ID",
    "clientSecretEnv": "ZERO_TEAM_OIDC_SECRET",
    "redirectUri": "https://${domain}/api/team/auth/callback"
  }
}
EOF
chown 1000:1000 /data/team.json
chmod 600 /data/team.json

cat > docker-compose.reference.yml <<EOF
services:
  zero:
    image: 0:local
    pull_policy: never
    command: ["--host", "0.0.0.0", "--server-mode", "--team-config", "/data/team.json"]
EOF

docker compose --profile proxy up -d
```

Edit the issuer, client ID and subject in `/data/team.json`, then run `docker compose restart zero` from `/opt/zero`. Edits to the team file apply on restart. The instance needs outbound access to your identity provider to sign in.

Check that the console is ready:

```bash
curl -fsS http://127.0.0.1:48123/readyz
```

## Reach the console without DNS

If you do not want a public name, close ports 80 and 443, leave `ZERO_PUBLIC_URL` unset and use an SSH tunnel. OIDC needs the public URL, so the tunnel works with the access token only.

```bash
ssh -L 48123:127.0.0.1:48123 ubuntu@<public_ip>
```

Open `http://127.0.0.1:48123` on your computer.

## Check that usage metrics are off

Ask the running container for its environment and look at the analytics log. The log records every analytics payload that leaves, so it stays empty.

```bash
docker compose exec zero printenv ZERO_ENTERPRISE
docker compose exec zero sh -c 'ls -l /data/.0/analytics-sent.log 2>/dev/null || echo no analytics log'
```

To check from the network side, also look at the instance's outbound connections while you run a scan. They should reach only your model endpoint and, at sign-in, your identity provider.

## Check that sign-in is in the audit log

Sign in through your identity provider in a browser. Then read the audit log:

```bash
docker compose exec zero node /app/dist/0.js config audit-export --type access --since 1h
```

A successful sign-in has the action `access.login`, the detail `kind` set to `sso` and the member's ID and role. A refused sign-in has `access.login_failed`, the outcome `denied` and a reason of `not_a_member` or `verification_failed`. No token, code or cookie appears in either event. Send the log to your SIEM as described in [Send the audit log to a SIEM](/server-mode/#send-the-audit-log-to-a-siem).

## Remove everything

Export what you need first. This deletes the data volume.

```bash
docker compose exec zero node /app/dist/0.js config audit-export --since 365d -o /data/audit-final.ndjson
```

Copy `/data/audit-final.ndjson` and any backup off the instance. Then destroy the stack:

```bash
terraform destroy
aws ssm delete-parameters --names /zero/ZERO_ACCESS_TOKEN /zero/ZERO_TEAM_OIDC_SECRET /zero/OPENAI_API_KEY
```

Remove the DNS record yourself.

## What is not verified

- The Terraform and the start script have not run against an AWS account.
- The image build on `t3.xlarge` and its duration are not measured.
- The OIDC flow is covered by the repository's tests with a stub provider. It has not run against a real identity provider behind Caddy on EC2.
- The `analytics-sent.log` check shows that nothing was sent. It does not replace a network-level check.
