---
title: Self-hosted trial guide
description: "Install 0 from this repository on Docker or Helm, connect Amazon Bedrock, check it with a five-minute smoke test, wire Bitbucket and GitHub, and run a 40,000-line benchmark."
---

This guide takes an engineer from an empty machine to a working self-hosted 0 and a first benchmark. It covers Docker, Helm, Amazon Bedrock, Bitbucket and GitHub. It links to the full pages for each part and states what is not tested.

Real Amazon Bedrock calls are not qualified yet (see [Limits](#limits)). Run the smoke test before you plan anything else.

## Size the machine

The minimum is 2 vCPU, 4 GB of memory and 30 GB of SSD. Add about 1 vCPU and 1 to 2 GB of memory for each Thread that runs at the same time. A benchmark at concurrency 3 needs about 5 vCPU and 7 to 10 GB.

Run one replica. See [Self-hosting on Azure and AWS](/self-hosting/#sizing) for larger sizes.

## Allow the network traffic

Open these destinations from the machine:

- `ghcr.io`, to pull the image.
- `github.com`, to clone this repository and download releases.
- Your model endpoint. For Amazon Bedrock that is the regional `bedrock-runtime` endpoint and the AWS credential endpoints for your credential source.
- Your Bitbucket or GitHub host, if you connect one.

Set `ZERO_ENTERPRISE=1` and `DO_NOT_TRACK=1` to stop every other automatic call. That setting also refuses every `gh` call and Bitbucket Cloud. See [Data flow](/data-flow/) for the full list.

## Start with Docker

Clone the repository and start the console:

```bash
git clone --depth 1 https://github.com/0sec-labs/0security && cd 0security/deploy/compose
cp .env.example .env
docker compose up -d
```

Set `ZERO_ACCESS_TOKEN` in `.env` first, with `openssl rand -base64 32`. Open `http://127.0.0.1:48123` and enter the token. To reach the console from another machine, see [Server mode and Docker](/server-mode/#start-it).

## Start with Helm

Create the namespace and the access token Secret, then install the chart:

```bash
kubectl create namespace zero
kubectl -n zero create secret generic zero-secrets \
  --from-literal=ZERO_ACCESS_TOKEN="$(openssl rand -base64 32)"
helm install zero deploy/helm/zero -n zero \
  --set secrets.existingSecret=zero-secrets \
  --set model.provider=bedrock \
  --set model.name=eu.anthropic.claude-sonnet-4-5-20250929-v1:0 \
  --set model.awsRegion=eu-central-1
helm test zero -n zero
kubectl port-forward svc/zero-zero 48123:80 -n zero
```

The chart sets `ZERO_ENTERPRISE` by default. Set `enterprise: false` if you use pull request reviews on GitHub. For ingress, TLS and the other values, see [Run on Kubernetes with Helm](/self-hosting/#run-on-kubernetes-with-helm).

## Connect Amazon Bedrock

Choose one of two ways.

### Use the AWS credential chain

0 calls Bedrock with the AWS SDK. Give the container an AWS role, or set the credentials in `.env`. Then pin the provider and name a model your account can invoke:

```bash
ZERO_SELECTED_PROVIDER=bedrock
ZERO_MODEL=eu.anthropic.claude-sonnet-4-5-20250929-v1:0
AWS_REGION=eu-central-1
```

The IAM role needs `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on the inference profile and on the foundation model behind it. See the policy under [Amazon Bedrock](/models/#amazon-bedrock). A container on EC2 reaches the instance role only if the instance metadata hop limit is 2 or more.

### Use a LiteLLM gateway

Put a LiteLLM proxy in front of Bedrock. The proxy holds the AWS credentials and 0 never sees them. See [Enterprise gateway: Bedrock through LiteLLM](/models/#enterprise-gateway-bedrock-through-litellm).

## Run the smoke test

This takes about five minutes. It checks the model connection before you scan anything. Run it where 0 runs, with the settings above:

```bash
0security doctor
0security -p "Reply with the single word ready"
```

`doctor` checks the machine and the engine. The prompt makes one model request. If it answers, the provider, credentials and model work. If it fails with an access error, check the model ID, the region and the IAM resources first.

In Docker, put `docker compose exec zero` in front of each command.

## Connect Bitbucket and GitHub

For Bitbucket, create a token that can read pull requests, write comments and write Code Insights reports. A repository access token works on Cloud and an HTTP access token on Data Center. Check your setup before the first review:

```bash
export BITBUCKET_TOKEN=...
0security sentinels bitbucket doctor --platform dc --repo PROJECT/repo --url https://bitbucket.example.com --checkout ~/code/repo
```

For GitHub, the token or `gh` login needs the access each feature uses:

- Pull request checks with the Action: the job permission `security-events: write`.
- Code scanning uploads from a Sentinel: the `security_events` scope for a classic token.
- Pull request comments: permission to comment on pull requests.
- Commit statuses: the status permission.

See [Pull request checks](/ci/) and [Sentinels](/sentinels/).

## Run a 40,000-line benchmark

Use a public Java project of about 40,000 lines so the result does not depend on your code. WebGoat at a pinned commit has 35,209 Java lines:

```bash
git clone https://github.com/WebGoat/WebGoat && cd WebGoat
git checkout 4e98f1cbbf896fdd06edcc9930515ebe0ade7c69
```

Check the size of the work first. `--plan` lists the entry points, the batches and a rough cost range, and makes no model request:

```bash
0security scan . --plan
```

Then run the audit in batches at concurrency 3, with a budget and a time limit:

```bash
0security scan . --batches on --concurrency 3 --budget 5 --timeout 1800 --format json -o webgoat.json
```

If it stops at the budget or the time limit, it exits with code 3 and keeps its findings. Continue it:

```bash
0security scan . --resume latest --batches on --concurrency 3 --budget 5 --format json -o webgoat.json
```

`--format` takes json, md, sarif, html or pdf. Use json for the agent's verdicts and guidance, and sarif for tools that read it.

In one earlier run with the model `gpt-6-luna` on OpenAI, this audit cost about $1.79 and took about 34 minutes. The first run stopped at the time limit and `--resume` finished the rest. That run was not on Bedrock, so costs and speed differ. See [Plan the cost of a large estate](/cost/).

## Limits

- Real Amazon Bedrock calls are not qualified. The Bedrock path is tested against a local stand-in and with unit tests, not against the AWS service.
- Bitbucket, Jenkins and Azure Pipelines integrations are tested with stand-in programs, not on live instances.
- The Terraform and Helm files have not been applied to a real AWS account or cluster.
- 0 runs on one node with one volume. It has no high availability.
- Dependency reachability labels are evidence from import lines. They are an estimate, not proof that vulnerable code runs.
- The benchmark above measures cost and time. It does not measure precision or recall.
