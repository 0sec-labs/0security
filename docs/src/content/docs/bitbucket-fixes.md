---
title: Fix findings on Bitbucket
description: Create and update fix pull requests on Bitbucket Cloud or Data Center with your own git credentials and access token.
---

`0security fix` uses the repository's `origin` to select GitHub, Bitbucket Cloud or Bitbucket Data Center. Bitbucket fixes use the REST API directly; they do not need `gh`.

For Bitbucket Cloud, configure your own git credentials with write access and set a repository/workspace access token or OAuth access token that can read and write pull requests:

```bash
export BITBUCKET_TOKEN=...
0security fix <finding> --repo ./your-clone --test "npm test"
```

For Data Center, also name the HTTPS server URL, including any context path. The hostname must match the clone's origin:

```bash
export BITBUCKET_URL=https://bitbucket.example.com/bitbucket
export BITBUCKET_TOKEN=...
0security fix <finding> --repo ./your-clone --test "mvn test"
```

You can pass `--host bitbucket-cloud` or `--host bitbucket-dc` explicitly, and `--bitbucket-url` instead of `BITBUCKET_URL`. Cloud origins use `bitbucket.org/workspace/repo`; Data Center HTTPS clone URLs use `/scm/PROJECT/repo.git`, and SSH clone URLs use `PROJECT/repo.git`.

The API token stays in the Authorization header. Git uses your existing credentials; the token is never placed in a command argument or remote URL. A different `origin` push URL or multiple push destinations are refused. HTTP redirects are refused, and fix pushes disable git hooks. A fix pushes only its own branch with a lease and never merges it.

The command opens one pull request for the fix branch and base, and updates its description on subsequent runs. Failing checks, or no checks without `--ready`, make it a draft. Data Center updates include the current PR version so concurrent edits cause a conflict instead of being overwritten silently. A server that does not preserve draft state causes an error; inspect that PR before proceeding. The implementation targets the Cloud API and Data Center 9.6 contracts.

Bitbucket PRs do not support GitHub labels. Data Center reviewer settings use usernames. Cloud reviewer settings currently require account UUIDs through the host API; the CLI's reviewer policy accepts GitHub-style names, so leave Cloud reviewers to Bitbucket's default reviewers. Local test results are separate from CI build statuses: a locally verified fix can still have pending or failed CI.

`--no-pr` makes a local fix commit without API credentials or a push. It works when the code host is unavailable.

In restricted network mode, Bitbucket remains blocked unless the process environment explicitly sets `ZERO_BITBUCKET_URL` for the destination. See the data-flow documentation for the allowlist policy; setting `BITBUCKET_URL` alone does not grant an exception.

The test suite exercises actual git pushes against a temporary bare repository and the HTTP request flow against a local server. A successful local test is not proof of compatibility with your live Bitbucket version or credentials. Run the same fix flow in a dedicated repository on your server before enabling it for production repositories.
