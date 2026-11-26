# Packaged CI integrations

Build the Pipe from the repository root:

```sh
docker build -f ci/bitbucket-pipe/Dockerfile -t 0security-pipe:0.46.0 .
sh ci/packaging/qualify-pipe.sh 0security-pipe:0.46.0
```

Set `QUALIFICATION_ARTIFACTS=/absolute/new-directory` to retain the synthetic report, exit code and commit after the rehearsal. The image installs CLI 0.46.0 from its release, verifies its published SHA-256 and embeds the trusted scan/publish scripts. Change `--build-arg VERSION=X.Y.Z` for another explicit release. No `latest` is fetched. The image metadata and invocation example are in `ci/bitbucket-pipe/`; the `docker://ghcr.io/0sec-labs/0security-pipe:0.46.0` name is the intended release location, **not a claim that it has been published**. Build and qualify first, then publish through the release process and replace both example image references with its immutable digest. This change publishes nothing.

Use two pipeline steps. The scan receives only the model key. Keep `BITBUCKET_TOKEN` in a deployment variable available only to the publish step, which disables checkout and consumes only `.zero-ci/scan.*` artifacts. Scan mode refuses a token rather than silently exposing it to repository code. Publish mode runs from an empty temporary directory, accepts only regular artifacts below the clone, and clears model keys and execution settings from the child environment. Configure trusted pipeline definitions and deployment permissions so an untrusted PR cannot rewrite the publisher.

`qualification-pipelines.yml` is a manual Bitbucket test pipeline. For a paid model qualification after approving a cap, set `OPENAI_API_KEY` and pass `--model` to the rehearsal script (budget 1 USD). Its script creates a real local git origin and synthetic PR, runs the actual CLI and installed FoxGuard scanner in the image without a model key or charge, then exercises publish isolation **without a Bitbucket token**. A separate live test must verify Code Insights on the intended Cloud plan/DC version, rerun the same commit to check idempotency, push a new commit, and confirm severity/partial failures. Never use a production repository for qualification.

## Jenkins library

Export the standard Jenkins library structure:

```sh
sh ci/packaging/package-jenkins-library.sh /tmp/0security-jenkins-0.46.0
```

The command also writes a `.tar.gz` package and `.tar.gz.sha256` sidecar beside the output directory for release publication. The output contains `vars/zeroSecurity.groovy` and `resources/0security/`. Mirror that directory into an internal SCM repository, configure it as a trusted external Jenkins Shared Library named `0security`, pin its revision and disallow overriding that revision. `ci/jenkins-library/Jenkinsfile` is the test/adoption pipeline. Put this pipeline definition in trusted SCM, not the scanned PR. The library uses `libraryResource`, documented in [Jenkins Shared Libraries](https://www.jenkins.io/doc/book/pipeline/shared-libraries/), to load the installer and canonical scan/publish scripts.

The scanner and publisher require distinct labels **and distinct physical Jenkins nodes**. Use ephemeral scan nodes; publisher nodes must have no untrusted jobs. Only the scan gets the model credential; only the publisher gets the Bitbucket credential. Stash/unstash transfers the three fixed report files. The publisher performs no checkout, uses a fresh workspace and deletes it afterward. Jenkins permissions, agent isolation and trusted Pipeline provenance are prerequisites, not properties a library can enforce across a compromised controller.

The one-step call is:

```groovy
zeroSecurity scanLabel: 'ephemeral-scan', publishLabel: 'trusted-publish',
  modelCredential: 'openai-api-key', bitbucketCredential: 'bitbucket-token',
  repo: 'PROJECT/repo', bitbucketUrl: 'https://bitbucket.example.com'
```

Options: `version` (pinned release, default package version), `baseBranch` (default `CHANGE_TARGET`), `budget` (default `3`), `failOn` (default `high`), `target` (default `.`), `prepassOnly` (installed scanners only, no model), `platform` (`bitbucket-dc` default or `bitbucket-cloud`), `enterprise` and `allowedBitbucketUrl` for the explicit restricted-egress policy. Do not attach the Bitbucket credential globally to a scan node.

The existing `ci/azure-pipelines.yml` already satisfies the Azure **template** acceptance criterion; an Azure Marketplace extension is outside #453's stated criteria.

## Qualification status

Local automated tests run the wrapper shell against real temporary git histories, verify credential separation and artifact rejection, export the actual Jenkins library and check its resource identity. The Groovy harness can execute the actual shared-library control flow with Jenkins steps supplied by a harness; it is not a Jenkins controller. The image/scanner rehearsal is executable locally; live Jenkins agents, live Bitbucket/Azure pipelines, image publication and release-artifact publication remain explicit release qualification steps. Record the image digest, CLI checksum, server version and test-run links before claiming those integrations are qualified.
