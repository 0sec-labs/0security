---
title: Java fix verification
description: Explicit Maven/JDK verification with a pinned container image, offline checks and optional short-lived artifact credentials.
---

Use the Java profile when you want a fix checked with Maven and JDK 21:

```bash
0security findings fix <finding-id> --repo ./project --sandbox-profile java
```

This explicitly runs the repository's build scripts. The profile selects official Maven 3.9.11 with Eclipse Temurin 21, warms a fresh disposable cache with `dependency:go-offline verify` (including an online build and tests), checks that the test container has only loopback networking, then runs `mvn -o -B -ntp -Dmaven.repo.local=/cache/m2 verify`. Add `--test 'mvn -o -B -ntp -Dmaven.repo.local=/cache/m2 -pl api -am verify'` to select modules or a different test command. Projects requiring another JDK or Gradle can use the existing explicit `--sandbox docker --sandbox-image <digest-pinned-image> --sandbox-setup <command> --test <command>` options.

The profile's OCI index is `docker.io/library/maven@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237`. It was checked against the Docker Hub registry's `library/maven:3.9.11-eclipse-temurin-21` manifest on November 25, 2026; it includes Linux amd64 and arm64 images. Executing the digest avoids a moving tag. The pinned profile ran on Colima/Docker Linux arm64 during qualification: online warm-up succeeded, the network-off canary passed (and rejected a network-enabled container), and offline Maven compiled the retained Java canary and passed all three JUnit tests. Removing the traversal guard in a disposable copy produced two failing tests in the same offline container. Local Maven also passed the positive fixture and rejected that negative control. Linux amd64 and a live private artifact registry have not been qualified.

A successful setup alone does not verify a fix. Missing plugins in offline mode, failing tests, an unavailable Docker daemon or a failed network canary keep the fix unverified. The online `verify` warm-up is intentional: `dependency:go-offline` alone misses dynamically loaded artifacts such as the Surefire JUnit provider. Supply a trusted explicit `--sandbox-setup` command if your project needs another preparation step. Strict `ZERO_ENTERPRISE=1` refuses online setup; use an already prepared internal image and explicit offline sandbox commands when outbound preparation is forbidden.

## Private Maven artifacts

Issue an expiring credential with artifact-read permission only. Put its Maven `<servers>` and mirror configuration in a regular settings file outside the repository, owned by your account and readable only by you:

```bash
chmod 600 /secure/temporary-maven-settings.xml
0security findings fix <finding-id> --repo ./project --sandbox-profile java \
  --sandbox-maven-settings /secure/temporary-maven-settings.xml
```

The default setup command uses `-s /run/secrets/maven-settings.xml`. With a custom `--sandbox-setup`, include that argument yourself. The caller mounts a temporary copy read-only at that fixed location for online setup only. The model and offline check container receive no settings mount; the PR records the command and exit status but withholds credentialed setup output. The temporary copy is removed after the step. Revoke the credential and remove the original file when done. Do not put secret values in `--test`, `--sandbox-setup` or model prompts.

The setup step runs the repository's build code and plugins. They can read the mounted credential, send it elsewhere while networking is enabled, or write it into the cache. Use this only for trusted build definitions with short-lived credentials; the mount and output controls do not protect a secret from the build itself. No Docker socket, host Maven settings directory, SSH agent or broad home-directory mount is supplied.

The implementation decision and its scope are recorded in [the repository](https://github.com/0sec-labs/0security/blob/main/docs/decisions/java-verification.md).
