# Opt-in Java verification

Date: 2026-11-25. Scope: self-hosted engine and CLI (#450, #463).

The operator explicitly opts into executing repository build code with `--sandbox-profile java` or the existing `--sandbox docker` options. A plain fix keeps its current source-editing behavior and does not acquire a default build step. Hosted execution, default execution and multi-tenant isolation are outside this decision.

The Java profile uses a content-pinned official Maven/JDK image, warms dependencies with an online verify build, then runs a network-off canary and offline checks. Only completed passing checks support the existing sandbox-verification statement. A failed or unavailable Docker runtime is a failure, never evidence of verification. A green build is evidence for its checks, not a guarantee of security or exploitability.

Private Maven artifact credentials are optional, explicit, short-lived, read-only and supplied in an owner-only settings file outside the repository. The caller copies it into a per-step scratch directory, mounts it read-only for online setup only, withholds that step's output, and removes the copy afterward. It never gives the file to the model, normal offline checks or the PR report. The source credential file remains the operator's responsibility.

Online setup executes repository build scripts with the credential available. A malicious build can steal it or copy it into its dependency cache. Therefore this option is for trusted build definitions with narrowly scoped, expiring artifact-read credentials. Do not use production, SCM-write or signing credentials. This boundary does not claim secret isolation from the build itself. Strict `ZERO_ENTERPRISE` still refuses online setup; the Java profile does not bypass that policy.

Qualification recorded during implementation: official OCI index fetched from Docker Hub registry; local Maven/JDK regression fixture compiled and three JUnit tests executed successfully. The exact pinned Maven image then ran on Colima/Docker Linux arm64: online warm-up succeeded, the offline canary passed and its online negative control failed, offline verify passed all three tests, and removing the traversal guard caused two expected failures offline. A live private artifact registry and Linux amd64 remain unqualified.
