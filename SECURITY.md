# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub private vulnerability reporting:

<https://github.com/0sec-labs/0security/security/advisories/new>

Do not open a public issue, pull request or discussion for a suspected vulnerability. Include the affected version (`0security --version`), what you observed, and the steps or proof of concept needed to reproduce it. If the report concerns the `0` engine, the CLI, the container image or the install script, it belongs here. Vulnerabilities in the companion scanner are best reported in its own repository (<https://github.com/0sec-labs/foxguard>); we will forward anything that lands here by mistake.

## What to expect

These are targets, not guarantees. We are a small team.

| Step | Target |
| --- | --- |
| Acknowledge your report | within 3 business days |
| Initial assessment and severity | within 10 business days |
| Fix or mitigation for confirmed high and critical issues | within 90 days, sooner where we can |

We will keep you informed as the report progresses, and we are glad to credit you in the advisory unless you prefer to stay anonymous. We ask that you give us a reasonable chance to ship a fix before you disclose publicly, and we will coordinate the disclosure date with you.

## Supported versions

Security fixes are made against the latest release. Older releases are not patched; upgrade to the latest release to receive fixes. Self-hosted deployments should follow the upgrade steps in the [self-hosting guide](https://docs.0.security/self-hosting/#upgrades-and-rollbacks).

## Verifying what you run

Every release publishes SHA-256 checksums, a CycloneDX SBOM and GitHub build-provenance attestations for each asset. See [Verify a release](https://docs.0.security/self-hosting/#verify-a-release).

## Safe harbor

We will not pursue legal action against people who make a good-faith effort to follow this policy: test only against your own installations and accounts, avoid privacy violations and service disruption, do not access or modify other people's data, and report what you find promptly. This is a statement of intent and not a legal waiver. It does not authorize testing of systems we do not own or operate.
