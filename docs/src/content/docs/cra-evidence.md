---
title: Evidence for the Cyber Resilience Act
description: Which 0security files support evidence for which obligations of the EU Cyber Resilience Act, and what they do not show.
---

The Cyber Resilience Act (Regulation (EU) 2024/2847) puts duties on manufacturers of products with digital elements. 0 produces records that can support evidence for some of them. This page maps the files to the duties.

0 does not decide whether a product conforms, and no file here says it does. Conformity is the manufacturer's responsibility. Some product classes need a notified body. The references below are to the [Official Journal text on EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj). Confirm current requirements with your legal and compliance advisers.

## Produce the files

```bash
0security findings evidence ./evidence --repo . --check-advisories
```

To sign the folder with your key, see [Sign an evidence folder](/ci/#sign-an-evidence-folder). To keep audit records, see [Check the audit log for tampering](/server-mode/#check-the-audit-log-for-tampering).

## What each file supports

| Provision | File or command | Supports evidence for |
| --- | --- | --- |
| Annex I Part II point 1; Annex VII points 2(b) and 8 | `sbom.cdx.json` from `0security sbom generate` | A machine-readable component list read from your lockfiles |
| Annex I Part II point 3; Annex VII point 6 | `findings.json`, `findings.md`, `findings.sarif` | Security tests that were run: what they found, with severity, status, triage notes and times |
| Annex I Part II point 2; Article 13(7) | `findings.json` triage and workflow times, `fixes.md` | Vulnerabilities you became aware of, when they were recorded, how they were triaged, and which fix branches exist |
| Article 13(5) and 13(6) | `advisories.json` from `--check-advisories` | A lookup of your third-party components in the public OSV database on a given date |
| Article 13(12), Article 31, Annex VII | The whole folder with its `README.md` and `manifest.json` | Records you can attach to technical documentation, with tool version, models, scan ids and git commit |
| Article 14(2) | `0security findings report-draft` | A draft of the early warning (24 hours), the vulnerability notification (72 hours) and the final report that a person completes and submits |
| Integrity of the records above | `evidence.dsse.json` and `0security evidence verify` | The files are unchanged since the holder of your key signed them |
| Integrity of your own audit records | `0security config audit-verify`, `audit-export --with-proof` | The audit log was not edited, reordered or cut |

The Regulation does not require a signature or an audit log. The last two rows help you show that your own records were not altered. Signing and retention of audit records are paid features. Verifying is free.

## What it does not show

- That the code has no other weaknesses. The files hold what the scans found and nothing else.
- That a finding is real, that a fix is correct, reviewed or released, or what is deployed.
- That the SBOM is complete. It is read from lockfiles and misses vendored code and system packages.
- That an advisory lookup is current beyond its date.
- Who signed, beyond who holds the key. A signature does not show the findings are right.
- That the audit log is honest. The chain shows it is consistent. Someone who can rewrite the whole database can rewrite the chain, so keep a copy of the head hash elsewhere.
- Any duty that is not about these records: the cybersecurity risk assessment (Article 13(2) to 13(4)), secure design (Annex I Part I), the support period, the coordinated vulnerability disclosure policy, the conformity assessment (Article 32), the declaration of conformity, and notifying the authorities through the single reporting platform. A person does those.

## Keep the files

Article 13(13) requires the technical documentation to be kept for at least 10 years after the product is placed on the market, or for the support period, whichever is longer. Keep the evidence folders, the public key and the audit archives for at least that long.
