---
title: Evidence for the Cyber Resilience Act
description: Which 0security files support evidence for which obligations of the EU Cyber Resilience Act, and what they do not show.
---

The Cyber Resilience Act (Regulation (EU) 2024/2847) puts duties on manufacturers of products with digital elements. 0 produces records that can support evidence for some of them. This page maps the files to the duties.

0 does not decide whether a product conforms, and no file here says it does. Conformity is the manufacturer's responsibility. Harmonised standards are still being written, and some product classes need a notified body. Check the article and annex references below against the text of the Regulation and with your legal and compliance advisers.

## Produce the files

```bash
0security findings evidence ./evidence --repo . --check-advisories
```

To sign the folder with your key, see [Sign an evidence folder](/ci/#sign-an-evidence-folder). To keep audit records, see [Check the audit log for tampering](/server-mode/#check-the-audit-log-for-tampering).

## What each file supports

| Area of the Regulation | File or command | Supports evidence for |
| --- | --- | --- |
| Annex I Part II, identify and document vulnerabilities and components, including a software bill of materials | `sbom.cdx.json` from `0security sbom generate` | A machine-readable list of components read from your lockfiles |
| Annex I Part II, regular tests and reviews of security | `findings.json`, `findings.md`, `findings.sarif` | Which scans found what, with severity, status, triage notes and times |
| Annex I Part II, address and remediate vulnerabilities without delay | `findings.json` triage and workflow times, `fixes.md` | When a finding was recorded, how it was triaged, and which fix branches exist |
| Annex I Part II, known vulnerabilities in components | `advisories.json` from `--check-advisories` | A lookup of your components in the public OSV database on a given date |
| Article 13 and Annex VII, technical documentation | The whole folder with its `README.md` and `manifest.json` | Records you can attach to technical documentation, with tool version, models, scan ids and git commit |
| Article 14, reporting actively exploited vulnerabilities | `0security findings report-draft` | A draft of each reporting stage that a person completes and submits |
| Integrity of the records above | `evidence.dsse.json` and `0security evidence verify` | The files are unchanged since the holder of your key signed them |
| Integrity of records of privileged actions | `0security config audit-verify`, `audit-export --with-proof` | The audit log was not edited, reordered or cut |

Signing and the retention of audit records are paid features. Verifying is free.

## What it does not show

- That the code has no other weaknesses. The files hold what the scans found and nothing else.
- That a finding is real, that a fix is correct, reviewed or released, or what is deployed.
- That the SBOM is complete. It is read from lockfiles and misses vendored code and system packages.
- That an advisory lookup is current beyond its date.
- Who signed, beyond who holds the key. A signature does not show the findings are right.
- That the audit log is honest. The chain shows it is consistent. Someone who can rewrite the whole database can rewrite the chain, so keep a copy of the head hash elsewhere.
- Any duty that is not about records: the risk assessment, secure design, the support period, the coordinated disclosure policy, the declaration of conformity and notifying authorities. A person does those.

## Keep the files

The Regulation sets how long a manufacturer keeps technical documentation. Confirm the period with your advisers, and keep the evidence folders, the public key and the audit archives for at least that long.
