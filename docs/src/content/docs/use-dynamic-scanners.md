---
title: Use Nuclei, ZAP or Strix with 0security
description: Run a dynamic scanner on your staging app, import its results, and triage and fix them in one list with the findings from your code.
---

Nuclei, ZAP and Strix test a running web app. 0security reads what they find and puts it in the same list as your code findings. You triage and fix everything in one place.

0security does not attack anything in this flow. You run the other tool yourself, against an app you own, and 0security only reads the file it wrote.

## Before you start

Run these tools only against systems you own or have written permission to test. Use a staging copy, not production. Dynamic scanners send real requests and can change data.

## Import Nuclei results

Write Nuclei's JSON Lines file. It names the matched URL, the CWE and the severity.

```bash
nuclei -u https://staging.example.com -jsonl-export nuclei.jsonl
0security findings import nuclei.jsonl
```

0security also reads Nuclei's SARIF export (`-sarif-export`). That file names only the host, not the matched URL, so prefer the JSON Lines file.

## Import ZAP results

Add a report job with the `sarif-json` template to your ZAP automation plan.

```yaml
jobs:
  - type: report
    parameters:
      template: sarif-json
      reportDir: .
      reportFile: zap.sarif
```

Run the plan, then import the file.

```bash
zap.sh -cmd -autorun plan.yaml
0security findings import zap.sarif
```

## Import Strix results

Strix writes a `findings.sarif` file in each run folder under `strix_runs`.

```bash
strix -n --target https://staging.example.com
0security findings import strix_runs/<run-name>/findings.sarif
```

The file leaves out the exploit script. It keeps the description of the proof of concept, and 0security stores that text as evidence. Strix's coverage notes are not findings, and 0security skips them.

## Triage and fix

Imported findings are marked unverified. List them next to your code findings.

```bash
0security findings list
```

A web finding shows the method and URL where a code finding shows a file and line. Open a finding, set its triage state, and fix it in the code like any other. See [Findings](/findings/).

## What 0security keeps

Each finding keeps the tool name, rule id, CWE, severity, the method and URL, and any proof text. Importing the same file twice changes nothing. Credentials in a URL and anything that is not an http or https address are dropped.

## Limits

0security does not re-test an imported finding. It does not check that the tool was pointed at your app.

The ZAP and Strix shapes are read from their documented output and from Strix's report writer. They have not been checked against a live ZAP run. Nuclei was run for real against a local test server.
