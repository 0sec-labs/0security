# Qualification run: a large Java project

This page records one real run of `0security scan` on a public Maven project, with SARIF output. It lists the numbers as measured, including what went wrong. Use the recipe to repeat it.

## Recipe

Clone the project into an empty folder outside any repository, then plan and scan:

```bash
git clone --depth 1 https://github.com/WebGoat/WebGoat.git /tmp/qualify/webgoat
0security scan /tmp/qualify/webgoat --plan
0security scan /tmp/qualify/webgoat --budget 1.5 --timeout 1500 --format sarif -o scan.sarif
```

Continue a stopped scan with the command it prints, for example `0security scan /tmp/qualify/webgoat --resume <scan-id>`.

Check the SARIF against the official 2.1.0 schema. In this run a Draft 4 validator reported 0 errors:

```bash
curl -sLo sarif-schema-2.1.0.json https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json
python3 -I -c "import json,jsonschema; jsonschema.Draft4Validator(json.load(open('sarif-schema-2.1.0.json'))).validate(json.load(open('scan.sarif')))"
```

## What was scanned

- Project: WebGoat, commit 4e98f1c. A single Maven module (one root `pom.xml`), so the module map did not apply.
- Size: 585 source files, 327 entry points (256 routes, 44 file uploads, 15 deserialization sites, 7 exec sites, 5 mains) and 149 groups of other files. 58 batches at the default batch size.
- Plan estimate: $1.01 to $6.09. Verdict at the default budget: could go either way.
- Model: the default (gpt-6-luna). Pattern scanner (foxguard) pre-pass: 152 leads.
- Flags: `--budget 1.5 --timeout 1500 --format sarif`. One thread at a time.

## Result

- Wall time: 1518 seconds. The scan stopped at its 1500 second limit.
- Cost: $0.351 of the $1.50 budget.
- Coverage: 6 of 58 batches reviewed. 48 of 327 entry points reviewed, 279 not reached. 0 of 149 groups of other files reviewed. Exit code 3 (partial, not failed).
- Why batches were not reviewed: 3 stopped at their own cost ceiling of $0.05, 1 was cancelled by the time limit, and 48 were never started.
- Findings: 26 in the SARIF (5 error, 8 warning, 13 note). Categories: information disclosure 6, CSRF 4, command injection 3, missing validation 3, broken access control 2, denial of service 2, and one each of XSS, unsafe deserialization, broken authentication, hardcoded secret, crypto misuse and SSRF.
- SARIF: valid against the 2.1.0 schema. The run properties carry the status, the failure cause and the coverage ledger.

## What this shows

- A scan of a few hundred files in one module does not finish in 25 minutes at one batch at a time. A batch took about 2.5 minutes on average, so 58 batches need about 2.5 hours. Use `--concurrency` (up to 3), a longer `--timeout`, and `--resume`.
- With 58 batches the budget share is below the $0.05 floor, so each batch got $0.05. Three batches reached that ceiling. The scan reported "Stopped by the $1.5 budget" while only $0.351 was spent. The message is misleading: the limit that stopped those batches was the per-batch floor, not the total budget.
- The findings were not checked by hand. The count is not a measure of true positives. The 26 results include project lessons that are intentionally vulnerable, so many are expected.

## Not done

- SARIF import into a viewer. Only the schema check was done.
- Findings with fixes. The scan report carries no fixes; the SARIF has none. A fix run (`0security fix`) was not part of this run.
- The scan was not resumed to completion, and no second model or concurrency setting was tried. This is one run.
- The issue asks for a project of this kind with SARIF "and fixes"; this run covers scan and SARIF only.
