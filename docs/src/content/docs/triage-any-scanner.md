---
title: Triage findings from any scanner
description: Scan, then verify. Use leads from the built-in scanner or from another tool's SARIF, let 0 check each one, keep true-positive and uncertain, and read the measured results with their limits.
---

A pattern scanner is fast and finds many leads. Most leads are false alarms. 0 can check each lead with a fresh model thread that reads the code. This page shows the steps and what we measured.

The model only checks leads. It does not add bugs the scanner missed.

## Scan, then verify

1. Get leads. Scan with the built-in scanner, or import SARIF from another tool:

   ```bash
   0security scan ./app --format json -o scan.json
   0security findings import ./codeql.sarif --root ./app --tool "CodeQL"
   ```

   `findings import` reads SARIF 2.1.0 from CodeQL, Semgrep, ZAP, Strix, Nuclei and others. Nothing in the file is executed. Each result becomes a finding with the scanner's rule, severity, CWE, file and line. Use `--root` for the folder that was scanned, so absolute paths become repository paths. See [Import findings from another scanner](/findings/#import-findings-from-another-scanner).

2. Verify the leads. Pass the folder that was scanned, so the threads can read the code:

   ```bash
   0security findings verify --folder ./app --concurrency 2 --budget 5 --per-finding 0.1 --no-variants
   ```

   Each finding gets its own thread. The thread gets only the finding's text, reads the code, and records a verdict: true-positive, false-positive, fixed, uncertain or duplicate. A thread that returns no verdict is recorded as uncertain. A re-run skips findings that already have a verdict. `--budget` is the total spend and `--per-finding` caps one finding. `--no-variants` skips the hunt for the same bug at other sites after a true-positive verdict, so the run only judges the leads you gave it. See [Check findings for false positives](/findings/#check-findings-for-false-positives) and [findings verify](/commands/#findings-verify).

3. Keep the true-positive and the uncertain findings. Set aside the false-positive and duplicate ones. `0security findings list` and `0security findings show <id>` print each verdict and its reasoning. The verdict is advice. Severity and status do not change unless you pass `--apply`, and even then critical and high findings are never suppressed.

Keep uncertain. In the measurements below, keeping uncertain verdicts kept recall at or near the scanner's own. Dropping them lost real bugs.

## What we measured

We imported leads into 0, ran `findings verify` with the model `gpt-6-luna`, and scored the result against the answer key of the OWASP Benchmark for Java. The runs below keep true-positive and uncertain findings.

### Limits first

- The OWASP Benchmark for Java is synthetic and generated from templates. Its files are not real code.
- Many files carry cues. Safe cases often contain the word "safe" in a comment or a string literal. We repeated the runs with the comments removed, and with the cue literals replaced. About a quarter of the gain disappears (see below). The cue-free score is the better estimate for real code.
- Sample A has 304 cases. Sample B has 290 cases. They are two disjoint samples of the same benchmark. An odd and even split of one benchmark is a weak holdout, so do not read sample B as proof that the result carries to other code.
- Each configuration ran once. The model is not deterministic, so differences of a few cases are noise.
- Verification cannot add bugs the scanner missed. Recall can only stay the same or fall.
- Verification can wrongly dismiss a real finding. It happened about three times per 300 cases. This is why uncertain stays.
- The numbers are for one model on one benchmark. They are not your repository's result.

### Leads from the built-in scanner

| Sample | Score before | Score after | False alarm rate before | False alarm rate after | Real cases dropped |
| --- | --- | --- | --- | --- | --- |
| A (304 cases) | 0.763 | 0.862 | 0.151 | 0.033 | 3 |
| B (290 cases) | 0.822 | 0.902 | 0.122 | 0.020 | 3 |

With the comments removed and the cue literals replaced, sample A went from 0.763 to 0.836 instead of 0.862. About a quarter of the gain is gone. All the dropped real cases had a plain false-positive verdict. At least three of the eleven drops across the runs came from a mismatch in the finding's stated source or algorithm, where the code was still vulnerable.

### Leads from CodeQL

CodeQL leads (the `java-security-extended` suite, filtered to the sample files) found every real case on sample A, with many false alarms.

| Sample | Score before | Score after | Recall after | False alarm rate before | False alarm rate after |
| --- | --- | --- | --- | --- | --- |
| A (304 cases) | 0.592 | 0.822 | 1.000 | 0.408 | 0.178 |
| B (290 cases) | 0.642 | 0.851 | 0.993 | 0.358 | 0.142 |

With comments removed, sample A scored 0.770. With the cue literals replaced, it scored 0.750. That is a gain of 0.178 or 0.158 instead of 0.230.

The false alarms that stayed were mostly the benchmark's dead-branch and helper tricks, which the model evaluated wrongly, and hash and crypto cases that depend on a properties file we did not include. Keeping only true-positive verdicts, and dropping uncertain, lost 10 real cases on sample A and 6 on sample B, all of them uncertain verdicts. Keeping both lost none on A and one on B.

### Leads from SonarQube Community

SonarQube Community has no SARIF export, so we converted its issue list to SARIF. Its leads reached a recall of 0.368 on sample A and 0.394 on sample B. Verification removed false alarms (the false alarm rate went from 0.125 to 0.053 on A) and the score rose from 0.243 to 0.316. Recall stayed at the lead recall. Verification cannot raise it.

### Cost and speed

- Cost was about a tenth of a cent per verified finding. For 425 CodeQL findings on sample A the recorded cost was $0.413. A few threads that failed returned no cost, so the true figure is slightly higher.
- Speed was about 10 findings a minute at `--concurrency 2` on a loaded machine. The 425 findings took about 2,550 seconds.
- A run can stop on a transport error. Start it again. Findings that already have a verdict are skipped.

### Real vulnerabilities

The benchmark above is synthetic. We also ran scanners on 39 real Java vulnerabilities from the Vul4J dataset, on the code before the fix. A hit means a finding of the right weakness class in a file the fix changed.

| Scanner | Hits on 39 |
| --- | --- |
| Semgrep OSS | 2 |
| foxguard, the built-in pattern scanner | 7 |
| Model scan (`0security scan`), told which package to scan | 10 |

Pattern scanners find a minority of these. The model scan found 10 of 39, which is also a minority. The model scan was handed the package of the fix, so 10 of 39 is an upper bound. Without that, a scan of a large project may find fewer. The run is a single run on a small sample of projects from 2013 to 2019. Repeat runs vary by two or three vulnerabilities, and the 10 of 39 has a wide interval, roughly 14% to 42%.

The scan's own triage also rejected two real flaws that it had found. This is the same failure as in `findings verify`: a real finding dismissed.

## What to do with this

- Use verification to cut review time on a large lead list. Do not use it to decide that code is safe.
- Keep uncertain. A person, or a stricter rule, decides those.
- Use `--apply` only for low and medium findings, and read the reasoning first. `findings reopen` undoes a suppression.
- A scanner that misses a bug is still a gap. Run more than one scanner and scan with the model too.
