# Java agent-layer benchmark

This benchmark measures what the 0 scan agent finds in Java code. It runs the full scan with a model, never the pattern scanners alone. Use it as evidence of agent-layer quality on Java.

## Run it

Check the fixtures and the scorer without a model:

```bash
node scripts/bench/run.mjs --dry-run --fixtures-dir scripts/bench/java/fixtures
```

Run the scan for real. It spends model money, up to the printed worst case:

```bash
node scripts/bench/run.mjs --run --fixtures-dir scripts/bench/java/fixtures \
  --configs generic --repeat 1 --budget 0.2 --out scripts/bench/java/results
```

Build the engine, then the CLI, first. Each scan runs with a fresh home folder, a copy of the fixture without its answer key, `--prepass off` and `--budget`.

## Fixtures

Four small Maven-layout projects with a hand-written answer key (`answer.json`) each.

- java-servlet: SQL injection, command injection and path traversal in servlets, with a prepared statement and an allow-list as decoys.
- java-spring: missing ownership check, XML external entities, Java deserialization and a hardcoded token in a Spring controller, with an owner check as decoy.
- java-crypto: unsalted MD5, AES in ECB mode, a hardcoded key and a token from `java.util.Random`, with AES-GCM as decoy.
- java-clean: safe code only. Any finding there is a false positive.

That is 11 planted bugs, 6 decoys and 1 clean project.

## Scoring

A finding counts as a hit when it is in the same file as a planted bug, within 5 lines of it, and its category is in the same family as the bug (for example `sql-injection` for `sqli`). The matcher is `scripts/bench/match.mjs`.

- Recall: planted bugs found divided by planted bugs.
- False positives: findings on a decoy (within 2 lines), and every finding in the clean project.
- Unmatched: findings that are neither. Read them by hand. They are real extra issues or noise.
- Cost and time: from the scan report, per fixture and per configuration.

Results go to `scripts/bench/java/results/<time>.md` and `.json`. Report the mean and the min-max range over repeats. A difference smaller than the range is noise.

## Limits

- The fixtures are small and written by us. They are not the OWASP Benchmark or Vul4J. A result here does not predict a result on those, or on a large project.
- One repeat is a single sample. Use `--repeat 3` or more before you quote a number.
- Category families are matched by pattern. A real bug reported under an unrelated category counts as unmatched, not as a hit.
- A model that cannot call tools well scores low because its findings are incomplete, not because the code is hard.

## First result

One repeat, `generic` configuration, default model (gpt-6-luna), `--budget 0.2` per scan, run on 2026-11-24. Files are in `scripts/bench/java/results`.

- Recall: 10 of 11 planted bugs (java-crypto 4 of 4, java-servlet 3 of 3, java-spring 3 of 4).
- Missed: the hardcoded API token in java-spring.
- False positives: 1. The model flagged the prepared statement in java-servlet. java-clean produced no findings.
- Cost: $0.0196 for all four scans. Time: 41 to 92 seconds per scan.

This is a single sample on small fixtures written for this benchmark. It shows the harness works. It is not procurement evidence yet: it needs more repeats, larger code, and the OWASP Benchmark and Vul4J.

## Not done

- OWASP Benchmark and Vul4J. Both need their own harness: the OWASP Benchmark scores by test case id, and Vul4J needs a build and the project's tests per vulnerability.
- Comparison with foxguard alone and with other tools on the same fixtures. Run `--configs foxguard` to add the scanner-led configuration.
