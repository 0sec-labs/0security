# Benchmark: AI security

This benchmark measures how well 0security finds problems in AI agent setups and in LLM application code. Run it to check a change to the agent-config rules or the scan skills.

Results are from one model on small synthetic fixtures. They show that the harness works and give a first reading. They do not show how 0security performs on your code.

## What it measures

There are two parts.

- Detection: `0security sbom agent-config` runs over a folder with planted problems and a clean twin. No model is called, so the run is free and repeatable.
- Model-judged: the scan agent reviews a small LLM app with planted bugs from the OWASP LLM Top 10. Each run costs a few cents.

`0security probe` is not scored here.

## Run the detection part

Build the CLI, then run:

```bash
node scripts/bench/ai-security.mjs --detect
node --test scripts/bench/ai-security.test.mjs
```

The first command builds the folders in a new temporary directory, scans both and prints recall, precision and false positives. It exits 1 on a miss or a false positive. The second runs in CI.

Anything hidden, secret-shaped or linked is made at run time by `scripts/bench/fixtures/agent-config-repo/build.mjs`. The repository holds no invisible characters, no key-shaped strings and no symbolic links. The key is `manifest.json` in the same folder.

A planted item counts as found when a finding has the same rule id, file and line. Findings the rules report on every enabled server or hook, by design, are listed as context and are not scored. Any other finding is a false positive, and a finding in the clean twin always is.

The fixture was written against the rule set. Full recall here is a regression check, not an independent measurement.

## Run the model-judged part

```bash
node scripts/bench/run.mjs --run --fixtures llm-app-2 --configs generic,skill --repeat 3 --budget 0.2
```

`llm-app-2` is a small Python assistant with nine planted bugs and six decoys: prompt injection through a tool result, a shell tool with no approval, model-written code run with `exec`, model output in HTML, uploaded notes in the system prompt, secrets in the prompt, a model download with no pin and a pickle load, and an unrestricted URL fetch. The matcher is the one the other fixtures use. The scan is given a copy without the answer key.

## Results

The latest numbers, method and limits are in `scripts/bench/results/`. Each file is named `ai-security-<date>.md`.

The planted fixtures are marked as intentionally vulnerable. Do not copy them into a real project, and do not treat a scan of this repository that flags them as a product finding.
