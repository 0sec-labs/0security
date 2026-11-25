# AI security benchmark, 2026-11-25

Results are from one model on small synthetic fixtures. See `docs/design/benchmark-ai-security.md` for how to reproduce.

## Method

- CLI version 0.45.0, built from the branch that adds this benchmark.
- Detection: `node scripts/bench/ai-security.mjs --detect`. It builds the planted folder and its clean twin, runs `0security sbom agent-config` on each and matches findings to the key by rule id, file and line, exactly. No model is called.
- Model-judged: `node scripts/bench/run.mjs --run --fixtures llm-app-2 --configs generic,skill --repeat 3 --budget 0.2`. A fresh home per run. The `generic` configuration is a plain scan with `--prepass off`. The `skill` configuration adds `--skill llm-app-review`. The matcher is the existing one in `scripts/bench/match.mjs`.
- Model: the default model (gpt-6-luna). One model only.

## Fixtures

- `agent-config-repo`: 16 planted items and 11 decoys in a planted folder, plus a clean twin. Planted: hidden Unicode (tag characters, and zero width and bidirectional characters), an HTML comment that tells the agent to ignore earlier instructions, four unpinned launchers (npx, bunx, pipx, docker latest), a remote http MCP server, two secrets in MCP env (built at run time from fragments), broad Claude permissions (three), a hook that pipes curl into a shell, a project MCP server, and a symlinked rules file. Decoys: pinned launchers, https remote, emoji joined with zero width joiners and a flag sequence, a rules file that names the attack phrase in plain view, narrow permissions, placeholders and references in env, a symlink no agent reads.
- `llm-app-2`: a small Python assistant, 127 lines, no dependencies, no network calls. 9 planted bugs and 6 decoys.

## Numbers

Detection (no model, deterministic):

| folder | found | recall | precision | decoy hits | other unexpected | findings in clean twin |
|---|---|---|---|---|---|---|
| planted | 16 of 16 | 100% | 100% | 0 | 0 | not applicable |
| clean | not applicable | not applicable | not applicable | not applicable | not applicable | 0 |

Twelve more findings in the planted folder are listed in the key as context and are not scored. The rules report one project-autostart finding for every enabled server and one hook-command finding for every hook, by design.

Model-judged, `llm-app-2`, 3 repeats each:

| configuration | recall (mean, range) | found per run | false positives | unmatched findings | cost per run | time per run |
|---|---|---|---|---|---|---|
| generic | 67% (56% to 78%) | 7, 6, 5 of 9 | 0 | 0 | $0.0080 ($0.0065 to $0.0098) | 78 s (65 to 90) |
| skill | 56% (56%) | 5, 5, 5 of 9 | 0 | 0 | $0.0070 ($0.0058 to $0.0076) | 66 s (51 to 75) |

Total model cost of the six scans: $0.0448. The cap was $1.50.

Missed items by run:

- generic: run 1 missed the prompt injection through the tool result and the unpinned download. Run 2 also missed the `exec` of model code. Run 3 missed the injection, `exec`, the uploaded notes in the system prompt and the unpinned download.
- skill: runs 1 and 2 missed the injection, `exec`, the unpinned download and the pickle load. Run 3 missed the injection, `exec`, the notes in the system prompt and the unpinned download.

The prompt injection through a tool result was never credited, and the unpinned download was missed in all six runs. Every run reported the shell tool, the HTML output, the secrets in the prompt and the unrestricted fetch. The matcher credits one finding to one item, so a single finding that mixes the injection with the shell tool can credit only one of them. I did not read the findings to decide how many such cases there were.

## What this does not show

- It does not show how 0security does on real applications. The fixtures are small, written by the authors, and hold a handful of bug shapes.
- The detection fixture was written against the rule set, so full recall is a regression check. It is not an independent measurement. The rules were not tuned to it, but the key was written with them in view.
- One model, three repeats and nine planted bugs. A difference of one or two bugs is within the spread. The generic and skill configurations are not shown to differ.
- The wording rule is a heuristic. It reports visible attack phrases in non-rules files such as command files, which no decoy here covers.
- `0security probe` is not scored. The `mcp-server-review` skill and `sbom generate --ai` are not scored.
- No other tool was run, and no comparison is made.
- Cost and time vary with the provider on the day.
