<p align="center">
  <img src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/code.png" alt="" height="32">
</p>

# @0/engine

The engine behind the [0 CLI](../../README.md): agent loops, tools,
model runtimes, source review, verification and extensions. The CLI package
is named `@0/cli`; it registers the `0` command.

## Source organization

| Area | Source |
| --- | --- |
| Agent execution | `src/agent/`, `src/console/`, `src/runtime/` |
| Findings, reports and review | `src/storage/`, `src/report-formatters/`, `src/review-checks.ts` |
| Verification | `src/verifier/`, `src/verification-spec/` |
| Plugins and extensions | `src/plugins/` |
| Coordination | `src/events/`, `src/hub/` |

The package is ESM. Its build generates the skill manifest, compiles TypeScript
and copies runtime assets into `dist/`. The main entry point is `src/index.ts`;
internal modules are not automatically part of that exported API.

## Package role versus CLI

Selected exports from `src/index.ts`:

| Entry point | Purpose |
| --- | --- |
| `createRuntime`, `createNativeApiRuntime` | Runtime construction |
| `createConsoleSession` | A thread: the agent loop with tools and findings |
| `@0/engine/storage` | Findings, threads, Sentinels (SQLite) |
| `@0/engine/shared` | Schemas, SARIF and report types |

Use the [quick start](https://github.com/0sec-labs/0security#quick-start) to run an
assessment. For programmatic integration, follow the exported TypeScript types
and [architecture guide](https://github.com/0sec-labs/0security/blob/main/docs/design/architecture.md).

## Feature flags

Feature flags are declared in `src/agent/features.ts`. Each flag maps to a
`ZERO_FEATURE_<NAME>` environment variable. The `@0/cli` `scan` command
has no flag for them; set the environment variable before running it:

```bash
env ZERO_FEATURE_WEB_SEARCH=0 0security scan ./app
env ZERO_FEATURE_PRESET=fp-moat ZERO_FEATURE_POV_GATE=0 0security scan ./app
```

Use the exact environment-variable suffix from `src/agent/features.ts`, not a
guessed camelCase property name. The current feature properties are getters:
they re-read the environment when accessed. Explicit `0` or `false` disables a
flag; an unset flag uses its declared default (or a recognized preset).
Enabling a flag does not bypass tool availability or
workflow-specific prerequisites.

Named presets (e.g. `fp-moat`) are defined in `src/agent/feature-presets.ts`.
Applying a preset never overwrites a flag already set in the environment.

## Playbooks

Playbooks live in `src/agent/playbooks.ts`. Each playbook is a string keyed by
vulnerability type (`sqli`, `ssti`, `idor`, `xss`, `cve_exploitation`, …) plus
a set of regex `INDICATORS` that pattern-match against recent tool-result text.
When `ZERO_FEATURE_DYNAMIC_PLAYBOOKS=1`, the native agent loop matches
indicators from about 30% of the turn budget onward and injects matching
playbooks. It tracks injected content and can re-inject after compaction;
this is not a mandatory one-shot phase of every loop.

## Agent runtimes

The package provides multiple LLM runtime backends in `src/runtime/`:

- **LlmApiRuntime** — direct API requests and native tool-use loops.
- **ProcessRuntime** — subprocess adapters for Claude and Codex CLIs.
- **CliNativeRuntime** — CLI-native session execution.

`createRuntime(config)` constructs the API or process runtime from
`config.type`. Other exported adapters have their own constructors.
`pickRuntimeForStage` and `detectAvailableRuntimes` are registry helpers.
Provider metadata does not establish credentials or account access.

## Verification

`src/verifier/` and `src/verification-spec/` hold the verification contracts and
checks that a finding goes through. Use the canonical `VerificationResultSchema`
from `@0/engine/shared` for replay JSON: `reproduced`, `not_reproduced`,
`skipped`, or `error`, with declared assertions and hashed artifact descriptors.
A source finding, model consensus or a saved candidate is not automatically
runtime proof.

## Plugin system

`src/plugins/extensions/` holds the extension adapters: MCP servers, connectors
and the installer. See [Extensions](https://docs.0.security/extensions/).

## Development

From the repository root:

```bash
pnpm --filter '@0/engine...' build
pnpm --filter @0/engine test
pnpm --filter @0/engine test -- feature-presets
pnpm --filter @0/engine dev
```

Build assets live in `scripts/`: `generate-skills-manifest.mjs` compiles the
skills directory into a TypeScript manifest, `copy-build-assets.mjs` copies
non-compiled assets into `dist/`.