# Code index

Per-repo index behind the `code-index` tool pack: `callers_of`, `callees_of`, `routes`, `trace_to_sink`. Principles:
[tool-philosophy.md](tool-philosophy.md); toolset: [core-toolset.md](core-toolset.md).

## What it is

- Symbols, a name-based call graph, HTTP routes with their middleware, and sink calls (command, code-eval, sql, file,
  network, deserialize, template, redirect) for TypeScript, JavaScript and Python.
- Built offline from the granted folder. Cached in memory per root, commit and working-tree state (commit plus the
  stat of every indexed file), so an edit or a new commit gives a new index.
- Loaded by skills (`seedless-depth-review`, `verify-finding`) through `tools: [code-index]`, not part of the core list. The main session and any subagent get the four tools on the turn after `load_skill` of such a skill, never before; a child does not inherit them from its parent, and a restricted worker tool list or workflow phase keeps them out. `ZERO_TOOLSET=full` (opt-in everything list) advertises them up front.
- Not data flow. A path is a lead; the model reads each hop with `cat -n` before it claims a finding. Unsupported
  languages, unknown symbols and a missing folder return a soft result that points back to `rg`.

## Backends

1. Foxguard, when a binary with `foxguard graph` is found (`ZERO_FOXGUARD_PATH`, then `PATH`). Probed once with
   `foxguard graph --help` for the text `schema version 1`; output is validated with Zod and falls back on any failure.
2. The built-in extractor (`packages/engine/src/code-index/extract-*.ts`): comment and string masking plus
   brace and indentation matching. It exists so the tools work without Foxguard and is the fallback.

## `foxguard graph <path> [--missing-guard] [--output file]` (schema version 1)

```json
{
  "version": 1,
  "producer": "foxguard",
  "root": "/abs/path",
  "files": 4,
  "symbols": [{ "id": "src/a.ts#Class.method@12", "name": "method", "qualified": "Class.method",
                "kind": "function|method|route-handler|module", "file": "src/a.ts", "line": 12, "endLine": 20,
                "language": "javascript|python" }],
  "calls": [{ "from": "<symbol id>", "name": "query", "text": "db.query", "file": "src/a.ts", "line": 14,
              "sink": { "category": "sql", "text": "db.query" } }],
  "routes": [{ "method": "GET", "path": "/notes/:id", "file": "src/routes.ts", "line": 9,
               "handler": "<symbol id> | ref:<name> | unresolved:<name>", "middleware": ["requireAuth"],
               "framework": "express-like|flask-fastapi|django|nest", "missingGuard": false }],
  "taintSummaries": [],
  "unsupported": { "go": 3 },
  "truncated": false
}
```

- `missingGuard` is present only with `--missing-guard`: no auth-like name on the middleware or within three call hops.
- `taintSummaries` is reserved for the per-function summaries in `rules/cross_file.rs` (`paramsToReturn`,
  `paramsToSink`) and is empty in version 1. Source-to-sink path search stays in the consumer (`trace_to_sink`).
- The Foxguard v1 emits `express-like` and `flask-fastapi` routes; `nest` and `django` come from the built-in extractor only.
- A reader must ignore unknown keys and reject a `version` it does not know.

## Dependencies

The Foxguard side is `docs/design/code-index-foxguard.patch` (paths under `crates/foxguard/`), written against the
Foxguard tree that `feat/merge-foxguard` imports. It is not applied by this change. Without it the built-in extractor
runs, so the tools work either way.
