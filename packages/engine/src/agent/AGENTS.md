# agent/ — engine agent loop & tools

Area context for `packages/engine/src/agent/`: the native agent loop
(`native-loop.ts`, `native-loop/`), the tool surface (`tools.ts`, `tools/`) and
the core toolset (`toolset.ts`; see `docs/design/core-toolset.md`).

## Rules for any tool or loop added here

- **Validate every model submission.** Parse tool arguments against an explicit
  Zod schema and reject a mismatch before any side effect (subprocess, DB
  write). Feed the rejection back as an `is_error` tool result so the model can
  correct itself. `.strip()` unknown top-level keys that must never propagate
  downstream (for example `argv`, `cwd`, `args`).
- **Enforce bounds in the schema**, not ad hoc at the call site: sizes, enums,
  attempt and turn caps.
- **Keep sub-steps small.** A sub-step gets only the tools it needs; refuse the
  rest explicitly in the loop instead of hiding them from the model.
- **Feed real signal, not blind retries.** A retry prompt carries what the last
  attempt actually produced.
