import { defineConfig } from "vitest/config";
import { osecWorkspaceAliases } from "../../scripts/config/vitest.workspace-aliases.ts";

// Restrict discovery to source tests (mirrors packages/engine/vitest.config.ts) —
// without an explicit include, vitest's default glob also picks up compiled
// test files under dist/, running everything twice.
//
// Raise the global timeout: the CLI suite's transform load is heavy
// (chat-screen.tsx et al.), so under a full `vitest run` a test doing real work
// mid-run (e.g. findings.ts's per-action `await import("@0/engine/storage")`) can exceed
// vitest's 5s default even though it passes in ~4s alone.
export default defineConfig({
  // The key-gated enterprise package resolves to its source, so tests do not depend on its dist output.
  resolve: { alias: { "@0/enterprise": osecWorkspaceAliases["@0/enterprise"] } },
  test: {
    include: ["src/**/*.test.{ts,tsx}", "test/e2e/**/*.test.ts"],
    testTimeout: 20_000,
    // Threads and scans read Memory only when a test opts in; never touch the real ~/.0/memory.
    env: { ZERO_DISABLE_MEMORY: "1" },
  },
});
