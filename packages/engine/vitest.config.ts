import { defineConfig } from "vitest/config";
import { osecWorkspaceAliases } from "../../scripts/config/vitest.workspace-aliases.ts";

// These files start real containers and each asserts that none labelled `0.verify=1` is left behind. They share
// that label, so two of them running at once would see each other's live containers. Run them one file at a time.
const DOCKER_FILES = [
  "src/executed-poc/executed-poc.docker.integration.test.ts",
  "src/reproduction/harness.integration.test.ts",
  "src/verifier/docker-runner.integration.test.ts",
  "src/verifier/docker-runner.maven.integration.test.ts",
];

const shared = {
  // Threads and scans read Memory only when a test opts in; never touch the real ~/.0/memory.
  env: { ZERO_DISABLE_MEMORY: "1" },
  // Persistence suites perform real fsync/SQLite round trips, not mocked I/O.
  // Their default deadline must tolerate shared-runner disk contention;
  // tests of actual runtime deadlines retain their explicit timeouts.
  testTimeout: 30_000,
};

export default defineConfig({
  resolve: {
    alias: osecWorkspaceAliases,
  },
  test: {
    // Keep native-addon and SQLite work bounded on the shared CI runner; use the cores on a developer machine.
    maxWorkers: process.env.CI ? 2 : undefined,
    projects: [
      { extends: true, test: { ...shared, name: "unit", include: ["src/**/*.test.ts"], exclude: DOCKER_FILES } },
      { extends: true, test: { ...shared, name: "docker", include: DOCKER_FILES, fileParallelism: false } },
    ],
  },
});
