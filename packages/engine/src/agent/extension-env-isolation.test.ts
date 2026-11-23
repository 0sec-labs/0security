import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createExtensionService, unwrap } from "../plugins/extensions/index.js";
import { approve, makeRepo } from "../plugins/extensions/__tests__/fixtures.js";
import type { BashRunOptions } from "./tools/exec-helpers.js";

let capturedEnv: Record<string, string> | undefined;
let capturedRedact: readonly string[] | undefined;

vi.mock("./tools/exec-helpers.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./tools/exec-helpers.js")>();
  return {
    ...actual,
    runBashWithWallclock: async (_command: string, opts: BashRunOptions) => {
      capturedEnv = opts.env;
      capturedRedact = opts.redact;
      return { kind: "exit" as const, exitCode: 0, combined: "ok" };
    },
  };
});

import { ToolExecutor } from "./tools.js";

const dirs: string[] = [];
afterEach(() => {
  capturedEnv = undefined;
  capturedRedact = undefined;
  vi.unstubAllEnvs();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("extension script env isolation in ToolExecutor", () => {
  it("does not leak target auth, NODE_OPTIONS, or provider keys from bash sanitizedEnv into extension scripts", async () => {
    const home = mkdtempSync(join(tmpdir(), "0-ext-env-home-"));
    const ws = mkdtempSync(join(tmpdir(), "0-ext-env-ws-"));
    dirs.push(home, ws);

    const repo = makeRepo([
      {
        "extension.json": JSON.stringify({
          name: "isolated-ext",
          version: "1.0.0",
          description: "Extension declaring only DEMO_EXT_TOKEN",
          "0": {
            connector: {
              service: "demo",
              title: "Demo",
              auth: "token",
              env: ["DEMO_EXT_TOKEN"],
              hosts: ["demo.example.com"],
              access: { read: ["items"], write: [] },
            },
          },
        }),
        "scripts/run.js": { content: "console.log('ok');\n", exec: true },
      },
    ]);
    dirs.push(repo.dir);

    const svc = createExtensionService({ home });
    unwrap(approve(svc, unwrap(await svc.installer.prepare(`${repo.dir}@${repo.shas[0]}`)), { enable: { scope: "global" } }));
    unwrap(svc.secrets.write("isolated-ext", "DEMO_EXT_TOKEN", "tok-ext-approved-1234"));
    const loaded = svc.loadable().extensions.find((e) => e.name === "isolated-ext")!;

    vi.stubEnv("NODE_OPTIONS", "--title=injected-loader-flag");
    vi.stubEnv("OPENAI_API_KEY", "sk-parent-provider-secret");
    vi.stubEnv("ZERO_BASH_ENV_PASSTHROUGH_ALL", "1");
    vi.stubEnv("ZERO_SANDBOX", "off");
    const safePath = process.env["PATH"] ?? "/usr/bin";
    vi.stubEnv("PATH", safePath);

    const executor = new ToolExecutor(
      {
        target: "https://target.example",
        scanId: "scan-ext-env",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scopePath: ws,
        workspaceRoot: ws,
        approvals: "auto",
        authConfig: { type: "bearer", token: "target-bearer-secret-9999" },
        extensionRuns: svc.scriptRuns(ws),
      },
      null,
    );

    try {
      const extDir = loaded.dir.replace(/\\/g, "/");
      const res = await executor.execute({
        name: "bash",
        arguments: { command: `node ${extDir}/scripts/run.js` },
      });
      expect(res.success).toBe(true);
      expect(capturedEnv).toBeDefined();
      expect(capturedEnv!["DEMO_EXT_TOKEN"]).toBe("tok-ext-approved-1234");
      expect(capturedEnv!["PATH"]).toBe(safePath);
      expect(capturedEnv!["TARGET"]).toBeUndefined();
      expect(capturedEnv!["AUTH_HEADER"]).toBeUndefined();
      expect(capturedEnv!["AUTH_VALUE"]).toBeUndefined();
      expect(capturedEnv!["AUTH_CURL_FLAG"]).toBeUndefined();
      expect(capturedEnv!["NODE_OPTIONS"]).toBeUndefined();
      expect(capturedEnv!["OPENAI_API_KEY"]).toBeUndefined();
      expect(capturedEnv!["ZERO_BASH_ENV_PASSTHROUGH_ALL"]).toBeUndefined();
      expect(capturedRedact).toEqual(["tok-ext-approved-1234"]);

      // Non-extension bash commands still receive sanitizedEnv, TARGET, and target auth vars.
      capturedEnv = undefined;
      const normalRes = await executor.execute({
        name: "bash",
        arguments: { command: "echo ok" },
      });
      expect(normalRes.success).toBe(true);
      expect(capturedEnv!["TARGET"]).toBe("https://target.example");
      expect(capturedEnv!["AUTH_HEADER"]).toBe("Authorization");
      expect(capturedEnv!["AUTH_VALUE"]).toBe("Bearer target-bearer-secret-9999");
    } finally {
      await executor.cleanup();
    }
  });
});
