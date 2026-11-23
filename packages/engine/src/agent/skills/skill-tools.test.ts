import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ToolExecutor, TOOL_DEFINITIONS, getToolsForRole } from "../tools.js";
import { clearSkillRegistry, loadSkillRegistry } from "./index.js";
import type { ToolContext } from "../types.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

/**
 * Build a minimal ToolContext for skill-tool tests. Skills only need
 * `role`, `recentToolResultTexts`, and `loadedSkills` — the rest are
 * stubs so the ToolExecutor constructor doesn't complain.
 */
function makeCtx(overrides?: Partial<ToolContext>): ToolContext {
  return {
    target: "http://localhost:1234",
    scanId: "test-scan",
    findings: [],
    attackResults: [],
    targetInfo: {},
    role: "attack",
    skillDiscoveryOptions: { homeDir: null },
    ...overrides,
  };
}

describe("Skill Tools (#457)", () => {
  let savedJitSkills: string | undefined;

  beforeEach(() => {
    savedJitSkills = process.env["ZERO_FEATURE_JIT_SKILLS"];
    process.env["ZERO_FEATURE_JIT_SKILLS"] = "1";
    clearSkillRegistry();
    loadSkillRegistry(__dirname);
  });

  afterEach(() => {
    if (savedJitSkills === undefined) delete process.env["ZERO_FEATURE_JIT_SKILLS"];
    else process.env["ZERO_FEATURE_JIT_SKILLS"] = savedJitSkills;
    clearSkillRegistry();
  });

  it.each(["discovery", "verify", "report"])("allows %s agents to load standard folder skills", async (role) => {
    const root = mkdtempSync(join(tmpdir(), "zero-skill-role-"));
    try {
      mkdirSync(join(root, "evidence-review"));
      writeFileSync(join(root, "evidence-review", "SKILL.md"), "---\nname: evidence-review\ndescription: Review collected evidence.\n---\nConfirm the evidence supports each finding.");
      expect(getToolsForRole().map((tool) => tool.name)).toContain("load_skill");
      const executor = new ToolExecutor(makeCtx({ role, skillDiscoveryOptions: { homeDir: null, mounts: [{ path: root, id: "shared" }] } }));
      const loaded = await executor.execute({ name: "load_skill", arguments: { skill_id: "mount/shared/evidence-review" } });
      expect(loaded.success).toBe(true);
      expect((loaded.output as { content: string }).content).toContain("Confirm the evidence");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  // ── load_skill ──────────────────────────────────────────────────

  describe("load_skill", () => {
    it("returns skill content for a valid skill ID", async () => {
      const executor = new ToolExecutor(
        makeCtx({ loadedSkills: new Set() }),
      );
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "sqli-advanced" },
      });

      expect(result.success).toBe(true);
      const output = result.output as {
        kind: string;
        skill_id: string;
        name: string;
        content: string;
        estimated_tokens: number;
      };
      expect(output.kind).toBe("skill_loaded");
      expect(output.skill_id).toBe("sqli-advanced");
      expect(output.name).toBe("Advanced SQL Injection");
      expect(typeof output.content).toBe("string");
      expect(output.content.length).toBeGreaterThan(0);
      expect(output.estimated_tokens).toBeGreaterThan(0);
    });

    it("refuses double-load for already loaded skills", async () => {
      const loaded = new Set(["sqli-advanced"]);
      const executor = new ToolExecutor(makeCtx({ loadedSkills: loaded }));
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "sqli-advanced" },
      });

      expect(result.success).toBe(true);
      const output = result.output as { kind: string; message: string };
      expect(output.kind).toBe("already_loaded");
      expect(output.message).toBe("Skill already loaded");
    });

    it("loads an agent skill by its short name and refuses double-load under both names", async () => {
      const root = mkdtempSync(join(tmpdir(), "zero-skill-short-"));
      try {
        mkdirSync(join(root, "evidence-review"));
        writeFileSync(join(root, "evidence-review", "SKILL.md"), "---\nname: evidence-review\ndescription: Review collected evidence.\n---\nConfirm the evidence supports each finding.");
        const executor = new ToolExecutor(makeCtx({ role: "audit", skillDiscoveryOptions: { homeDir: null, mounts: [{ path: root, id: "shared" }] } }));
        const loaded = await executor.execute({ name: "load_skill", arguments: { skill_id: "evidence-review" } });
        expect(loaded.success).toBe(true);
        expect((loaded.output as { content: string }).content).toContain("Confirm the evidence");
        expect((loaded.output as { name: string }).name).toBe("evidence-review");

        // Refuse double load using the namespaced ID
        const second = await executor.execute({ name: "load_skill", arguments: { skill_id: "mount/shared/evidence-review" } });
        expect(second.success).toBe(true);
        expect((second.output as { kind: string }).kind).toBe("already_loaded");
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    });

    describe("allow-lists and same-named folder skills", () => {
      const folderSkill = (root: string, name: string, body: string) => {
        mkdirSync(join(root, name), { recursive: true });
        writeFileSync(join(root, name, "SKILL.md"), `---\nname: ${name}\ndescription: A folder skill named ${name}.\n---\n${body}`);
      };
      const load = async (executor: ToolExecutor, skill_id: string) => executor.execute({ name: "load_skill", arguments: { skill_id } });

      it("does not load an extension skill named scan under an allow-list of scan", async () => {
        const root = mkdtempSync(join(tmpdir(), "zero-skill-scan-"));
        try {
          folderSkill(root, "scan", "EXTENSION SCAN TEXT");
          const skillDiscoveryOptions = { homeDir: null, extensionRoots: [{ extension: "demo", revision: "r1", folder: root }], allowedSkillIds: ["scan"] };
          const executor = new ToolExecutor(makeCtx({ role: "audit", skillDiscoveryOptions }));
          const byId = await load(executor, "extension/demo/scan");
          expect(byId.success).toBe(false);
          expect(byId.error).toContain("allow-list");
          // The bare name is the built-in skill, never the folder's.
          const byName = await load(executor, "scan");
          expect(byName.success).toBe(true);
          expect(JSON.stringify(byName.output)).not.toContain("EXTENSION SCAN TEXT");
        } finally {
          rmSync(root, { recursive: true, force: true });
        }
      });

      it("does not let an allow-list of a namespaced skill permit the built-in with the same name", async () => {
        const root = mkdtempSync(join(tmpdir(), "zero-skill-builtin-"));
        try {
          folderSkill(root, "secrets-hunting", "EXTENSION TEXT");
          const skillDiscoveryOptions = { homeDir: null, extensionRoots: [{ extension: "foo", revision: "r1", folder: root }], allowedSkillIds: ["extension/foo/secrets-hunting"] };
          const executor = new ToolExecutor(makeCtx({ role: "audit", skillDiscoveryOptions }));
          const builtIn = await load(executor, "secrets-hunting");
          expect(builtIn.success).toBe(false);
          expect(builtIn.error).toContain("allow-list");
          expect((await load(executor, "extension/foo/secrets-hunting")).success).toBe(true);
        } finally {
          rmSync(root, { recursive: true, force: true });
        }
      });

      it("does not pick between two folder skills with the same name", async () => {
        const a = mkdtempSync(join(tmpdir(), "zero-skill-a-")), b = mkdtempSync(join(tmpdir(), "zero-skill-b-"));
        try {
          folderSkill(a, "lint-rules", "FROM A");
          folderSkill(b, "lint-rules", "FROM B");
          const skillDiscoveryOptions = { homeDir: null, mounts: [{ path: a, id: "a" }, { path: b, id: "b" }] };
          const executor = new ToolExecutor(makeCtx({ role: "audit", skillDiscoveryOptions }));
          const bare = await load(executor, "lint-rules");
          expect(bare.success).toBe(false);
          expect(bare.error).toContain("mount/a/lint-rules");
          expect(bare.error).toContain("mount/b/lint-rules");
          const full = await load(executor, "mount/b/lint-rules");
          expect(full.success).toBe(true);
          expect(JSON.stringify(full.output)).toContain("FROM B");
        } finally {
          rmSync(a, { recursive: true, force: true });
          rmSync(b, { recursive: true, force: true });
        }
      });
    });

    it("tracks loaded skills across consecutive calls", async () => {
      const ctx = makeCtx({ loadedSkills: new Set() });
      const executor = new ToolExecutor(ctx);

      // First load — should succeed
      const first = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "jwt-attacks" },
      });
      expect(first.success).toBe(true);
      expect((first.output as { kind: string }).kind).toBe("skill_loaded");

      // Second load of same skill — should return already_loaded
      const second = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "jwt-attacks" },
      });
      expect(second.success).toBe(true);
      expect((second.output as { kind: string }).kind).toBe("already_loaded");
    });

    it("initializes loadedSkills set when ctx has none", async () => {
      // ctx.loadedSkills is undefined (not pre-initialized)
      const ctx = makeCtx();
      expect(ctx.loadedSkills).toBeUndefined();

      const executor = new ToolExecutor(ctx);
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "prototype-pollution" },
      });

      expect(result.success).toBe(true);
      expect(ctx.loadedSkills).toBeDefined();
      expect(ctx.loadedSkills!.has("prototype-pollution")).toBe(true);
    });

    it("returns error for unknown skill ID", async () => {
      const executor = new ToolExecutor(
        makeCtx({ loadedSkills: new Set() }),
      );
      const result = await executor.execute({
        name: "load_skill",
        arguments: { skill_id: "nonexistent-skill-xyz" },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Unknown skill ID");
      expect(result.error).toContain("nonexistent-skill-xyz");
    });

    it("lists the available skills when skill_id is missing", async () => {
      const executor = new ToolExecutor(makeCtx());
      const result = await executor.execute({
        name: "load_skill",
        arguments: {},
      });

      expect(result.success).toBe(true);
      expect(JSON.stringify(result.output)).toContain("sqli-advanced");
    });
  });

  // ── Tool definitions exist in TOOL_DEFINITIONS ──────────────────

  describe("tool definitions", () => {

    it("load_skill is defined in TOOL_DEFINITIONS", () => {
      expect(TOOL_DEFINITIONS.load_skill).toBeDefined();
      expect(TOOL_DEFINITIONS.load_skill.name).toBe("load_skill");
      expect(TOOL_DEFINITIONS.load_skill.parameters.skill_id).toBeDefined();
      expect(TOOL_DEFINITIONS.load_skill.required ?? []).toEqual([]);
    });
  });
});
