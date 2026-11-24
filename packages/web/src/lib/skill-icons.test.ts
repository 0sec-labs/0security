import { describe, expect, it } from "vitest";
import { SKILL_ICONS } from "@/components/skills/cells";
import { DEFAULT_SKILL_ICON, matchSkillIcon, SKILL_FAMILIES, skillIconName } from "./skill-icons";

/** Every built-in skill id, read from the engine skill sources. */
const yamls = import.meta.glob<string>("../../../engine/src/agent/skills/*/*.yaml", { query: "?raw", import: "default", eager: true });
const builtinIds = Object.values(yamls).map(yaml => /^id:\s*(\S+)/m.exec(yaml)![1]!);
const make = (id: string, scope = "builtin", category?: string) => ({ id, name: id, scope, ...(category ? { category } : {}) });

describe("skillIconName", () => {
  it("finds the built-in skills on disk", () => { expect(builtinIds.length).toBeGreaterThan(40); });
  it("gives every built-in skill a topic icon, never the default", () => {
    for (const id of builtinIds) expect(skillIconName(make(id)), id).not.toBe(DEFAULT_SKILL_ICON);
    for (const id of builtinIds) expect(skillIconName(make(`builtin/${id}`)), id).toBe(skillIconName(make(id)));
  });
  it("lists no id that is not a built-in skill", () => {
    const known = new Set(builtinIds);
    for (const family of SKILL_FAMILIES) for (const id of family.ids) expect(known.has(id), id).toBe(true);
  });
  it("uses one icon per family, so two families are never confusable", () => {
    const icons = SKILL_FAMILIES.map(family => family.icon);
    expect(new Set(icons).size).toBe(icons.length);
    expect(icons).not.toContain(DEFAULT_SKILL_ICON);
  });
  it("has a component for every icon name", () => {
    for (const family of SKILL_FAMILIES) expect(SKILL_ICONS[family.icon], family.icon).toBeTruthy();
    expect(SKILL_ICONS[DEFAULT_SKILL_ICON]).toBeTruthy();
  });
  it("maps the injection classes to their own glyphs", () => {
    expect(skillIconName(make("command-injection"))).toBe("Terminal");
    expect(skillIconName(make("structural-sqli"))).toBe("Database");
    expect(skillIconName(make("ssti-exploitation"))).toBe("Braces");
    expect(skillIconName(make("secrets-hunting"))).toBe("KeyRound");
    expect(skillIconName(make("llm-prompt-injection"))).toBe("MessageSquareWarning");
  });
  it("falls back to keywords for a skill that is not in the table, and to the default last", () => {
    expect(skillIconName(make("new-terraform-pack", "builtin"))).toBe("Boxes");
    expect(skillIconName({ id: "x", name: "Kubernetes hardening", scope: "workspace" })).toBe("Cloud");
    expect(skillIconName(make("zzz", "builtin"))).toBe(DEFAULT_SKILL_ICON);
  });
  it("matches whole words only", () => {
    expect(matchSkillIcon({ id: "email-notes", name: "email notes" })).toBeUndefined();
    expect(matchSkillIcon({ id: "ai-notes", name: "AI notes" })).toBe("Bot");
  });
  it("applies the id table to built-ins only", () => {
    expect(skillIconName(make("variant-hunting"))).toBe("Files");
    expect(skillIconName({ id: "bake", name: "bake", scope: "workspace" })).toBe(DEFAULT_SKILL_ICON);
  });
});
