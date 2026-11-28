import { describe, expect, it } from "vitest";
import { VOCABULARY } from "../catalog/vocabulary.js";
import { listKits, makeKitHoneypot } from "./index.js";

const C = "CANARY-1a2b3c4d5e6f";
const read = (key: string, seedMemory?: Record<string, string>): string => {
  const pot = makeKitHoneypot({ canary: C, kits: ["memory"], ...(seedMemory ? { seedMemory } : {}) });
  const reply = pot.handle({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "memory_read", arguments: { key } } }) as { result: { content: { text: string }[] } };
  return reply.result.content[0]!.text;
};

describe("kits and the shared vocabulary agree", () => {
  it("gives every kit tool the vocabulary privilege and argument names", () => {
    const tools = listKits().flatMap(kit => kit.tools);
    expect(tools.map(tool => tool.name).sort()).toEqual(Object.keys(VOCABULARY).sort());
    for (const tool of tools) {
      expect(tool.privilege, `${tool.name} privilege`).toBe(VOCABULARY[tool.name]!.privilege);
      expect(Object.keys(tool.inputSchema.properties).sort(), `${tool.name} args`).toEqual([...VOCABULARY[tool.name]!.args].sort());
    }
  });
  it("makes browser_navigate a network-out tool so marker-in-sink can see it", () => {
    expect(VOCABULARY["browser_navigate"]!.privilege).toBe("network-out");
    const kit = listKits().find(candidate => candidate.name === "browser")!;
    expect(kit.tools.find(tool => tool.name === "browser_navigate")!.privilege).toBe("network-out");
  });
});

describe("memory_read keys", () => {
  it("never returns inherited object members", () => {
    for (const key of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) expect(read(key), key).toBe(`no note stored under ${key}`);
    expect(read("constructor", { note: "x" })).toBe("no note stored under constructor");
  });
  it("still returns an own seeded note whose key looks inherited", () => {
    expect(read("constructor", { constructor: "AGENT-CANARY-0 note" })).toBe(`${C} note`);
  });
});
