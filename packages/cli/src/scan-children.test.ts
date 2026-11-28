import { describe, expect, it } from "vitest";
import { childrenOf, MAX_CHILD_ITEMS, summarizeChildren } from "./scan-children.js";

describe("childrenOf", () => {
  it("reads summary rows and strips control characters, clips long text and unsafe ids", () => {
    const [row] = childrenOf({ workers: [{ id: "a b/../c", name: "x".repeat(200), status: "completed", task: `t\u0000\n${"y".repeat(500)}`, summary: "z".repeat(900), telemetry: { turns: 2 }, turnCount: 9, toolCallCount: 4 }] });
    expect(row!.id).toBe("ab..c");
    expect(row!.name).toHaveLength(80);
    expect(row!.scope).toHaveLength(240);
    expect(row!.scope.startsWith("t y")).toBe(true);
    expect(row!.result).toHaveLength(300);
    expect(row).toMatchObject({ turns: 2, toolCalls: 4 });
  });
  it("falls back to full worker transcripts and nested usage, and ignores junk", () => {
    const rows = childrenOf({ workers: [{ id: "w", status: "running", task: "t", transcript: [{}, {}], telemetry: { usage: { inputTokens: 5, outputTokens: 6 } } }, null, { status: "x" }, "no"] });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ turns: 2, inputTokens: 5, outputTokens: 6 });
    expect(childrenOf({})).toEqual([]);
  });
});

describe("summarizeChildren", () => {
  it("is undefined without helpers, counts a repeated helper once and caps the list", () => {
    expect(summarizeChildren([[], []])).toBeUndefined();
    const one = { id: "a", status: "completed", scope: "s", turns: 1, toolCalls: 1 };
    expect(summarizeChildren([[one], [one]])).toMatchObject({ count: 1, turns: 1 });
    const many = Array.from({ length: MAX_CHILD_ITEMS + 5 }, (_, i) => ({ id: `w${i}`, status: "completed", scope: "s" }));
    const sum = summarizeChildren([many])!;
    expect(sum.count).toBe(MAX_CHILD_ITEMS + 5);
    expect(sum.items).toHaveLength(MAX_CHILD_ITEMS);
    expect(sum.omitted).toBe(5);
    expect(sum.inputTokens).toBeUndefined();
  });
});
