import { describe, expect, it } from "vitest";
import { buildNextMoveRequest, MAX_REQUEST_BYTES } from "./next-move.js";

const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;
const base = { objective: { goal: "get the agent to send the marker" }, turn: 9, maxTurns: 10, calls: [] as { tool: string; privilege: string; args: Record<string, unknown> }[] };

describe("buildNextMoveRequest size budget", () => {
  it("keeps a long conversation under the budget by dropping the oldest entries first", () => {
    // Multi-byte text makes each 2000-character entry far heavier than 2000 bytes.
    const history = Array.from({ length: 40 }, (_, i) => ({ role: (i % 2 ? "agent" : "attacker") as "agent" | "attacker", text: `${i}:` + "é".repeat(1999) }));
    const request = buildNextMoveRequest({ ...base, history });
    expect(bytes(request)).toBeLessThanOrEqual(MAX_REQUEST_BYTES);
    expect(request.history.length).toBeLessThan(40);
    expect(request.history.length).toBeGreaterThan(5);
    expect(request.history[request.history.length - 1]!.text.startsWith("39:")).toBe(true);
    expect(request.history[0]!.text.startsWith("0:")).toBe(false);
  });

  it("leaves a short conversation untouched", () => {
    const history = [{ role: "attacker" as const, text: "hello" }, { role: "agent" as const, text: "hi" }];
    expect(buildNextMoveRequest({ ...base, history }).history).toEqual(history);
  });

  it("always keeps the newest entry, clipped if it alone is too large", () => {
    const calls = Array.from({ length: 200 }, (_, i) => ({ tool: `tool_${i}`, privilege: "source", args: { a: "x".repeat(200), b: "y".repeat(200), c: "z".repeat(200) } }));
    const request = buildNextMoveRequest({ ...base, calls, history: [{ role: "agent", text: "é".repeat(5000) }] });
    expect(request.history).toHaveLength(1);
    expect(request.history[0]!.text.length).toBeGreaterThan(0);
  });
});
