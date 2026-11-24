import { describe, expect, it } from "vitest";
import type { ConsoleSessionSnapshot, DesktopConsoleEvent } from "@0/engine/shared";
import { reduceConversation } from "./transcript";
import { changesMessages, openSnapshotTime, OPEN_FRESH_MS } from "./workspace-events";

const ev = (sequence: number, rest: object) => ({ sequence, occurredAt: "2026-01-01T00:00:00Z", ...rest }) as unknown as DesktopConsoleEvent;
const snapshot = (messages: unknown[], events: DesktopConsoleEvent[]) =>
  ({ session: { id: "s", status: "ready" }, cursor: 20, messages, events, pendingDecisions: [], workers: [], queuedMessages: [], lastOutcome: null }) as unknown as ConsoleSessionSnapshot;

const first = [{ role: "user", content: [{ type: "text", text: "yoyo" }] }, { role: "assistant", content: [{ type: "text", text: "first reply" }] }];
const turnOne = [ev(1, { type: "user", text: "yoyo" }), ev(2, { type: "assistant-delta", text: "first reply" }), ev(3, { type: "turn-complete", stopReason: "end_turn", assistantText: "first reply" })];
const turnTwo = [ev(4, { type: "user", text: "second" }), ev(5, { type: "assistant-delta", text: "second reply" }), ev(6, { type: "turn-complete", stopReason: "end_turn", assistantText: "second reply" })];

describe("messages that lag behind the event journal", () => {
  it("keeps a turn that only the journal knows about", () => {
    const turns = reduceConversation(snapshot(first, [...turnOne, ...turnTwo]));
    expect(turns.map((turn) => [turn.user.text, turn.assistantText])).toEqual([["yoyo", "first reply"], ["second", "second reply"]]);
  });
  it("keeps it when the journal was trimmed to the newest turn", () => {
    const turns = reduceConversation(snapshot(first, turnTwo));
    expect(turns.map((turn) => [turn.user.text, turn.assistantText])).toEqual([["yoyo", "first reply"], ["second", "second reply"]]);
  });
  it("does not duplicate a turn the messages already have", () => {
    const messages = [...first, { role: "user", content: [{ type: "text", text: "second" }] }, { role: "assistant", content: [{ type: "text", text: "second reply" }] }];
    expect(reduceConversation(snapshot(messages, [...turnOne, ...turnTwo]))).toHaveLength(2);
  });
});

describe("opening a cached snapshot", () => {
  it("trusts only a snapshot read a moment ago", () => {
    expect(openSnapshotTime(10_000, 10_000 + OPEN_FRESH_MS)).toBe(10_000);
    expect(openSnapshotTime(10_000, 10_000 + OPEN_FRESH_MS + 1)).toBe(0);
  });
  it("sees which events change the message list", () => {
    expect(changesMessages([ev(1, { type: "assistant-delta", text: "x" })])).toBe(false);
    expect(changesMessages([ev(1, { type: "assistant-delta", text: "x" }), ev(2, { type: "user", text: "y" })])).toBe(true);
    expect(changesMessages([ev(1, { type: "turn-complete" })])).toBe(true);
  });
});
