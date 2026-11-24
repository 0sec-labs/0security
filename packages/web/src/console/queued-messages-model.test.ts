import { describe, expect, it } from "vitest";
import { queueState } from "./queued-messages-model";

const snap = (status: string, queuePausedReason?: "stopped" | "error" | "restored") =>
  ({ session: { status }, queuePausedReason }) as Parameters<typeof queueState>[0];

describe("queueState", () => {
  it("says the message sends after the response while a turn is running", () => {
    const state = queueState(snap("working"));
    expect(state.kind).toBe("waiting");
    expect(state.label).toBe("Queued · sends after the current response");
    expect(state.sendNowHint).toMatch(/Interrupt/);
  });

  it("does not call an idle thread paused unless the gateway holds the queue", () => {
    const state = queueState(snap("ready"));
    expect(state.kind).toBe("waiting");
    expect(state.label).not.toMatch(/paused/i);
  });

  it("names why the queue is paused", () => {
    expect(queueState(snap("ready", "stopped")).label).toBe("Paused because you stopped the turn. Send now to continue");
    expect(queueState(snap("failed", "error")).label).toMatch(/^Paused because the last turn failed/);
    expect(queueState(snap("ready", "restored")).kind).toBe("paused");
  });
});
