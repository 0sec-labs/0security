import { describe, expect, it } from "vitest";
import type { ConsoleWorker } from "@0/engine/shared";
import { scanPrompt } from "@0/engine/shared";
import { summarizeConsoleWorker } from "./console-snapshot-window.js";

const worker = (telemetry: ConsoleWorker["telemetry"]): ConsoleWorker => ({ id: "w", parentId: "p", name: "n", status: "completed", task: "t", transcript: [{ turn: 1, ts: 1, tools: [{ callIndex: 0, call: {} as never, result: null }] }], telemetry });

describe("worker summaries", () => {
  it("keep the token counts of the nested usage as scalars", () => {
    const summary = summarizeConsoleWorker(worker({ turns: 4, usage: { inputTokens: 120, outputTokens: 30, cachedInputTokens: 5 } }));
    expect(summary.telemetry).toMatchObject({ turns: 4, inputTokens: 120, outputTokens: 30 });
    expect(summary).toMatchObject({ turnCount: 1, toolCallCount: 1 });
  });
  it("ignore a usage that is not numbers", () => {
    expect(summarizeConsoleWorker(worker({ usage: { inputTokens: "many", outputTokens: -1 } })).telemetry).toEqual({});
  });
});

describe("scan prompt", () => {
  it("asks for poc_steps only where a safe check exists, in every skill", () => {
    for (const skill of ["scan", "seedless-depth-review"]) {
      const prompt = scanPrompt("repo", skill);
      expect(prompt).toMatch(/high or critical finding with a safe, shell-reproducible check, also set poc_steps \(never network access, nothing outside the folder\)/);
    }
  });
});
