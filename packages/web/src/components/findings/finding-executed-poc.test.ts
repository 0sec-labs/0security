import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { executedPocView } from "./finding-executed-poc";
import { ExecutedPocChip, ExecutedPocSection } from "./finding-executed-poc-view";

const base = { schemaVersion: 1, harness: "0security-executed-poc/1", stepIds: ["p1"], startedAt: "2026-01-01T00:00:00.000Z", finishedAt: "2026-01-01T00:00:02.000Z" };
const run = (status: string, extra: Record<string, unknown> = {}) => ({ status, reason: "x", command: "sh app.sh", isolation: "container", durationMs: 2100, logTail: "out", imageDigest: `sha256:${"a".repeat(64)}`, exitCode: 0, ...extra });
const matched = { ...base, outcome: "script-matched", reason: "expectation-met", run: run("pass") };
const unmatched = { ...base, outcome: "script-unmatched", reason: "expectation-not-met", run: run("fail", { exitCode: 0 }) };
const derived = { schemaVersion: 1, harness: "0security-executed-poc/1", outcome: "static-only", reason: "not-attempted", stepIds: [], startedAt: "", finishedAt: "" };
const html = (node: ReturnType<typeof createElement>) => renderToStaticMarkup(node);

describe("executedPocView", () => {
  it("labels the three outcomes in plain words", () => {
    expect(executedPocView(matched)).toMatchObject({ outcome: "script-matched", label: "Script matched" });
    expect(executedPocView(unmatched)).toMatchObject({ outcome: "script-unmatched", label: "Script unmatched" });
    expect(executedPocView({ ...base, outcome: "static-only", reason: "no-sandbox-image" })).toMatchObject({ outcome: "static-only", label: "Static only" });
  });
  it("shows the server's derived record for a high finding never attempted as static only", () => {
    const view = executedPocView(derived);
    expect(view).toMatchObject({ outcome: "static-only", label: "Static only" });
    expect(view!.line).toContain("not attempted");
    expect(view!.facts).toEqual([]);
  });
  it("never shows a script result without a complete container run record", () => {
    expect(executedPocView({ ...matched, run: undefined })).toBeNull();
    expect(executedPocView({ ...matched, run: run("pass", { isolation: "host" }) })).toBeNull();
    expect(executedPocView({ ...matched, run: run("pass", { imageDigest: undefined }) })).toBeNull();
    expect(executedPocView({ ...matched, harness: "someone-else" })).toBeNull();
    // A derived-looking record cannot claim an executed outcome.
    expect(executedPocView({ ...derived, outcome: "script-matched" })).toBeNull();
  });
  it("shows nothing when there is no record (lower severities, older servers)", () => {
    expect(executedPocView(null)).toBeNull();
    expect(executedPocView(undefined)).toBeNull();
    expect(executedPocView("garbage")).toBeNull();
  });
  it("carries the run facts for the detail view", () => {
    expect(executedPocView(matched)!.facts).toEqual([`Image sha256:${"a".repeat(12)}`, "Container, network off", "2.1s, exit 0", "Steps p1"]);
  });
});

describe("executed PoC in the findings views", () => {
  it("renders a chip per outcome with the honest sentence on hover", () => {
    const chip = html(createElement(ExecutedPocChip, { executedPoc: matched }));
    expect(chip).toContain('data-executed-poc="script-matched"');
    expect(chip).toContain(">Script matched<");
    expect(chip).toContain("title=");
    expect(html(createElement(ExecutedPocChip, { executedPoc: unmatched }))).toContain(">Script unmatched<");
    expect(html(createElement(ExecutedPocChip, { executedPoc: derived }))).toContain(">Static only<");
    expect(html(createElement(ExecutedPocChip, { executedPoc: null }))).toBe("");
  });
  it("renders the detail section, with the not-proof-of-safety wording for an unmatched run", () => {
    const section = html(createElement(ExecutedPocSection, { executedPoc: unmatched }));
    expect(section).toContain('aria-label="PoC execution"');
    expect(section).toContain("does not mean the issue is absent");
    expect(html(createElement(ExecutedPocSection, { executedPoc: matched }))).toContain("network off");
    expect(html(createElement(ExecutedPocSection, { executedPoc: undefined }))).toBe("");
  });
});
