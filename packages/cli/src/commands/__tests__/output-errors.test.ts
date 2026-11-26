import { describe, expect, it } from "vitest";
import { errorLine, wantsJsonOutput } from "../output.js";

describe("machine-readable errors", () => {
  it("recognises the spellings that ask for JSON", () => {
    expect(wantsJsonOutput(["findings", "show", "abc", "--json"])).toBe(true);
    expect(wantsJsonOutput(["-p", "hi", "--format", "json"])).toBe(true);
    expect(wantsJsonOutput(["-p", "hi", "--format=ndjson"])).toBe(true);
  });
  it("stays text for everything else, including a prompt that mentions --json after --", () => {
    expect(wantsJsonOutput(["findings", "list"])).toBe(false);
    expect(wantsJsonOutput(["scan", ".", "--format", "sarif"])).toBe(false);
    expect(wantsJsonOutput(["-p", "--", "--json"])).toBe(false);
  });
  it("writes one parseable line in JSON mode and painted text otherwise", () => {
    expect(JSON.parse(errorLine("no such finding", true))).toEqual({ error: "no such finding" });
    expect(errorLine("no such finding", false, text => `<${text}>`)).toBe("<no such finding>");
  });
});
