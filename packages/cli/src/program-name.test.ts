import { describe, expect, it } from "vitest";
import { invokedProgramName } from "./program-name.js";

describe("invokedProgramName", () => {
  it("shows 0security when started as 0security", () => {
    expect(invokedProgramName("0security")).toBe("0security");
    expect(invokedProgramName("/usr/local/bin/0security")).toBe("0security");
    expect(invokedProgramName("C:\\bin\\0security.exe")).toBe("0security");
  });
  it("shows 0 for the alias and for anything else", () => {
    expect(invokedProgramName("0")).toBe("0");
    expect(invokedProgramName("/home/u/.0/bin/0")).toBe("0");
    expect(invokedProgramName("node")).toBe("0");
    expect(invokedProgramName("bun")).toBe("0");
    expect(invokedProgramName(undefined)).toBe("0");
  });
});
