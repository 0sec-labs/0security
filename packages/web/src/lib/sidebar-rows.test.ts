import { describe, expect, it } from "vitest";
import { folderName, rowWorkspacePath } from "./sidebar-rows";

describe("rowWorkspacePath", () => {
  it("uses the folder of a live thread", () => {
    expect(rowWorkspacePath({ workspacePath: "/work/app", cwd: "/other" })).toBe("/work/app");
  });
  it("falls back to the folder a saved thread was started in", () => {
    expect(folderName(rowWorkspacePath({ cwd: "/work/proj" }))).toBe("proj");
  });
  it("has no folder when neither is known", () => {
    expect(rowWorkspacePath({})).toBeUndefined();
  });
});
