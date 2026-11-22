import { homeStateDir } from "@0/engine/shared";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { feedbackFilePath } from "./feedback.js";
import { pendingDirectory } from "./pending-diagnostics.js";

describe("state paths follow the HOME environment variable", () => {
  const realHome = process.env.HOME;
  let home = "";
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "home-state-dir-"));
    process.env.HOME = home;
  });
  afterEach(() => {
    if (realHome === undefined) delete process.env.HOME; else process.env.HOME = realHome;
    rmSync(home, { recursive: true, force: true });
  });

  it("puts pending diagnostics and feedback under homeStateDir()", () => {
    expect(homeStateDir()).toBe(join(home, ".0"));
    expect(pendingDirectory().startsWith(homeStateDir())).toBe(true);
    expect(feedbackFilePath().startsWith(homeStateDir())).toBe(true);
  });
});
