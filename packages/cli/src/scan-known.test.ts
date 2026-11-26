import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadKnown, withoutFolderPrefix } from "./scan-known.js";

const sarif = (uri: string) => JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "0" } }, results: [{ ruleId: "t/x", level: "error", message: { text: "Command injection" }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 30 } } }] }] }] });

function folderWith(files: string[]) {
  const root = join(mkdtempSync(join(tmpdir(), "known-")), "app");
  mkdirSync(root, { recursive: true });
  for (const file of files) { mkdirSync(join(root, file, ".."), { recursive: true }); writeFileSync(join(root, file), "x\n"); }
  return root;
}

describe("known items from a 0 report", () => {
  it("drops the scanned folder's name from a path when only the shorter path exists", () => {
    const root = folderWith(["server.js"]);
    const file = join(root, "..", "own.sarif");
    writeFileSync(file, sarif("app/server.js"));
    expect(loadKnown([file], [root]).items[0]?.path).toBe("server.js");
  });

  it("keeps a path that exists as written, even when it starts with the folder's name", () => {
    const root = folderWith(["app/server.js", "server.js"]);
    expect(withoutFolderPrefix({ path: "app/server.js" }, [root]).path).toBe("app/server.js");
  });

  it("keeps a path whose shorter form does not exist, and items without a path", () => {
    const root = folderWith(["other.js"]);
    expect(withoutFolderPrefix({ path: "app/server.js" }, [root]).path).toBe("app/server.js");
    expect(withoutFolderPrefix({}, [root])).toEqual({});
  });
});
