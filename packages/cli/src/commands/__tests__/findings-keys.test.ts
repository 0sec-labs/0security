import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FindingsAccessTokenStore } from "../../web/findings-access-tokens.js";
import { registerFindingsKeysCommand } from "../findings-keys.js";

let directory: string;
let out: string[];
let err: string[];
const saved = { inline: process.env.ZERO_LICENSE, file: process.env.ZERO_LICENSE_FILE };

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "0-keys-"));
  out = []; err = [];
  delete process.env.ZERO_LICENSE;
  delete process.env.ZERO_LICENSE_FILE;
  process.exitCode = 0;
});
afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
  for (const [name, value] of [["ZERO_LICENSE", saved.inline], ["ZERO_LICENSE_FILE", saved.file]] as const) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
  process.exitCode = 0;
});

async function run(...args: string[]): Promise<void> {
  const program = new Command().exitOverride();
  const keys = program.command("findings");
  registerFindingsKeysCommand(keys, { out: text => out.push(text), err: text => err.push(text), store: () => new FindingsAccessTokenStore({ workspaceId: "w", stateDir: directory }) });
  await program.parseAsync(["findings", "keys", ...args], { from: "user" });
}

describe("findings keys --scope", () => {
  it("makes a read key by default and lists its scope", async () => {
    await run("create", "reader", "--json");
    expect(JSON.parse(out.join("")).credential.scopes).toEqual(["read:findings"]);
    out = [];
    await run("list");
    expect(out.join("\n")).toMatch(/reader\s+read/);
  });

  it("asks for an enterprise license before it makes a write key", async () => {
    await run("create", "ci", "--scope", "write");
    expect(err.join("\n")).toMatch(/needs an enterprise license/);
    expect(process.exitCode).not.toBe(0);
    expect(out).toEqual([]);
  });

  it("refuses an unknown scope", async () => {
    await run("create", "ci", "--scope", "admin");
    expect(err.join("\n")).toMatch(/--scope must be read or write/);
  });
});
