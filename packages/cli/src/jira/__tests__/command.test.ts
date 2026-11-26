import { describe, expect, it } from "vitest";
import { Command } from "commander";
import { registerFindingsUploadCommand, type UploadDeps } from "../../commands/findings-upload.js";

describe("findings upload --to jira-cloud", () => {
  it("prints a dry run through the command", async () => {
    const out: string[] = [];
    const deps = { out: (t: string) => out.push(t), err: () => undefined, sleep: async () => undefined, readText: () => JSON.stringify({ findings: [{ id: "a", title: "T", severity: "high", status: "confirmed", category: "c", description: "d" }] }), gh: async () => "", git: async () => "", env: {} } as UploadDeps;
    const program = new Command(); program.exitOverride();
    registerFindingsUploadCommand(program, deps);
    await program.parseAsync(["node", "x", "upload", "scan.json", "--to", "jira-cloud", "--jira-project", "SEC", "--jira-label", "a", "--jira-label", "b", "--dry-run", "--format", "json"]);
    const parsed = JSON.parse(out.join(""));
    expect(parsed.planned[0].labels).toEqual(["0security", "high", "0-finding-a", "a", "b"]);
  });
});
