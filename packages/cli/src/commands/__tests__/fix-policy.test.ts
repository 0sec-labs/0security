import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_FIX_POLICY_FILES, MAX_POLICY_FILE_BYTES, loadFixPolicyFile } from "../fix-policy.js";

function dirs() {
  const root = mkdtempSync(join(tmpdir(), "0-fix-policy-"));
  const repo = join(root, "repo");
  const home = join(root, "home");
  mkdirSync(join(repo, ".zero"), { recursive: true });
  mkdirSync(join(home, ".0"), { recursive: true });
  return { root, repo, home };
}

describe("where the fix policy comes from", () => {
  it("lists the six repository file names once", () => {
    expect(DEFAULT_FIX_POLICY_FILES).toEqual([
      ".zero/fix-policy.json", ".zero/fix-policy.yaml", ".zero/fix-policy.yml",
      "fix-policy.json", "fix-policy.yaml", "fix-policy.yml",
    ]);
  });

  it("ignores a policy file inside the repository by default", () => {
    const { repo, home } = dirs();
    writeFileSync(join(repo, "fix-policy.json"), JSON.stringify({ rules: ["from the repo"] }));
    writeFileSync(join(repo, ".zero", "fix-policy.yaml"), "rules:\n  - from the repo\n");
    expect(loadFixPolicyFile(repo, {}, home)).toBeUndefined();
  });

  it("reads the repository's file only with repoPolicy, and marks it as coming from the repository", () => {
    const { repo, home } = dirs();
    writeFileSync(join(repo, "fix-policy.json"), JSON.stringify({ rules: ["from the repo"] }));
    const loaded = loadFixPolicyFile(repo, { repoPolicy: true }, home);
    expect(loaded).toMatchObject({ fromRepo: true, policy: { rules: ["from the repo"] } });
  });

  it("prefers the operator's own policy over the repository's, even with repoPolicy", () => {
    const { repo, home } = dirs();
    writeFileSync(join(repo, "fix-policy.json"), JSON.stringify({ rules: ["from the repo"] }));
    writeFileSync(join(home, ".0", "fix-policy.yaml"), "rules:\n  - mine\n");
    expect(loadFixPolicyFile(repo, { repoPolicy: true }, home)).toMatchObject({ fromRepo: false, policy: { rules: ["mine"] } });
    expect(loadFixPolicyFile(repo, {}, home)).toMatchObject({ policy: { rules: ["mine"] } });
  });

  it("takes --policy from any path, relative to the current directory and not to the repository", () => {
    const { root, repo, home } = dirs();
    const file = join(root, "elsewhere.json");
    writeFileSync(file, JSON.stringify({ rules: ["explicit"] }));
    writeFileSync(join(repo, "elsewhere.json"), JSON.stringify({ rules: ["repo copy"] }));
    expect(loadFixPolicyFile(repo, { policy: file }, home)).toMatchObject({ fromRepo: false, policy: { rules: ["explicit"] } });
    const cwd = process.cwd();
    process.chdir(root);
    try {
      expect(loadFixPolicyFile(repo, { policy: "elsewhere.json" }, home)).toMatchObject({ policy: { rules: ["explicit"] } });
    } finally { process.chdir(cwd); }
    expect(() => loadFixPolicyFile(repo, { policy: join(root, "missing.json") }, home)).toThrow("not found");
  });

  it("refuses a repository policy that links outside the repository, and an oversized file", () => {
    const { root, repo, home } = dirs();
    const outside = join(root, "secret.json");
    writeFileSync(outside, JSON.stringify({ rules: ["secret"] }));
    symlinkSync(outside, join(repo, "fix-policy.json"));
    expect(() => loadFixPolicyFile(repo, { repoPolicy: true }, home)).toThrow("outside the repository");
    const big = join(root, "big.json");
    writeFileSync(big, JSON.stringify({ notes: "x".repeat(MAX_POLICY_FILE_BYTES) }));
    expect(() => loadFixPolicyFile(repo, { policy: big }, home)).toThrow("larger than");
  });
});
