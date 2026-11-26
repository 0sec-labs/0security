import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { osecDB } from "@0/engine/storage";
import type { Finding } from "@0/engine/shared";
import { loadFindingFocus } from "./finding-focus.js";
import { findingFingerprintCode } from "@0/engine/shared";
import { shortFindingId } from "./finding-id.js";

const SCAN = `ci-${"a".repeat(64)}`;
const ID = `${SCAN}-0123456789abcdef01234567`;
let directory: string;
let dbPath: string;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "0-cli-focus-"));
  dbPath = join(directory, "state.db");
  const db = new osecDB(dbPath);
  try {
    db.createScan({ target: "repo", depth: "deep", format: "json" }, SCAN);
    db.saveFinding(SCAN, { id: ID, fingerprint: `${SCAN}:sarif:0123456789abcdef01234567`, templateId: "source", title: "Imported", description: "Issue", severity: "high", category: "xss", status: "confirmed", timestamp: 1800000000000,
      evidence: { request: "src/a.ts:4", response: "evidence" } } as Finding);
  } finally { db.close(); }
});
afterEach(() => { rmSync(directory, { recursive: true, force: true }); });

describe("loadFindingFocus", () => {
  it("accepts the short id that `findings list` shows for an imported finding", () => {
    expect(loadFindingFocus(shortFindingId(ID), { dbPath }).finding.id).toBe(ID);
  });
});

it("accepts the displayed UI code and the legacy fingerprint prefix", () => {
  expect(loadFindingFocus(findingFingerprintCode(`${SCAN}:sarif:0123456789abcdef01234567`), { dbPath }).finding.id).toBe(ID);
  expect(loadFindingFocus(`fp:${SCAN.slice(0, 12)}`, { dbPath }).finding.id).toBe(ID);
});
