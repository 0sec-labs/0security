import { describe, expect, it } from "vitest";
import { createShimmedDatabase } from "./wasm-shim.js";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "../shared/index.js";
import { REPRODUCTION_HARNESS, proposeProof } from "../shared/reproduction.js";
import { osecDB } from "./database.js";
import { restoreFindingReviewFields } from "./finding-helpers.js";

const result = {
  schemaVersion: 1, harness: REPRODUCTION_HARNESS, status: "reproduced", reason: "canary-observed",
  commit: "0123456789abcdef0123456789abcdef01234567", imageDigest: `sha256:${"a".repeat(64)}`, isolation: "container", network: "loopback",
  canary: { token: "canary-abcdef12", observed: true }, recipeSha256: "b".repeat(64), appSha256: "d".repeat(64),
  startedAt: "2026-11-24T10:00:00.000Z", finishedAt: "2026-11-24T10:00:03.000Z", logTail: "ok",
} as const;

function withDb(fn: (db: osecDB, scanId: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "0-db-repro-"));
  const db = new osecDB(join(dir, "t.db"));
  try {
    const scanId = db.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
    fn(db, scanId);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}
const finding = (): Finding => ({ id: "f-1", templateId: "t", title: "x", description: "d", severity: "high", category: "path-traversal", status: "discovered", evidence: { request: "a", response: "b" }, timestamp: Date.now() } as Finding);

describe("finding reproduction storage", () => {
  it("is absent on a new finding and does not touch severity or status", () => {
    withDb((db, scanId) => {
      db.saveFinding(scanId, finding());
      expect(db.getFindingReproduction("f-1")).toBeUndefined();
      db.setFindingReproduction("f-1", { result: result as never });
      expect(db.getFindingReproduction("f-1")?.result?.status).toBe("reproduced");
      const row = db.getFinding("f-1")!;
      expect(row.severity).toBe("high");
      expect(row.status).toBe("discovered");
      expect(restoreFindingReviewFields(row).reproduction?.result?.commit).toBe(result.commit);
    });
  });

  it("refuses to store 'reproduced' without a harness record", () => {
    withDb((db, scanId) => {
      db.saveFinding(scanId, finding());
      expect(() => db.setFindingReproduction("f-1", { result: { status: "reproduced", reason: "model said so" } as never })).toThrow(/harness/);
      expect(() => db.setFindingReproduction("f-1", { result: { ...result, imageDigest: "node:20" } as never })).toThrow(/harness/);
      expect(db.getFindingReproduction("f-1")).toBeUndefined();
    });
  });

  it("keeps the record when the same finding is saved again, and merges a proof with a result", () => {
    withDb((db, scanId) => {
      db.saveFinding(scanId, finding());
      const proof = proposeProof({ pocSteps: [{ id: "s", kind: "exploit", summary: "x", action: { type: "shell", cmd: "echo hi" } }] })!;
      db.setFindingReproduction("f-1", { proof });
      db.setFindingReproduction("f-1", { result: result as never });
      db.saveFinding(scanId, finding());
      expect(db.getFindingReproduction("f-1")).toMatchObject({ proof: { label: "proposed" }, result: { status: "reproduced" } });
    });
  });

  it("opens a database from before the column existed and adds it", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-db-repro-old-"));
    const path = join(dir, "old.db");
    try {
      const first = new osecDB(path);
      const scanId = first.createScan({ target: "https://example.com", depth: "full" } as unknown as Parameters<typeof first.createScan>[0]);
      first.saveFinding(scanId, finding());
      first.close();
      const raw = createShimmedDatabase(path);
      raw.exec("ALTER TABLE findings DROP COLUMN reproduction");
      raw.close();
      const reopened = new osecDB(path);
      expect(reopened.getFinding("f-1")?.reproduction).toBeNull();
      expect(reopened.getFindingReproduction("f-1")).toBeUndefined();
      reopened.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
