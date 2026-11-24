// FindingsServerRepository: storage for the shared findings server (ingest, triage history, org rollup).
// The tables are always present so any database opens the same way; only the licensed server paths write to them.
import { randomUUID } from "node:crypto";
import type { Finding } from "../../shared/index.js";
import * as schema from "../schema.js";
import type { SQLiteScanId } from "../types.js";
import { Repository } from "./base.js";

export type FindingHistoryAction = "open" | "reopen" | "accept" | "suppress" | "fixed" | "seen";

export interface FindingHistoryInput {
  fingerprint: string;
  actor: string;
  action: FindingHistoryAction;
  reason?: string | null;
  expiresAt?: string | null;
  prevState?: string | null;
  newState?: string | null;
  repo?: string | null;
  source?: string | null;
  ts?: string;
}

export interface FindingHistoryRow {
  id: string;
  fingerprint: string;
  ts: string;
  actor: string;
  action: string;
  reason: string | null;
  expiresAt: string | null;
  prevState: string | null;
  newState: string | null;
  repo: string | null;
  source: string | null;
}

export interface IngestFindingsInput {
  /** `fx-` plus the digest of the upload; the same upload always has the same id. */
  scanId: string;
  digest: string;
  repo: string;
  source: string;
  ref?: string;
  commit?: string;
  actor: string;
  format: string;
  /** Findings with a stable fingerprint already set. */
  findings: Finding[];
}

export interface IngestFindingsResult { scanId: string; alreadyImported: boolean; total: number; created: number; known: number }

/** One finding family (latest row per fingerprint) that came from an ingest. */
export interface OrgFindingRow {
  fingerprint: string;
  id: string;
  title: string;
  severity: string;
  category: string;
  triageStatus: string;
  triageNote: string | null;
  triageExpiresAt: string | null;
  triageApprover: string | null;
  repo: string;
  source: string | null;
  tool: string | null;
  firstSeen: number;
  lastSeen: number;
}

export class FindingsServerRepository extends Repository {
  appendFindingHistory(input: FindingHistoryInput): string {
    const id = randomUUID();
    this.sqlite.prepare(
      `INSERT INTO finding_history (id, fingerprint, ts, actor, action, reason, expiresAt, prevState, newState, repo, source)
       VALUES (@id, @fingerprint, @ts, @actor, @action, @reason, @expiresAt, @prevState, @newState, @repo, @source)`,
    ).run({
      id, fingerprint: input.fingerprint, ts: input.ts ?? new Date().toISOString(), actor: input.actor, action: input.action,
      reason: input.reason ?? null, expiresAt: input.expiresAt ?? null, prevState: input.prevState ?? null,
      newState: input.newState ?? null, repo: input.repo ?? null, source: input.source ?? null,
    });
    return id;
  }

  /** Oldest first. */
  listFindingHistory(fingerprint: string, limit = 500): FindingHistoryRow[] {
    return this.sqlite.prepare(
      "SELECT id, fingerprint, ts, actor, action, reason, expiresAt, prevState, newState, repo, source FROM finding_history WHERE fingerprint = ? ORDER BY ts ASC, rowid ASC LIMIT ?",
    ).all(fingerprint, Math.max(1, Math.min(limit, 5000))) as FindingHistoryRow[];
  }

  /** The repo a fingerprint was ingested for, or null when it was not ingested. */
  repoOfFingerprint(fingerprint: string): { repo: string; source: string | null } | null {
    const row = this.sqlite.prepare("SELECT repo, source FROM findings WHERE fingerprint = ? AND repo IS NOT NULL ORDER BY timestamp DESC LIMIT 1").get(fingerprint) as { repo: string; source: string | null } | undefined;
    return row ?? null;
  }

  /**
   * Store one upload. The upload is idempotent as a whole (same digest, nothing happens) and per finding:
   * a fingerprint already known for this repository only has its last-seen time refreshed. New fingerprints
   * are saved with the usual triage inheritance and get an `open` history row.
   */
  ingestFindings(input: IngestFindingsInput): IngestFindingsResult {
    return this.transaction(() => {
      const previous = this.owner.getScan(input.scanId);
      if (previous) return { scanId: input.scanId, alreadyImported: true, total: input.findings.length, created: 0, known: input.findings.length };
      const now = new Date();
      this.db.insert(schema.scans).values({
        id: input.scanId as SQLiteScanId,
        target: input.repo,
        depth: "default",
        runtime: "external-ci",
        mode: "findings-server",
        status: "completed",
        startedAt: now.toISOString(),
        completedAt: now.toISOString(),
        durationMs: 0,
        summary: JSON.stringify({
          totalFindings: input.findings.length,
          ciImport: { digest: input.digest, source: "findings-server", trust: "unverified", repo: input.repo, sourceLabel: input.source, ref: input.ref ?? null, commit: input.commit ?? null, format: input.format, importedAt: now.toISOString() },
        }),
      }).run();
      let created = 0;
      let known = 0;
      for (const finding of input.findings) {
        const fingerprint = finding.fingerprint!;
        const existing = this.sqlite.prepare("SELECT id FROM findings WHERE fingerprint = ? AND repo = ? LIMIT 1").get(fingerprint, input.repo) as { id: string } | undefined;
        if (existing) {
          this.sqlite.prepare("UPDATE findings SET timestamp = ?, source = ? WHERE fingerprint = ? AND repo = ? AND timestamp < ?").run(now.getTime(), input.source, fingerprint, input.repo, now.getTime());
          known++;
          continue;
        }
        this.owner.saveFinding(input.scanId, finding);
        this.sqlite.prepare("UPDATE findings SET repo = ?, source = ? WHERE id = ?").run(input.repo, input.source, finding.id);
        this.appendFindingHistory({ fingerprint, actor: input.actor, action: "open", newState: "new", repo: input.repo, source: input.source, ts: now.toISOString() });
        created++;
      }
      return { scanId: input.scanId, alreadyImported: false, total: input.findings.length, created, known };
    });
  }

  /** Latest row per fingerprint among ingested findings, optionally for one repository. */
  listOrgFindings(options: { repo?: string; limit?: number } = {}): OrgFindingRow[] {
    const limit = Math.max(1, Math.min(options.limit ?? 5000, 20000));
    return this.sqlite.prepare(
      `SELECT f.fingerprint AS fingerprint, f.id AS id, f.title AS title, f.severity AS severity, f.category AS category,
              f.triageStatus AS triageStatus, f.triageNote AS triageNote, f.triageExpiresAt AS triageExpiresAt,
              f.triageApprover AS triageApprover, f.repo AS repo, f.source AS source, f.tool AS tool,
              (SELECT MIN(timestamp) FROM findings g WHERE g.fingerprint = f.fingerprint AND g.repo = f.repo) AS firstSeen,
              f.timestamp AS lastSeen
         FROM findings f
        WHERE f.repo IS NOT NULL AND f.fingerprint IS NOT NULL AND (@repo IS NULL OR f.repo = @repo)
          AND f.rowid = (SELECT g.rowid FROM findings g WHERE g.fingerprint = f.fingerprint AND g.repo = f.repo ORDER BY g.timestamp DESC, g.rowid DESC LIMIT 1)
        ORDER BY f.timestamp DESC LIMIT @limit`,
    ).all({ repo: options.repo ?? null, limit }) as OrgFindingRow[];
  }
}
