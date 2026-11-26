import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildExport, type RollupRow } from "../findings-rollup-core.js";
import { buildRollupReport, HISTORY_SCHEMA, labelSnapshot, latestSnapshotRows, parseHistory, rollupCsv, type RollupSnapshot } from "../findings-rollup-history.js";
import { runFindingsRollup, type FindingsRollupDeps } from "../findings-rollup.js";
const first = "2026-01-01T00:00:00.000Z"; const second = "2026-02-01T00:00:00.000Z";
const row = (over: Partial<RollupRow> = {}): RollupRow => ({ repository: "api", fingerprint: "same-flaw", title: "example", severity: "critical", category: "xss", owner: null, status: "confirmed", triage: "new", firstSeen: first, lastSeen: first, ...over });
const snapshot = (at: string, findings: RollupRow[], source = "api.json", repositories?: string[]): RollupSnapshot => ({ ...buildExport(findings, new Date(at), repositories), source });
const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(path => rmSync(path, { recursive: true, force: true })));
describe("dated organisation snapshots", () => {
  it("uses capture time for current state and keeps the same flaw in both historical points", () => {
    const history = [snapshot(second, [row({ triage: "accepted" })]), snapshot(first, [row()])];
    const report = buildRollupReport(history, new Date(second));
    expect(report.open).toBe(0);
    expect(report.excluded.accepted).toBe(1);
    expect(report.trend.map(point => [point.at, point.summary.open])).toEqual([[first, 1], [second, 0]]);
    expect(report.trend[0]!.sources).toEqual(["api.json"]);
    expect(report.snapshots).toHaveLength(2);
  });
  it("does not erase another repository or infer a fix from its absence at a date", () => {
    const report = buildRollupReport([snapshot(first, [row(), row({ repository: "web" })]), snapshot(second, [row({ status: "fixed" })])], new Date(second));
    expect(report.open).toBe(1); // web's last known snapshot is retained in the current view
    expect(report.trend[1]!.repositories).toEqual(["api"]); // second point does not pretend to cover web
    expect(report.repositories).toBe(2);
  });
  it("an explicit empty repository snapshot replaces its earlier findings", () => {
    const history = [snapshot(first, [row()]), snapshot(second, [], "clean.json", ["api"])];
    expect(latestSnapshotRows(history)).toEqual({ rows: [], repositories: ["api"] });
    const report = buildRollupReport(history, new Date(second));
    expect(report.repositories).toBe(1); expect(report.open).toBe(0);
    expect(report.trend[1]!.summary.repositories).toBe(1);
  });
  it("does not overwrite historical team or tier labels with the current map", () => {
    const older = snapshot(first, [row({ team: "before", tier: "tier-2" })]);
    expect(labelSnapshot(older, { api: { team: "now", tier: "tier-1" } }).findings[0]).toMatchObject({ team: "before", tier: "tier-2" });
    const report = buildRollupReport([labelSnapshot(snapshot(second, [row()]), { api: { team: "payments", tier: "tier-1" } })], new Date(second));
    expect(report.byTeam).toEqual([{ name: "payments", count: 1 }]);
    expect(report.byTier).toEqual([{ name: "tier-1", count: 1 }]);
  });
  it("roundtrips archived timestamps and sanitises spreadsheet formulas in the CSV contract", () => {
    const snapshots = [snapshot(first, [row({ team: "=HYPERLINK(1)", tier: "tier-1" })])];
    const parsed = parseHistory(JSON.parse(JSON.stringify({ schema: HISTORY_SCHEMA, snapshots })));
    expect(parsed[0]!.exportedAt).toBe(first);
    const csv = rollupCsv(buildRollupReport(parsed, new Date(second)));
    expect(csv).toContain("0.findings-rollup.report.v1"); expect(csv).toContain("snapshot_at");
    expect(csv).toContain("'=HYPERLINK(1)");
  });
  it("command writes a history archive and can consume it later without redating old snapshots", () => {
    const root = mkdtempSync(join(tmpdir(), "0-rollup-history-")); dirs.push(root);
    writeFileSync(join(root, "old.json"), JSON.stringify(buildExport([row()], new Date(first))));
    writeFileSync(join(root, "new.json"), JSON.stringify(buildExport([row({ status: "fixed" })], new Date(second))));
    writeFileSync(join(root, "labels.json"), JSON.stringify({ api: { team: "payments", tier: "tier-1" } }));
    const out: string[] = [];
    const deps: FindingsRollupDeps = { now: () => new Date("2026-03-01T00:00:00Z"), defaultDatabases: () => [], out: text => out.push(text), err: () => {}, writeFile: (path, text) => writeFileSync(path, text) };
    const archive = join(root, "history.json");
    runFindingsRollup([join(root, "new.json"), join(root, "old.json")], { history: archive, labels: join(root, "labels.json"), format: "json" }, deps);
    const firstReport = JSON.parse(out.pop()!);
    expect(firstReport.trend.map((point: any) => point.summary.open)).toEqual([1, 0]);
    runFindingsRollup([archive], { format: "json" }, deps);
    expect(JSON.parse(out.pop()!).trend).toEqual(firstReport.trend);
    expect(readFileSync(archive, "utf8")).not.toContain(root);
    runFindingsRollup([archive], { format: "html" }, deps);
    expect(out.pop()).toContain("Snapshot trend");
  });
});
