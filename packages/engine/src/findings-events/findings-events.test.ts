import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Finding } from "../shared/types.js";
import { findingEventJsonSchema, findingEventSchema } from "./schema.js";
import { findingEventStatus, serializeFindingEvent, serializeFindingEvents } from "./serialize.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "__golden__");
function golden(name: string, value: unknown): string {
  const file = join(dir, name);
  const text = `${JSON.stringify(value, null, 2)}\n`;
  if (process.env.UPDATE_GOLDEN === "1" || !existsSync(file)) writeFileSync(file, text);
  return readFileSync(file, "utf8");
}

const base: Finding = {
  id: "f-1", templateId: "semgrep/js.sql-injection", title: "SQL injection in order lookup", description: "User input reaches a query.",
  severity: "high", category: "injection", status: "verified", evidence: { request: "GET /orders?id=1'", response: "500" },
  fingerprint: "loc:src/db.ts:12", timestamp: 1700000000000,
  reviewAnnotation: { path: "src/db.ts", startLine: 12, endLine: 14 }, cvssScore: 8.1,
};
const opts = { emittedAt: "2026-01-01T00:00:00.000Z", target: "github.com/acme/shop", now: Date.parse("2026-01-01T00:00:00Z") };

describe("findings events", () => {
  it("matches the golden events", () => {
    const events = serializeFindingEvents([
      base,
      { ...base, id: "f-2", fingerprint: "fp-2", status: "fixed", reviewAnnotation: undefined, templateId: "idor", cvssScore: undefined },
      { ...base, id: "f-3", fingerprint: undefined, triageStatus: "suppressed" },
    ], opts);
    expect(`${JSON.stringify(events, null, 2)}\n`).toBe(golden("events.json", events));
    for (const event of events) expect(findingEventSchema.safeParse(event).success).toBe(true);
  });
  it("matches the golden JSON Schema", () => {
    const schema = findingEventJsonSchema();
    expect(`${JSON.stringify(schema, null, 2)}\n`).toBe(golden("schema.v1.json", schema));
  });
  it("maps status", () => {
    expect(findingEventStatus({ status: "fixed" })).toBe("fixed");
    expect(findingEventStatus({ status: "false-positive" })).toBe("suppressed");
    expect(findingEventStatus({ status: "verified", triageStatus: "accepted", triageExpiresAt: "2025-01-01T00:00:00Z" }, opts.now)).toBe("open");
    expect(findingEventStatus({ status: "verified", triageStatus: "accepted" })).toBe("suppressed");
  });
  it("keeps the finding's own fingerprint and is deterministic", () => {
    const a = serializeFindingEvent(base, opts);
    expect(a.finding.fingerprint).toBe("loc:src/db.ts:12");
    expect(a.id).toBe("loc:src/db.ts:12:open");
    expect(serializeFindingEvent(base, opts)).toEqual(a);
    expect(a.version).toBe(1);
  });
});
