---
title: Findings events
description: The versioned JSON event that describes a finding to a webhook receiver, a ticket tool or any other consumer.
---

A findings event is one finding, written as JSON with a version number. Any tool that reads the event can create, update or close its own record, without knowing how 0 stores findings. This page is the contract. The serializer and the schema ship in `@0/engine` (`serializeFindingEvent`, `findingEventJsonSchema`); this release defines the format only and does not change how or when webhooks are delivered.

## Example

```json
{
  "schema": "0.findings-event",
  "version": 1,
  "id": "loc:src/db.ts:12:open",
  "type": "finding.open",
  "emittedAt": "2026-01-01T00:00:00.000Z",
  "finding": {
    "fingerprint": "loc:src/db.ts:12",
    "id": "f-1",
    "title": "SQL injection in order lookup",
    "description": "User input reaches a query.",
    "severity": "high",
    "category": "injection",
    "status": "open",
    "location": { "path": "src/db.ts", "startLine": 12, "endLine": 14, "target": "github.com/acme/shop" },
    "ruleId": "js.sql-injection",
    "tool": "semgrep",
    "cvssScore": 8.1
  }
}
```

## Fields

| Field | Meaning |
| --- | --- |
| `schema` | Always `0.findings-event`. |
| `version` | Integer, `1` today. |
| `id` | Fingerprint and status joined with a colon. The same event always has the same id, so a receiver can drop a redelivery. |
| `type` | `finding.open`, `finding.fixed` or `finding.suppressed`. Always matches `finding.status`. |
| `emittedAt` | ISO 8601 time the event was produced. |
| `finding.fingerprint` | The finding's own fingerprint, the same one 0 uses to group duplicates into a family and that SARIF output carries. Use it as the key of your record. A finding that has none falls back to its `id`. |
| `finding.id` | The identifier of this occurrence in the run that produced it. Not stable across runs. |
| `finding.title`, `finding.description` | Text for people. Wording can change between runs; do not key on it. |
| `finding.severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `finding.category` | The attack category, a string. New categories can appear. |
| `finding.status` | `open`, `fixed` or `suppressed`. A fixed finding is fixed. A false positive, a dismissed finding and an accepted risk that has not expired are suppressed. Everything else, including an accepted risk whose expiry passed, is open. |
| `finding.location` | `path`, `startLine` and `endLine` when the finding cites exact lines, and `target` (what was scanned) when the sender knows it. Any part can be missing; the object itself is always present. |
| `finding.ruleId`, `finding.tool` | The rule and the scanner, when known. |
| `finding.cvssScore`, `finding.cvssVector` | Present only when scored. |

The JSON Schema (draft 2020-12) is generated from the same definition the serializer checks, so an event that is emitted always validates.

## Compatibility rules

- `version` changes only for a breaking change: removing or renaming a field, changing a type, or changing what a value means. Old versions are documented here for as long as they can be sent.
- Adding an optional field, or a new `category` or `tool` value, is not breaking and keeps the version. Receivers must ignore fields they do not know.
- Adding a value to `severity`, `status` or `type` is breaking and needs a new version.
- Receivers should reject a `schema` they do not recognise and treat a `version` higher than the one they support as unprocessable, not as a partial match.
- Fingerprints are stable for the same flaw in the same place. Treat them as opaque strings; do not parse them.
- Events carry no evidence, requests, responses or credentials.
