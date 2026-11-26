# High availability for server mode

Tracking issue: #476 (R61). Status: design, with phase 1 and the job queue built. The delivery steps that followed phase 1 are listed under "Delivery steps after phase 1".

Server mode runs as one process on one SQLite file. This page lists the state that blocks a second replica, picks the storage approach, and splits the work into phases that each ship alone.

## Why it was deferred

The issue says "sell single-node plus support first". That was a sequencing call, not a technical block. Two facts made it expensive:

- 42 source files open SQLite directly, and all of them are synchronous. A shared database is a network call, so every one of them has to become async.
- Several features keep state in process memory. Sessions, sign-in state, rate limits and live event streams all live in one Node process.

Nothing needs a rewrite. The work is large but cuts into small pieces. Phase 1 proves the approach on one piece and ships with this page.

## What HA means here

N stateless replicas behind a load balancer, one managed PostgreSQL that has its own high availability, and shared storage for files. We do not build clustering, consensus or replication. The database carries all shared state and all coordination.

Failover target: losing one replica drops its open connections and in-flight Thread turns. Everything else carries on. Losing the database stops writes until the managed service fails over.

## Inventory: where state lives today

All paths are under the state directory (`~/.0`, `/data/.0` in the image). In team mode the database is `teams/<sha256 of workspace>/data.db`; otherwise `0.db`.

### Durable state in SQLite

| State | Tables or file | Code | HA problem | Target |
| --- | --- | --- | --- | --- |
| Findings, scans, targets, cases, work items, artifacts, verdicts, triage memory, trust graph, coverage, workers, persistent credentials, finding history | `scans`, `targets`, `findings`, `finding_history`, `attack_results`, `verdicts`, `pipeline_events`, `agent_sessions`, `cases`, `work_items`, `artifacts`, `triage_memories`, `workers`, `persistent_credentials`, `trust_graph_edges`, `coverage_scans`, `coverage_units` | `storage/database.ts`, `schema-migrations.ts`, `repositories/` (drizzle on SQLite) | One writer file. Repositories are synchronous. | Postgres, phase 4 |
| Learning | `learning_events`, `learning_knowledge`, `learning_candidates`, `learning_suggestion_keys`, `learning_active`, `learning_work` | `storage/learning.ts` | Same | Postgres, phase 4 |
| Audit log and hash chain | `audit_events`, `audit_checkpoints` | `storage/audit-log.ts`, `audit-chain.ts` | The chain needs one writer at a time | Postgres, phase 3 |
| Team accounts | `team_users` | `storage/team-users.ts` | Each replica caches rows in memory | Postgres, phase 3 |
| SCIM tokens and groups | `scim_tokens`, `scim_groups` | `storage/scim-store.ts` | Same file ownership | Postgres, phase 3 |
| Sentinels, activations, files, triggers, turns | `sentinels`, `sentinel_activations`, `sentinel_files`, `sentinel_file_revisions`, `sentinel_triggers`, `agent_turns` | `storage/sentinels.ts` | Trigger claims use a local transaction and a stale window. Two replicas would both poll. | Postgres, phase 3 and 5 |
| Workflows and triggers | `workflow_definitions`, `workflow_definition_versions`, `workflow_executions`, `workflow_execution_results`, `workflow_triggers` | `storage/security-workflows.ts`, `workflow-triggers.ts` | Executions are driven by the process that started them | Postgres, phase 3 and 5 |
| Server sessions | none: in memory | `web/team-auth.ts`, `web/server-mode.ts` | A cookie works on one replica only | Postgres, phase 1 (store) and 2 (wiring) |

### Durable state in files

| State | File | HA problem | Target |
| --- | --- | --- | --- |
| API keys for the findings server | `findings-api-access/<sha256 of workspace>.json` plus `.lock` | A lock file and an atomic rename work on one disk only | Postgres table, phase 3 |
| Collaboration state (comments, presence snapshot) | `collaboration/<sha256>.json` plus lock | Same | Postgres, phase 3 |
| Webhook secrets | `signed-webhook-<trigger>.json` | Same | Postgres, phase 3 |
| Thread transcripts | `console-sessions/<id>.json` | A live Thread is held by one process; the file is the resume copy | Postgres or object storage, phase 6 |
| Run journals and results | `runs/<scanId>/journal.jsonl`, `final.json` | Appended by the process that runs the scan | Object storage, phase 6 |
| Reports and artifacts | report folders, `engagements/` | Local disk | Object storage, phase 6 |
| Hub mailbox and roster | `hub/<sha256 of project>/` | Per project directory | Stays local: it coordinates processes on one computer |
| Console access token | `access-token` (0600) | Each replica would generate its own | Set `ZERO_ACCESS_TOKEN` from the secret store. No code change. |
| Control token and local engine record | `engines/<sha256 of database path>.json` with pid, nonce and token | "A local engine already owns this database" is a pid check on one machine | Replaced by a lease in the database, phase 5. Per replica, the control token stays local. |
| Remote engines and computers | `engines.json`, `backends.json`, `workers/*.json` and `.env` | Per replica, differ between replicas | Config from the deployment, phase 7 |
| Caches and counters | `last-update-check`, catalog cache, `burndown.json`, `zeroverse-runtime.json` | Harmless duplicates | Stay local |
| Telemetry identifiers | state files under the state directory | One per replica | Stay local. Replicas count as separate installs. |

### In-memory state that breaks with two replicas

| State | Code | What goes wrong | Target |
| --- | --- | --- | --- |
| Team sessions (`Map`, 10,000 cap) | `web/team-auth.ts` | A request routed to another replica looks signed out | Postgres sessions, phases 1 and 2 |
| Access-token sessions | `web/server-mode.ts` | Same | Postgres sessions, phase 2 |
| OIDC sign-in in flight (nonce, PKCE verifier) | `web/team-auth.ts` `pending` | The callback lands on a different replica and fails | Short-lived Postgres rows, phase 2 |
| Login attempt counters | `team-auth.ts` `attempts`, `server-mode.ts` `LoginThrottle` | Each replica gives an attacker a fresh budget | Postgres counters, phase 2 |
| SAML requests in flight and the replay cache | `enterprise/src/saml/provider.ts`, `cache.ts` | A response replays across replicas; the ACS post lands elsewhere | Postgres rows with expiry, phase 2 |
| SCIM request rate | `web/scim-routes.ts` | Per replica budget | Postgres counters, phase 2 |
| Webhook delivery dedupe and rate windows | `web/github-webhook.ts`, `signed-webhook.ts` | A redelivery handled twice | Postgres insert-if-absent, phase 5 |
| Live Thread sessions, event buffers and listeners | `web/console-gateway.ts` (`ManagedSession`) | Event streams are held by one process | Thread lease and routing, phase 6 |
| Event fan-out (SSE) | `presentation/event-bus.ts`, `web/team-presence-stream.ts`, `web/dashboard-api.ts` | Clients on replica A miss events from replica B | LISTEN and NOTIFY, phase 5 |
| Presence | `web/collaboration.ts` | Per replica | Postgres plus NOTIFY, phase 5 |
| Sentinel watches and comment throttles | `web/sentinel-runner.ts` | Each replica starts its own | Leader only, phase 5 |
| Static asset and read caches | `web/dashboard-http.ts`, `read-cache.ts` | Safe: derived data | Stay local |
| Database file guard | `local-engine.ts` | Checks a pid on this machine | Not needed with Postgres. SQLite mode keeps it. |

### Processes that must run once

Run these on one replica at a time:

- The Sentinel scheduler tick (every 15 seconds) and the GitHub, Bitbucket, release and check pollers.
- The audit sink push to a SIEM. Two replicas send every event twice.
- Audit retention and rotation.
- Idle Thread reaping for sessions a replica owns stays per replica.

Election uses a PostgreSQL session advisory lock. A replica runs `pg_try_advisory_lock(key)` on a dedicated connection every few seconds. The holder is the leader. If its connection drops, PostgreSQL releases the lock and another replica takes over within one interval. Each job also checks `claimTrigger` on the database row, so a leader change in the middle of a tick cannot start a job twice. Leadership is an optimization over row claims, not the only protection.

## Decisions

### Storage: a thin async interface per subsystem

Each subsystem gets a small async `Store` interface with two implementations, SQLite and Postgres, written as plain SQL for each. One contract test suite runs against both.

We do not use a query builder or ORM across both dialects. The reasons:

- drizzle has separate SQLite and Postgres cores with different types, and the SQLite one is synchronous. One schema definition cannot serve both.
- Most queries are small. Hand-written SQL per dialect is easy to read and review.
- A contract suite catches any difference in behaviour. This is the check that matters.

### Where the code lives

- The interface and the SQLite implementation stay in the open engine. The free product runs on SQLite exactly as before.
- Everything that needs a shared database sits in `enterprise/src/ha/` behind the license feature `ha`: the PostgreSQL pool, migrations, the Postgres stores and leader election.
- `packages/cli/src/ha-bridge.ts` is the one place outside `enterprise/` that imports it. It checks `hasFeature("ha")` and returns a store. Call sites use plain `if` checks. There is no plugin interface.
- A license that expires keeps the server starting. Past the grace period, a server that names a shared database refuses to start with a clear message, because it cannot silently fall back to a different database. This matches how the other paid features report expiry.

### Connection and egress

The database is an operator-named destination, like the audit sink. The URL comes only from `ZERO_HA_DATABASE_URL` or from the file that `ZERO_HA_DATABASE_URL_FILE` names. A repository, a project file or a database cannot supply it. A database on another machine needs `sslmode` of `require`, `verify-ca` or `verify-full`. The password never appears in logs or errors. The entry `ha-shared-database` in `scripts/egress-inventory.json` and the data-flow page register it. `ZERO_ENTERPRISE` leaves it on.

### Migrations

Versioned, forward-only, numbered 1, 2, 3 with no gaps, kept in code. Every replica runs them at start:

1. Take a session advisory lock on a fixed key. Other replicas wait.
2. Read the highest applied version from `zero_schema_migrations`.
3. Refuse to run if the database is newer than the build.
4. Apply each pending migration in its own transaction and record it in the same transaction.
5. Release the lock.

Rolling upgrades use expand then contract. A release may add columns and tables. It may remove or rename them only one release after nothing reads them. Phase 1 tests concurrent starts, rollback of a failing migration and the newer-database refusal.

### Audit hash chain across replicas

The chain stays one linear chain. Each append runs in one transaction that takes `pg_advisory_xact_lock(audit-key)`, reads the newest hash, inserts the new row and commits. One writer at a time keeps the order and the links intact. Contention is low because audit events are few and small. Rotation checkpoints use the same lock. The verifier is unchanged: it reads rows by id and expects no gaps. A sequence default can leave a gap after a rollback, so the writer assigns the next id itself, inside the lock. Phase 3 tests this with many parallel writers.

### Sessions

Rows in `zero_ha_sessions`, keyed by the SHA-256 of the cookie value. The raw cookie never reaches the database, so a database leak does not give out usable sessions. Fields are account ID, optional fixed role, creation time and expiry. Revoking an account deletes its rows, so it takes effect on every replica at once. Replicas may cache a session for a few seconds to save a round trip. A cache makes revocation lag by that long, so the default is no cache.

### Job queue

Sentinel runs, workflow executions and queued turns become rows with a status. A worker takes one with:

```sql
SELECT id FROM jobs WHERE status = 'queued' AND run_after <= now()
ORDER BY run_after FOR UPDATE SKIP LOCKED LIMIT 1
```

The claim sets an owner and a lease time in the same transaction. A running job renews its lease. A job whose lease lapsed returns to the queue. This replaces the pid check, which means nothing across machines.

### Event fan-out

A replica that creates an event writes it, then runs `NOTIFY` on a channel. Every replica runs `LISTEN` on one dedicated connection and forwards events to the browsers it serves. The payload carries only an ID; NOTIFY payloads are capped near 8 KB and the listener reads the row. Streams that need replay read from the table with the last seen ID after a reconnect.

### Threads

A live Thread has an in-process agent runtime, so one replica owns it at a time. The owner holds a lease row. A request for a Thread that another replica owns is routed there: the load balancer uses a cookie hash for stickiness, and a replica that receives a request it does not own forwards it to the owner. When the owner dies, the lease lapses and any replica resumes the Thread from the stored transcript. The interrupted turn is lost and shown as such. This is the hardest part, which is why it comes late.

## Minimal topology

- 2 or more replicas of the same image, behind a load balancer with TLS.
- One managed PostgreSQL 16 or newer with its own failover, backups and point-in-time recovery.
- Shared storage for files: object storage, or Postgres for small ones.
- Secrets from the platform: `ZERO_ACCESS_TOKEN`, `ZERO_HA_DATABASE_URL_FILE`, `ZERO_LICENSE_FILE`, provider keys.
- `/readyz` returns 503 when the database does not answer, so the load balancer drops that replica.

## Phases

Each phase ships alone and keeps single-node SQLite working. Effort is one engineer's guess including tests and docs.

| Phase | Scope | Ships | Effort |
| --- | --- | --- | --- |
| 0 | This design | Page | done |
| 1 | `SessionStore` interface, SQLite store, Postgres store, migrations, license gate, contract tests | Not wired to the server yet. Proves the approach. | 1 week, done |
| 2 | Wire sessions into team and access-token sign-in (async resolve, about 15 call sites). Move OIDC and SAML in-flight state, replay cache and login counters to Postgres. | A server can run 2 replicas for sign-in. Everything else is still single-node, so not yet supported. | 2 weeks |
| 3 | Team users, SCIM, API keys, collaboration and webhook secrets to stores. Audit log with the single-writer chain. Sentinel and workflow stores. | All account and audit data in Postgres | 3 to 4 weeks |
| 4 | Findings database: the drizzle repositories and the 42 direct SQLite users become async stores | Findings in Postgres | 4 to 6 weeks |
| 5 | Leader election, job queue with `SKIP LOCKED`, LISTEN and NOTIFY fan-out, dedupe tables | Schedulers and pollers run once; live updates cross replicas | 2 to 3 weeks |
| 6 | Thread leases and routing, transcripts and run files in shared storage | A replica can fail mid-session and the Thread resumes | 4 to 6 weeks |
| 7 | Helm chart replicas and disruption budget, runbooks (backup, restore, rolling upgrade), failure and load tests | Supported HA release | 2 to 3 weeks |

Total: about 5 to 7 engineer-months. Phases 2 and 5 first give the best return: a team can then survive a replica restart without everyone signing in again.

Do not claim HA in the docs before phase 7. Until then, `server-mode.md` keeps saying one replica.

## Risks

- Sync to async touches 42 files. Mitigation: one subsystem per pull request, contract tests first.
- SQLite and Postgres differ: types, `LIKE` case rules, transaction isolation, integer size. The contract suite and a Postgres run in CI catch them. The CI runner needs a Postgres service. Until then the Postgres tests run only where `ZERO_TEST_POSTGRES_URL` is set.
- The release binary is built with Bun. The `pg` driver is pure JavaScript and should work, but phase 1 did not test it inside the compiled binary. Test this before phase 2 ships.
- Clock differences between replicas move session expiry by their difference. With eight-hour sessions this is small; leases use database time.
- Leader flapping if the database connection is unstable. Row claims keep jobs safe; only latency suffers.
- A shared database widens the blast radius of a leak. Store only hashes of tokens and cookies, and require TLS off the loopback.
- Thread routing adds a forward hop and a failure mode. Keep the sticky cookie as the common path.
- An expired license and a named database: the server refuses to start. Operators need that message in the runbook.

## Not in scope

- Our own clustering, consensus or replication. The managed database does this.
- Multi-region or active-active across regions.
- SQLite to Postgres migration tooling for existing data. A later phase may add a one-way export.
- Sharing one SQLite volume between hosts. This stays unsupported.
- Per-customer isolation inside one deployment.
- Autoscaling policy. The chart will set a replica count.

## Phase 1 as built

- `packages/engine/src/storage/session-store.ts`: the `SessionStore` interface and `SqliteSessionStore`. Nothing in the open product calls it yet.
- `enterprise/src/ha/`: config, `createHaPool`, migrations and `PostgresSessionStore`. The `ha` feature is in `enterprise/src/license.ts`.
- `packages/cli/src/ha-bridge.ts`: `openHaSessionStore` checks the license, opens the pool and migrates. The assignment to `SessionStore` there is the compile-time check that the Postgres store matches the interface.
- Tests: one contract suite (`web/__fixtures__/session-store-contract.ts`) runs against SQLite always and against PostgreSQL when `ZERO_TEST_POSTGRES_URL` is set. Enterprise tests cover the URL rules, concurrent migrations, rollback and hashed storage.

Why sessions first: they are the first thing a second replica breaks, they have a small surface (create, read, delete, delete by account), and they hold no findings, so a mistake cannot lose evidence. API keys and SCIM tokens came next in the ranking, but the keys sit in a file store with a lock file and need a larger change.

## Delivery steps after phase 1

The remaining work shipped as small steps in this order: durable job queue, leader election, health and readiness, graceful drain, Helm and compose wiring, docs. They are numbered 2 to 7 in issue #476 and are separate from the storage phases in the table above. The storage phases (accounts, audit, findings, Threads) are not done, so a second replica still cannot share findings.

### Job queue as built

- Migration 2 creates `zero_ha_jobs`: kind, JSON payload, optional dedupe key, status (`queued`, `running`, `done`, `dead`), attempts, owner, lease time and last error.
- `PostgresJobQueue` in `enterprise/src/ha/job-queue.ts` claims one job with `FOR UPDATE SKIP LOCKED`, renews leases, completes, fails with a retry delay, releases and reaps lapsed leases. All times are database time.
- A unique index on kind and dedupe key, for jobs that are queued or running, makes a repeated enqueue return the open job.
- A job that used its attempts becomes `dead` and stays for inspection until it is purged.
- `JobWorker` in `enterprise/src/ha/job-worker.ts` runs handlers by kind with a concurrency limit, renews each lease, aborts a handler whose lease was lost and drops its result. `stop` waits, then returns unfinished jobs to the queue without using an attempt.
- `openHaJobs` in `packages/cli/src/ha-bridge.ts` checks the license and returns the queue and a worker factory. The server does not enqueue anything yet: Sentinel and workflow runs move onto it when their stores move to the database.
- Tests: a worker against an in-memory queue, and the Postgres queue with competing claimers, dedupe races, lapsed leases and purge. The Postgres tests run only where `ZERO_TEST_POSTGRES_URL` is set.

### Leader election as built

- `LeaderElector` in `enterprise/src/ha/leader.ts` holds one dedicated connection and calls `pg_try_advisory_lock` on it every 5 seconds. A leader checks the same connection with `SELECT 1`. A connection that fails or does not answer within two intervals ends leadership at once, and the server releases the lock when the session ends.
- `HaRuntime` in `enterprise/src/ha/runtime.ts` owns the pool, the queue, the workers and the election for the `scheduler` role. `openHaRuntime` in the bridge opens it.
- Server mode opens the runtime when a shared database is named. A named database that cannot be used stops the start.
- The Sentinel scheduler fires due triggers only on the leader. Every replica still reconciles and observes its own state. Because Sentinel stores are still local SQLite files, a standby replica does not run the triggers in its own file. This is why the docs do not call the server highly available yet.
- Not gated yet: the audit sink and retention, because the audit log is still a local file per replica.
- Tests: a fake server for takeover, connection loss and hangs; real PostgreSQL for five competing replicas, a killed leader session and a handover on stop.

### Readiness as built

- `HaRuntime.healthy()` answers from memory. A timer reads `zero_schema_migrations` every 2 seconds with a 2 second limit. A failed check, or a check that stops completing, makes the replica unhealthy. A later success restores it.
- In server mode `/readyz` returns 503 when this replica's own database or the shared database is unhealthy. `/healthz` stays a liveness check and does not look at the database, so an outage does not make the platform restart every replica.
- The first failure is reported once on stderr, not on every check.
- Tests: a fake pool for failure, recovery and hangs; real PostgreSQL for a dropped schema.

### Graceful drain as built

On SIGTERM a replica with a shared database runs these steps at once, inside the `--shutdown-timeout` deadline:

1. `/readyz` returns 503, so the load balancer stops sending new requests.
2. The replica resigns the scheduler role. Another replica takes it on its next round, within about 5 seconds. This replica starts no more Sentinel triggers.
3. Job workers stop claiming. Running jobs get the rest of the deadline. A job still running at the deadline is aborted and returned to the queue without using an attempt, so another replica runs it from the start.
4. After requests and services finish, the connection pool closes.

A process that is killed instead, or exits after the failsafe, leaves its jobs with a lease that lapses. The next reaper returns them with the attempt counted.

The platform should wait before it sends SIGTERM, so the load balancer sees the 503 first. The Helm chart does this with a preStop delay.

Tests: a fake pool for resignation and repeated calls; real PostgreSQL for a drain that finishes one job, returns another and hands the scheduler role to a second replica. The shutdown order in the server itself has no test of its own.
