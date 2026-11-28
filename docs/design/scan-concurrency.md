# Scaling a batched audit: concurrency and several workers

Tracking issue: #724 (part of #478, #456, #690). Status: the concurrency limit is configurable and rate limits slow every batch (built). The multi-worker mode below is a design only; nothing of it is built.

## Why `--concurrency` was capped at 3

The cap came from `--passes`, not from batches. `a1f9d53bb` (2026-11-19) added `MAX_PARALLEL_PASSES = 3` with the comment "more only crowds the model provider and the console", and the batched scan then reused the same constant for `--concurrency`. No measurement backed 3 for batches. The same limit still holds `--passes` (each pass reads all of the code, so more passes only repeat the load); batches now have their own limit.

## What concurrent batches share

| Shared resource | What happens with more batches | Safe at 16? |
| --- | --- | --- |
| Model provider quota | Every batch is a thread, and each thread can start helpers (`ZERO_SUBAGENT_CONCURRENCY`, 32 at once per thread). In the WebGoat run 58 batches started 102 helper threads, about 2 per batch. A 429 was retried per request only, with the other requests still sending. | Bounded by the provider. Now a 429 holds back every request of the process (see below). |
| Console process | One Node process serves all threads. Each batch polls its status once a second (a window of the last 20 messages), so 16 batches are about 16 small requests a second. | Yes, measured. |
| SQLite (findings database) | The console writes findings; the scan process writes the ledger (`mark`, `addSpend`, `addThread`) through a second connection to the same file. The WASM SQLite engine locks with a `<db>.lock` directory. Writes are a few per batch. | Yes for one scan process. Not for several processes (see below). |
| Memory and CPU | About 1 vCPU and 1 to 2 GB per running thread, from the self-hosted guide. | The machine decides. |
| Budget | A batch gets a share of what is left, minus the shares reserved by batches in flight, and its thread has that share as a cost ceiling. A ceiling is checked on receipts, so each running thread can pass its share by what one more turn costs. | The overshoot grows with the number of batches in flight. Use a provider limit for a hard cap. |

## What changed

- `--concurrency` accepts 1 to `ZERO_SCAN_MAX_CONCURRENCY` (default 8, at most 16; a bad value is ignored). The default is 1.
- A 429 on any request now sets a cooldown for that provider in the whole process (`noteRateLimitCooldown`). The cooldown is the wait the provider asked for (`Retry-After`), capped at 120 s. Every other request of any thread waits for it, plus up to 750 ms of random spread, before it sends. Before, only the request that got the 429 waited.
- When a batch still fails with a rate limit after the engine used up its retries, `runBatches` pauses every worker before it starts another batch or another attempt, with a growing wait (1 to 30 s), and logs it.

## Several workers sharing one audit (design, not built)

### What `--resume` does with two processes today

Both processes read the pending units of the same scan, plan the same batches and run them, so every unit is reviewed twice and paid twice. `mark` is last writer wins, so the ledger stays valid but the duplicated threads' findings are both in the report. The two processes also write the ledger at the same time. In a stress test (two processes, 200 rounds each of `addThread`, `addSpend`, `mark` on one database file), 1 to 3 calls per process failed with `database is locked` and the lost updates left the thread list 3 short and the spend 3 cents short; one of three runs did not finish. A scan process that gets that error stops (the error is not caught in `runBatches`). That is the stress case, not a normal scan, but it rules out several processes writing one SQLite file.

### Proposed design

1. One coordinator owns the ledger. `0security scan <folder> --batches on --serve-ledger` (or the same process under `--workers n`) is the only process that writes it. Workers never open the database file.
2. A worker asks the coordinator for work over the existing authenticated engine HTTP API: `POST /api/scans/<id>/claim` returns one pending batch and a lease (batch number, lease id, expiry, budget share). The coordinator marks the batch `claimed` (a new `status`, shown as pending in every report) in the same transaction that records the lease.
3. The worker runs the batch as it runs one today (a thread on its own console) and reports with `POST /api/scans/<id>/batches/<n>/result`: outcome, cost, thread id, findings of the thread. Findings are uploaded with the result, because the worker's console database is not shared. This is the same shape that `0security findings upload` already uses.
4. Leases expire (default `--batch-timeout` plus 120 s). A worker that dies stops renewing (`POST .../lease`, every 60 s); the coordinator puts the batch back to pending with the reason `lease expired`. A result that arrives for an expired lease whose batch was handed to someone else is kept as findings but does not mark units reviewed twice.
5. Budget is enforced by the coordinator only. It gives each claim a share the same way `batchBudget` does (what is left, minus the shares of live leases, divided by the batches not started), and counts the reported cost. A worker cannot start a thread with more than its share, so the total can pass the budget by at most one turn per live lease, the same bound as in one process.
6. A rate limit is shared: a worker that reports a `provider_rate_limit` failure makes the coordinator hand out no claim for the backoff time. Workers that share one provider account then slow down together.
7. `--resume` stays the recovery path: it takes the pending and claimed units back after a coordinator crash, because the ledger is the only state.

### What breaks or stays open

- The ledger is local SQLite, so the coordinator is a single point of failure and one machine. Running it on several machines needs the PostgreSQL work in `docs/design/ha-server.md`.
- All workers must scan the same commit. The coordinator refuses a worker whose `git HEAD` differs, as `--resume` does today.
- Findings merge: two workers can find one flaw from two batches. The merge that `--passes` and batches already do on the coordinator applies, but it has to run on uploaded findings, not on local threads.
- A worker needs the code and the same model credentials. Credentials stay on the worker; the coordinator never sees them.
- Provider limits bound the gain. Workers on one account share one quota; workers on separate accounts add quota.

### Smaller option with no new code

Split a repository by folder and run one scan per worker, each with its own database, then read the reports together (`--format json` or SARIF). Nothing is shared, so nothing breaks, and the coverage statement of each says what its folder reached. The cost is that no report covers the whole repository and the same flaw can be reported twice.

## Measurements

Same target and flags in every run: OWASP WebGoat (35,209 Java lines, 58 batches), `scan --batches on --concurrency N --budget 5 --timeout 1800 --model gpt-6-luna --prepass off --format json`, model route `ChatGPT (Codex backend)`, one run each, 2026-11-27, on a shared machine whose load changed between runs.

| `--concurrency` | Wall time | Cost | Machine load (1 min average, mean / peak) | Rate limit (429) and connection retries | Batches that failed | Findings | Coverage |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 3 (origin/main build) | 1807 s, stopped by the 1800 s limit | $1.49 | 37 / 141 | none, 0 retries | 0 | 97 | 327 of 327 entry points, 135 of 149 groups; 14 not reached |
| 6 | 1786 s, stopped after failed batches | $1.51 | 11 / 22 | 19 lines with a 429, 8 dropped connections, 24 retries | 4 (3 rate limit after 2 retries, 1 provider `invalid_prompt`) | 108 | 288 of 327 entry points, 144 of 149 groups; 39 and 5 not reached |
| 8 | 693 s | $1.09 | 7 / 13 | none, 2 dropped connections, 2 retries | 0 | 93 | 327 of 327 entry points, 145 of 149 groups; 4 not reached, 29 files never opened |

What the table does and does not show:

- Concurrency 8 finished in 38% of the time of concurrency 3, with no rate limit. But the runs are confounded: the load on the machine fell from 37 to 7 between the first and the last, and the 429s in the concurrency-6 run came from a provider account that other work on this machine also uses. One run each cannot separate the effect of concurrency from the effect of load and of the provider's mood. A fair comparison needs repeated runs on a quiet machine.
- The provider limit is real and shows from 6 batches: the route answered `route_rate_limit_exceeded` with no `Retry-After`, a batch can run out of its 2 retries, and its units stay pending (resume them). It was absent at 8 in the run above, so the limit moves with time and with who else uses the account.
- Findings differ from run to run (93 to 108 here, stochastic); the sets were not compared.
- Cost per run varied from $1.09 to $1.51 with the number of follow-up rounds, not with concurrency.
- Each batch started about 2 helper threads (102, 114 and 92 over 58 batches), so the model sees more parallel requests than `--concurrency` says.
- The scan stopped the first run with "Stopped by the $5 budget" although it had spent $1.49: its last batch hit the time limit. This message was not changed.

Extrapolation to 60 million lines stays arithmetic: 693 s for 35 thousand lines is about 5.5 hours per million lines in one process, still about 14 days for 60 million at concurrency 8, and the cost and finding density change with the code. More workers are the only way past that, within the provider's limit.
