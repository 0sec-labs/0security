# Hard benchmark: multi-hop authorization fixtures, code-index tools and variant hunting

Measured on 2026-11-26/27 with the CLI built from `main` at `0774248c8` (0.46.0, including the graph work of #707) and Foxguard built from `crates/foxguard` in the same checkout. This is the follow-up the [first measurement](code-index-variants-measurement.md) asked for: its fixtures had no headroom (the plain batched scan found 54 of 54 planted bugs), so no tool could show a benefit. Harness: `scripts/bench/code-index/run.mjs` (unchanged apart from the options listed below), fixtures, generators, proofs and raw results in `scripts/bench/code-index-hard/`.

## Result in one paragraph

The new fixtures have headroom. Of 10 planted bugs per fixture, the batched scan found 8.6 to 9.2 on average; the one-thread scan 5.0 (TypeScript) and 8.6 (Java); the shipped skill path (`--skill seedless-depth-review`) 3.6 and 5.4. **The code-index tools did not help**: making them available (`ZERO_TOOLSET=full`) is statistically the same as the plain batched scan (8.8 vs 8.6 and 9.2 vs 8.8 found, ranges overlap), and the model called an index tool once in 10 runs. The skill that does use them (2 or 3 `routes` calls per run, then `spawn_agent`) is clearly worse on recall, as before, but very cheap. The biggest effect in the data is again batching: the batched scan finds more than a single thread on the TypeScript service (8.6 vs 5.0, ranges 8-9 vs 1-7), at 2.6 times the tokens and 5.5 times the wall time (on the Java service, 1.4 and 4.1 times), and it also files many more false positives. `findings variants` did **worse** than a plain scan on this scenario: 1.4 of 8 siblings (1 to 3) against 7.2 of 8 (7 to 8) for a scan that was not told about the seed, though at about 1/110 of the tokens and 1/33 of the time.

## What was built

All three fixtures were generated, proven and committed before any model ran, and not edited afterwards (frozen at `4f3efe4fb`; the first fixture commit is `3a2f2ed40`; branch point `0774248c8`). Generators are deterministic (`generators/gen-*.mjs`; the answer-key line numbers are computed from anchor strings in the generated files, so a key cannot drift from the code).

| fixture | what | files | planted | decoys | files verified correct (`cleanPaths`) |
|---|---|---|---|---|---|
| `ts-workspace` | Express/TypeScript, routes -> services -> repositories, shared `authenticate`/`securityRules`/`resolveOrg` middleware, URL-prefix security rules, 21 generated filler modules in three correct authorization styles | 185 | 10 | 29 | 112 |
| `java-ledger` | Spring Boot 3.5, controllers -> services -> repositories, bearer-token filter, tenant filter, `SecurityFilterChain` with `requestMatchers`, `@PreAuthorize` through an `AccessPolicy` bean, 25 filler modules | 249 | 10 | 35 | 163 |
| `variants-tenant` | Express/TypeScript, 25 CRUD modules, plus jobs, a resolver map, a realtime handler, import, reporting and an inbound webhook; the tenant-scoping fix was made at `GET /api/invoices/:id` only | 109 | 8 siblings (+ the seed) | 18 | 47 |

Planted bugs (all multi-hop, none a missing check in a handler that is plainly unguarded):

- ts-workspace: task history route skips the organisation check that 9 sibling sub-routes get through `taskService.require` (`tw-task-history`); invoice PDF route goes straight to the repository while its siblings use the checked service (`tw-invoice-pdf`); a webhook delivery-log route registered above the router-level manager guard (`tw-webhook-deliveries`); a service reached by an internal route and a public board export (`tw-public-export`); an organisation taken from an `X-Org-Id` header in the one router mounted before the membership check (`tw-billing-org-header`); a markup sanitiser reused to build a storage path (`tw-attachment-filename`); a case-sensitive `startsWith` URL rule against Express's case-insensitive routing (`tw-security-case`); one of three repositories searched without the tenant (`tw-search-comments`); `authorId` taken from a spread request body (`tw-comment-author`); a task moved into a project whose organisation is not checked (`tw-task-move`).
- java-ledger: the same families in Spring form: one of ten vendor endpoints without `@PreAuthorize` (`jl-vendor-bank`), receipt download skipping the checked service (`jl-receipt-download`), a public statement route that verifies the share token's signature but not its subject (`jl-statement-public`), bulk approve taking `approverId` from the body (`jl-bulk-approve`), a tag-stripping helper reused to build an export path (`jl-export-name`), `requestMatchers("/api/admin/*")` leaving nested admin paths open (`jl-admin-nested`), unscoped comment search (`jl-search-comments`), project transfer without a target-tenant check (`jl-project-transfer`), comment author spoofing through a bound body (`jl-comment-author`), tenant header read directly by the billing controller (`jl-billing-header`).
- variants-tenant: eight siblings of the seed in a service, a route that inlines the repository call, a background job enqueued by a route, a GraphQL-style resolver, a realtime message handler, a CSV import, a report that uses a differently named repository helper, and an inbound webhook whose signature covers only the timestamp; 18 look-alikes (explicit org comparison in several shapes, service-token routes, a share link whose claim binds the id, global reference data, a scoped data loader, ...).

**Solvability proof.** Every planted bug is shown by running the code, not by reading it:

- `proofs/ts-workspace/prove.mjs`: runs the real Express 5 app in-process. 49 checks, 12 of 12 exploit checks succeed (one case-bypass and one self-promotion, etc.), the nine sibling routes and every decoy deny, and a sweep of 72 generated filler routes denies a cross-organisation manager and a same-organisation non-owner.
- `proofs/java-ledger/` (Maven, `ExploitProofTest`): Spring Boot 3.5.0 with MockMvc through the real security filter chain. 64 tests, 0 failures: ten exploits, 53 decoy attempts, 112 filler routes (591 requests). J6 is real under Spring Security 6.5: `/api/admin/*` leaves `/api/admin/users/{id}/roles` and `/api/admin/tenants/{id}/limits` open to any signed-in user. Two attackers are managers, not plain users (J4 bulk approve, J8 transfer), because those routes require a manager at all. The proof needs Boot 3.5.0 from Maven Central (`mvn -Dmaven.repo.local=/tmp/ledger-m2 -f scripts/bench/code-index-hard/proofs/java-ledger/pom.xml test`); the local `~/.m2` holds only stubs for 3.5.0.
- `proofs/variants-tenant/prove.mjs`: 54 cases over HTTP: the seed denies, all eight siblings leak or modify across organisations, the 17 look-alike cases deny, and a 26-route sweep.

**Oracle.** `scripts/bench/match.mjs` gained a strict mode, used by every item of these keys (`oracle`): a finding is credited only when (1) its path is the item's or one of its `alsoAt` hops, (2) its lines are within 3 lines of that range (the #710 matcher allowed 5), (3) its category or title is in one of the item's families, and (4) its title or description matches one of the item's `mention` patterns (the route, entity or sink the bug is about). So a finding about the cancel route cannot be credited to the order read next to it, which is how #710 over-credited one run. Matching stays one-to-one. Decoys name the family that counts as a hit, and `cleanPaths` lists every file verified correct, where an authorization-class finding is a false positive. Old keys score as before. The harness stores the loose (#710) score next to the strict one: **they gave the same found count in 49 of 50 runs** (the one exception is one more item credited loosely), so strictness did not change any conclusion. Tests: `scripts/bench/match-strict.test.mjs`.

Harness changes in `run.mjs`: finding descriptions kept in the raw results (for re-scoring), `--variants-dir`, a dry run that checks key lines against the files (it found one `alsoAt` range past the end of the old `java-bank` file, corrected without any effect on a score) and checks every item's own description against its own oracle.

## Design of the runs

- Model `gpt-6-luna`, provider `chatgpt-codex` (read from the saved sessions of every run), subscription, nothing billed. Credentials never read by the harness: fresh `HOME` per run, only `ZERO_CODEX_AUTH_JSON_PATH` passed on. One `pong` call answered first.
- Scan arms, as in the first round: `baseline` (plain batched `0 scan`), `baseline-single` (`--batches off`), `index-skill` (`--skill seedless-depth-review`, the shipped path that loads the pack; one thread), `index-full` (plain scan with `ZERO_TOOLSET=full`, the four tools advertised without a skill). All `--prepass off --budget 3 --timeout 1500`, answer key not in the copy.
- 5 runs per cell, 2 fixtures, 4 arms = 40 scan runs; variants: 5 runs of `findings variants` (seed imported from SARIF, root cause derived by the thread) and 5 runs of a plain batched scan of the same folder, scored on the same eight siblings. Caps set before the runs: 40 and 10 runs, 300 and 180 minutes; stop on a rate limit. **No rate limit appeared; neither time cap was reached** (508 run-minutes of scan across three parallel workers, about 3 h wall).
- No tuning after seeing results: nothing in fixtures, keys, oracle or arms changed after the first run.

## Scan results

Cells are mean (min-max) over the runs; found is by the strict oracle. "scored" counts every run that wrote a report: statuses other than `complete` keep the findings they produced and are listed in the second column (see Caveats).

| fixture | arm | runs scored/total (statuses) | found per run | found mean (range) | loose found mean | false pos. per run | unmatched mean | turns | tokens | time (s) | index tool calls |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ts-workspace | index-skill | 5/5 (5 complete) | 3, 5, 2, 7, 1 of 10 | 3.6 (1.0-7.0) | 3.6 (1.0-7.0) | 0, 0, 0, 0, 0 | 1.0 (0.0-2.0) | 23 (16-30) | 1194k (544k-2006k) | 103 (64-165) | 1.6 (1.0-2.0) |
| ts-workspace | baseline-single | 5/5 (4 complete, 1 failed) | 6, 1, 7, 6, 5 of 10 | 5.0 (1.0-7.0) | 5.0 (1.0-7.0) | 0, 0, 2, 0, 0 | 2.8 (0.0-7.0) | 26 (11-50) | 3205k (348k-8821k) | 243 (73-471) | 0.0 (0.0) |
| ts-workspace | baseline | 5/5 (3 complete, 1 partial, 1 budget_exhausted) | 8, 9, 8, 9, 9 of 10 | 8.6 (8.0-9.0) | 8.6 (8.0-9.0) | 12, 7, 6, 3, 8 | 5.0 (2.0-8.0) | 284 (241-329) | 8477k (7102k-10136k) | 1337 (1169-1508) | 0.0 (0.0) |
| ts-workspace | index-full | 5/5 (5 complete) | 9, 8, 9, 9, 9 of 10 | 8.8 (8.0-9.0) | 9.0 (8.0-10.0) | 4, 4, 10, 6, 7 | 4.6 (2.0-7.0) | 267 (225-303) | 7644k (6010k-9205k) | 1282 (1045-1492) | 0.0 (0.0) |
| java-ledger | index-skill | 5/5 (5 complete) | 5, 2, 6, 7, 7 of 10 | 5.4 (2.0-7.0) | 5.4 (2.0-7.0) | 0, 0, 0, 0, 0 | 0.0 (0.0) | 20 (13-32) | 1457k (666k-2375k) | 120 (59-204) | 0.6 (0.0-2.0) |
| java-ledger | baseline-single | 5/5 (4 complete, 1 failed) | 9, 7, 8, 9, 10 of 10 | 8.6 (7.0-10.0) | 8.6 (7.0-10.0) | 2, 0, 2, 3, 0 | 1.2 (0.0-2.0) | 54 (39-73) | 5504k (4436k-7420k) | 324 (228-469) | 0.0 (0.0) |
| java-ledger | baseline | 5/5 (1 partial, 3 complete, 1 timed_out) | 9, 9, 9, 8, 9 of 10 | 8.8 (8.0-9.0) | 8.8 (8.0-9.0) | 7, 4, 7, 7, 7 | 5.6 (4.0-8.0) | 230 (199-267) | 7539k (6161k-9006k) | 1336 (1195-1511) | 0.0 (0.0) |
| java-ledger | index-full | 5/5 (4 complete, 1 partial) | 9, 9, 10, 9, 9 of 10 | 9.2 (9.0-10.0) | 9.2 (9.0-10.0) | 9, 5, 8, 5, 4 | 3.8 (2.0-5.0) | 239 (207-281) | 7816k (6168k-9478k) | 1346 (1160-1476) | 0.2 (0.0-1.0) |

Pooled over both fixtures (10 runs per arm, 100 planted items each): `index-full` 90 found, `baseline` 87, `baseline-single` 68, `index-skill` 45. False positives pooled (decoy or clean-file hits by the key): `baseline` 68, `index-full` 62, `baseline-single` 9, `index-skill` 0.

Reading it:

- **There is headroom now.** No arm found everything; the best arms found 8 to 10 of 10 per run, and two bugs were nearly out of reach for everyone: `tw-security-case` (the case-sensitive URL rule: found once in 20 runs, by one `baseline` run) and `tw-webhook-deliveries` for the one-thread arms (0 of 10 in `baseline-single` and `index-skill`, 10 of 10 in the batched arms).
- **index-full versus baseline** (are the tools available): 8.8 (8-9) vs 8.6 (8-9) on `ts-workspace`, 9.2 (9-10) vs 8.8 (8-9) on `java-ledger`. The differences are 0.2 and 0.4 of an item, inside the run-to-run range. The model called an index tool once in these 10 runs. As in round 1, advertising the tools without telling the model to use them changes nothing; it is not evidence about the tools when used.
- **index-skill versus baseline-single** (the fair pair, both one thread): 3.6 vs 5.0 and 5.4 vs 8.6. It found fewer on most bugs in both fixtures, but the ts-workspace ranges overlap (1-7 vs 1-7) so only the Java gap (2-7 vs 7-10) looks real. It is by far the cheapest (about 1.2M tokens and 2 minutes against 3 to 5M and 4 to 5 minutes) and filed no false positives; it stops after 13 to 32 turns and only uses `routes` and `spawn_agent` (child threads are not in the saved sessions, so its token and turn counts may be incomplete).
- **Batched versus one thread**: `ts-workspace` 8.6 (8-9) vs 5.0 (1-7), `java-ledger` 8.8 (8-9) vs 8.6 (7-10). Batching decides the TypeScript result and not the Java one. It costs 2.6 and 1.4 times the tokens (8.5M vs 3.2M, 7.5M vs 5.5M) and 5.5 and 4.1 times the time (1337 s vs 243 s, 1336 s vs 324 s), and files many more decoy hits (below).
- **Bugs only some arms found** (rate over 5 runs; bugs where the arms differ by more than a run or two): `tw-webhook-deliveries` batched 5/5 and 5/5, one-thread 0/5, skill 0/5; `tw-comment-author` index-full 5/5, baseline 4/5, single 1/5, skill 0/5; `tw-task-history` batched 5/5, single 4/5, skill 1/5; `jl-vendor-bank` (one of ten endpoints without `@PreAuthorize`) baseline-single 5/5, index-skill 2/5, index-full 1/5, **baseline 0/5**: the only bug that the batched default misses and a single thread finds; `jl-bulk-approve` batched 5/5, single 4/5, skill 1/5; `jl-export-name` batched 5/5, single 5/5, skill 1/5; `tw-attachment-filename` index-full 4/5, baseline 3/5, skill 1/5, single 0/5. The per-bug tables follow.
- **False positives.** By the key, the batched arms hit decoys or clean files 3 to 12 times per run, the one-thread scan 0 to 3, the skill never. Reading a sample of the hits: some are wrong claims (a finding that expired share tokens are accepted although `expiresAt` is checked), but many are defensible, not false: a service-token route that trusts any project id once the shared token is presented, private-visibility tasks listed to every member of the organisation, managers able to edit another employee's draft, a finding that a public share route does not bind the token to the id (which is the planted `jl-statement-public`, reported at the neighbouring share endpoint and so counted as a decoy hit instead of a find). The false-positive column is therefore an **upper bound** produced by a key with located decoys, and it penalises arms that report more; the batched arms' higher recall and higher false-positive counts come from the same behaviour (reporting more).

## Per-bug results

### Scan: ts-workspace: runs that found each planted bug

| bug | index-skill | baseline-single | baseline | index-full |
|---|---|---|---|---|
| tw-invoice-pdf | 3/5 | 4/5 | 5/5 | 5/5 |
| tw-billing-org-header | 5/5 | 5/5 | 5/5 | 5/5 |
| tw-task-move | 4/5 | 4/5 | 5/5 | 5/5 |
| tw-task-history | 1/5 | 4/5 | 5/5 | 5/5 |
| tw-webhook-deliveries | 0/5 | 0/5 | 5/5 | 5/5 |
| tw-public-export | 2/5 | 3/5 | 5/5 | 5/5 |
| tw-attachment-filename | 1/5 | 0/5 | 3/5 | 4/5 |
| tw-security-case | 0/5 | 0/5 | 1/5 | 0/5 |
| tw-search-comments | 2/5 | 4/5 | 5/5 | 5/5 |
| tw-comment-author | 0/5 | 1/5 | 4/5 | 5/5 |

Bugs whose find rate differs between arms (9):

- tw-invoice-pdf: index-skill 3/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- tw-task-move: index-skill 4/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- tw-task-history: index-skill 1/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- tw-webhook-deliveries: index-skill 0/5, baseline-single 0/5, baseline 5/5, index-full 5/5
- tw-public-export: index-skill 2/5, baseline-single 3/5, baseline 5/5, index-full 5/5
- tw-attachment-filename: index-skill 1/5, baseline-single 0/5, baseline 3/5, index-full 4/5
- tw-security-case: index-skill 0/5, baseline-single 0/5, baseline 1/5, index-full 0/5
- tw-search-comments: index-skill 2/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- tw-comment-author: index-skill 0/5, baseline-single 1/5, baseline 4/5, index-full 5/5

False positives by arm and place (decoy id or clean file; count of runs): baseline-single: tw-d-internal-export x1; baseline: tw-d-internal-export x3; baseline: tw-d-public-invoice x1; baseline: tw-d-task-require x2; baseline: tw-d-project-export x1; baseline: tw-d-resolve-org x1; index-full: tw-d-internal-invoice x4; index-full: tw-d-task-require x2; index-full: tw-d-internal-export x2; index-full: tw-d-public-invoice x1; index-full: tw-d-integration-comment x1

### Scan: java-ledger: runs that found each planted bug

| bug | index-skill | baseline-single | baseline | index-full |
|---|---|---|---|---|
| jl-vendor-bank | 2/5 | 5/5 | 0/5 | 1/5 |
| jl-receipt-download | 5/5 | 5/5 | 5/5 | 5/5 |
| jl-statement-public | 4/5 | 5/5 | 5/5 | 5/5 |
| jl-admin-nested | 4/5 | 4/5 | 5/5 | 5/5 |
| jl-project-transfer | 3/5 | 5/5 | 5/5 | 5/5 |
| jl-bulk-approve | 1/5 | 4/5 | 5/5 | 5/5 |
| jl-export-name | 1/5 | 5/5 | 5/5 | 5/5 |
| jl-search-comments | 2/5 | 4/5 | 5/5 | 5/5 |
| jl-comment-author | 2/5 | 1/5 | 4/5 | 5/5 |
| jl-billing-header | 3/5 | 5/5 | 5/5 | 5/5 |

Bugs whose find rate differs between arms (9):

- jl-vendor-bank: index-skill 2/5, baseline-single 5/5, baseline 0/5, index-full 1/5
- jl-statement-public: index-skill 4/5, baseline-single 5/5, baseline 5/5, index-full 5/5
- jl-admin-nested: index-skill 4/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- jl-project-transfer: index-skill 3/5, baseline-single 5/5, baseline 5/5, index-full 5/5
- jl-bulk-approve: index-skill 1/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- jl-export-name: index-skill 1/5, baseline-single 5/5, baseline 5/5, index-full 5/5
- jl-search-comments: index-skill 2/5, baseline-single 4/5, baseline 5/5, index-full 5/5
- jl-comment-author: index-skill 2/5, baseline-single 1/5, baseline 4/5, index-full 5/5
- jl-billing-header: index-skill 3/5, baseline-single 5/5, baseline 5/5, index-full 5/5

False positives by arm and place (decoy id or clean file; count of runs): baseline-single: jl-decoy-expense-references x1; baseline-single: jl-decoy-integration-comment x2; baseline-single: jl-decoy-template-publish x1; baseline: jl-decoy-integration-comment x2; baseline: jl-decoy-project-update x1; baseline: jl-decoy-statement-user x1; baseline: jl-decoy-tag-controller x1; baseline: jl-decoy-admin-stats x1; baseline: jl-decoy-expense-get x1; baseline: jl-decoy-template-publish x1; baseline: jl-decoy-note-linked x1; index-full: jl-decoy-integration-comment x2; index-full: jl-decoy-expense-get x1; index-full: jl-decoy-expense-references x1; index-full: jl-decoy-project-update x2; index-full: jl-decoy-template-publish x1

## Variant hunting (scenario 2)

| fixture | arm | runs scored/total (statuses) | found per run | found mean (range) | loose found mean | false pos. per run | unmatched mean | turns | tokens | time (s) | index tool calls |
|---|---|---|---|---|---|---|---|---|---|---|---|
| variants-tenant | variants | 5/5 (5 complete) | 3, 1, 1, 1, 1 of 8 | 1.4 (1.0-3.0) | 1.4 (1.0-3.0) | 1, 0, 0, 0, 0 | 0.0 (0.0) | 5 (4-6) | 53k (46k-63k) | 32 (24-38) | 0.0 (0.0) |
| variants-tenant | plain-scan | 5/5 (5 complete) | 7, 7, 7, 7, 8 of 8 | 7.2 (7.0-8.0) | 7.2 (7.0-8.0) | 5, 2, 4, 2, 2 | 5.4 (3.0-9.0) | 204 (174-236) | 5850k (5022k-6607k) | 1074 (1019-1212) | 0.0 (0.0) |

### Variants: variants-tenant: runs that found each planted bug

| bug | variants | plain-scan |
|---|---|---|
| vt-contract-service | 1/5 | 5/5 |
| vt-quote-pdf | 4/5 | 5/5 |
| vt-graphql-subscription | 1/5 | 5/5 |
| vt-reminder-job | 1/5 | 5/5 |
| vt-ws-ticket-subscribe | 0/5 | 5/5 |
| vt-import-product | 0/5 | 5/5 |
| vt-report-shipment | 0/5 | 5/5 |
| vt-payment-webhook | 0/5 | 1/5 |

Bugs whose find rate differs between arms (8):

- vt-contract-service: variants 1/5, plain-scan 5/5
- vt-quote-pdf: variants 4/5, plain-scan 5/5
- vt-graphql-subscription: variants 1/5, plain-scan 5/5
- vt-reminder-job: variants 1/5, plain-scan 5/5
- vt-ws-ticket-subscribe: variants 0/5, plain-scan 5/5
- vt-import-product: variants 0/5, plain-scan 5/5
- vt-report-shipment: variants 0/5, plain-scan 5/5
- vt-payment-webhook: variants 0/5, plain-scan 1/5

False positives by arm and place (decoy id or clean file; count of runs): variants: vt-decoy-invoice-void x1; plain-scan: vt-decoy-credit-notes x1; plain-scan: vt-decoy-invoice-void x1

- **`findings variants` found 1.4 of 8 siblings on average (1 to 3), a plain scan that was never told about the seed found 7.2 (7 to 8).** The hunt ran 4 to 6 turns, 46k to 63k tokens and 24 to 38 s and reported one finding in four of five runs (four in the first); the scan ran about 175 to 235 turns and 1020 to 1210 s. The hunt's finding that was credited most often was the quote PDF route (4 of 5), the sibling that most resembles the seed. It never found the realtime handler, the import, the report or the webhook.
- This reverses the first round's result (6 of 6 versus 3 of 6): there the siblings sat next to the fixed route in two files, here they are in other modules and layers and the scan has a 109-file folder in which every piece of code is reviewed in batches. The hunt did not search beyond a few turns. It is as designed a cheap pass, not an exhaustive one, but on this scenario it is not a substitute for a scan, and it cost 1/110 of the tokens.
- `vt-payment-webhook` (signature covers only the timestamp, so it is replayable across accounts) was found once in 10 runs overall.
- Plain scan false positives: 2 to 5 per run against the 18 look-alikes; the hunt filed one (the invoice void route) in five runs. Same caveat as above about defensible findings.
- The root cause was derived by the thread in all five runs (`rootCauseSource: derived`); a hunt after `findings verify` or `findings fix` recorded the root cause was not measured.

## Caveats

- **A second harness run shared the account.** During the first part of the scan another session was running the same harness against the same Codex login (two parallel workers), so wall times and the two transport failures include contention that is not the same for every cell. Times are interleaved across arms and should be read as order of magnitude.
- **Statuses.** Of 40 scan runs 33 are `complete`; the rest produced a report and are scored with the findings they had: 2 `failed` (one-thread arm, ChatGPT transport failure `UND_ERR_SOCKET` after 73 s and 295 s), 3 `partial` (coverage cut short: "stopped by an earlier run" in two batched runs, an `invalid_prompt` error in one `index-full` run), 1 `budget_exhausted` (batched TypeScript, stopped by the $3 budget with 8 of 210 entry points not reached), 1 `timed_out` (batched Java, 1500 s). Scoring only the complete runs changes the one-thread arms from 5.0 to 6.0 (TypeScript) and from 8.6 to 9.0 (Java), and nothing else by more than 0.1 of an item. The per-run found counts and statuses are in the raw JSON.
- **Counts are small and the keys are ours.** 5 runs per cell, one model at medium reasoning, fixtures written by the team (partly by sub-agents) in a way that follows the shapes the skill text describes. A one-item difference is inside the spread. The fixtures are generated: the filler modules are templated, which a model might exploit (and it makes the files that matter easier to find among 185 or 249, not harder). Two comments in `java-ledger` are accurate or stale on purpose (a `TenantFilter` note that the invoicing job is exempt; a `SecurityConfig` note that admin endpoints are limited to administrators, which is stale for nested paths), and two comments in `ts-workspace` say that callers are expected to authorize (`exportProject`) and who calls the billing routes.
- **Planted bugs are judgments.** `tw-webhook-deliveries` (a read route above a manager guard) and `tw-public-export` (the service returns private tasks) are bugs by the fixture's intent, which the key states; a reviewer may call the first a design choice. `tw-security-case` and `jl-vendor-bank` are the hardest and drive most of the batched-versus-single difference per bug.
- **Unmatched findings were not reviewed one by one** (2 to 8 per run in the batched arms). Some are real unplanted issues in the generated code; they are neither credited nor counted as false positives.
- **Index tools were barely exercised**: one call in the 10 `index-full` runs, 0.6 to 1.6 per run in the skill runs. The Foxguard graph backend, including the URL-rule mapping of #707, was effectively not measured. Foxguard was built and picked up (`ZERO_FOXGUARD_PATH`).
- Token and turn counts of the skill runs count the main thread only.

## Follow-ups

1. **Make the scan use the tools, then re-measure.** The two measurements agree that a model that is only told the tools exist does not use them. Put one line in the scan skill, or load the pack in batch threads, and run this benchmark again: the headroom now exists.
2. **The skill path should not be one thread without a coverage statement** (still open from round 1); its recall here is 45 of 100 against 87 for the batched default.
3. **Decide what the default is for 150 to 250 file services**: batched finds about 1.7 more of 10 on TypeScript for 2.6 times the tokens, and nothing on Java; its false-positive count is about 7 times higher in this key. `jl-vendor-bank` shows a bug only the one-thread scan finds, so a union of both is worth testing.
4. **`findings variants` needs a wider search for siblings in other layers** (service, job, resolver, handler, import): it stopped after 4 to 6 turns with one finding. A hunt that lists the unscoped data-access calls of the root cause across the folder, as the scan does for its batch, is the obvious next change.
5. **The case-sensitive URL rule (`tw-security-case`) was found once in 20 scan runs**: a rule that checks path-matching semantics (case, trailing slash, encoded separators) of a URL rule table against the framework's router is a candidate check for Foxguard.
6. **Re-score with a reviewed false-positive list.** About half of the decoy hits read as defensible; a person-reviewed list would give a cleaner false-positive rate.
7. Variant hunting after `findings verify`/`fix` recorded the root cause, and a second language for the variant scenario, are still not measured.

## Reproduce

```bash
# frozen fixtures, generators and proofs
node scripts/bench/code-index-hard/generators/gen-ts-workspace.mjs
node scripts/bench/code-index-hard/generators/gen-java-ledger.mjs
node scripts/bench/code-index-hard/generators/gen-variants-tenant.mjs
git status --short scripts/bench/code-index-hard   # must stay clean: the output is the committed fixture
node scripts/bench/code-index-hard/proofs/ts-workspace/prove.mjs
node scripts/bench/code-index-hard/proofs/variants-tenant/prove.mjs
mvn -Dmaven.repo.local=/tmp/ledger-m2 -f scripts/bench/code-index-hard/proofs/java-ledger/pom.xml test

# model runs (build the CLI with pnpm build and Foxguard with bash scripts/build-foxguard.sh first)
node scripts/bench/code-index/run.mjs --dry-run --fixtures ts-workspace,java-ledger --fixtures-dir scripts/bench/code-index-hard/fixtures
node scripts/bench/code-index/run.mjs --run --mode scan --label hard --fixtures ts-workspace,java-ledger --fixtures-dir scripts/bench/code-index-hard/fixtures --repeat 5 --budget 3 --timeout 1500 --max-runs 40 --max-minutes 300 --concurrency 3 --out scripts/bench/code-index-hard/results
node scripts/bench/code-index/run.mjs --run --mode variants --label hard --variants-dir scripts/bench/code-index-hard/variants --repeat 5 --budget 3 --timeout 1500 --max-runs 10 --max-minutes 180 --concurrency 2 --out scripts/bench/code-index-hard/results
node scripts/bench/code-index-hard/report.mjs scripts/bench/code-index-hard/results/scan-hard-*.json
```

Raw per-run results (findings with titles, categories, descriptions and locations, strict and loose scores, counts, tokens, seconds): `scripts/bench/code-index-hard/results/scan-hard-2026-11-27T00-23-19-506Z.json` and `variants-hard-2026-11-27T01-22-08-713Z.json`. They contain no credentials.
