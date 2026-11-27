# Variant hunt with a code-computed candidate checklist

Follow-up to [the hard benchmark](hard-benchmark.md). That benchmark showed `findings variants` finding 1.4 of 8 far-away siblings (53k tokens, about 30 s) while a plain scan that was not told about the seed found 7.2 of 8 (5.85M tokens, about 30 min). The model searched near the fix and stopped early, and models almost never opt into extra tools, so a tool is not the fix. The change here: build the list of sites in code, and let the model only judge them.

## What changed

Before the hunt thread runs, `variantCandidates` (`packages/engine/src/code-index/variant-candidates.ts`) computes a tree-wide list from the recorded root cause:

- **Sink shape.** The call names the root cause gives for the unsafe pattern (`invoiceRepo.findById(id)` gives `findById`), kept only if they are really called in the tree. Every call site is a candidate (same API). Sibling APIs (same receiver kind and verb family) and sibling operations (read, list, update, delete) rank lower. For injection and other non-authorization classes, any call of the same sink category counts as a sibling.
- **Authorization, ownership and missing-guard classes** also add every route the Foxguard graph marks `missingGuard` (`foxguard graph --missing-guard`: reaches a data sink with no auth signal). The binary is found as for the code index (`ZERO_FOXGUARD_PATH`, then `PATH`); without it the built-in TypeScript, JavaScript and Python extractor is used. When the index holds no matching call (for example Java without the binary) a text search over the source files supplies the sites.
- **Guard evidence.** Distinctive words of the missing guard (`orgId` and `findForOrg` give `org`) are looked for in the body of every function on the way from an entry point to the sink. A site with no such word ranks first; one with a word stays in the list, with a `guardHint`, so the model has to cite the guard. A call whose own name carries the guard (`findForOrg`) is scoped by construction and is not listed.
- **Grouping.** One candidate per enclosing function: a helper shared by many callers is one item that lists up to six routes and entry points (jobs, resolvers, message handlers are the functions nothing else calls).
- **Rank, cap, say what is left out.** At most 60 are listed; the prompt says how many were omitted and asks for a little effort on sites the list may have missed, reported under `variants`.

The prompt carries the list as numbered `<candidate>` blocks: id, file, line, symbol, `reachedFrom`, a reason written by the program, an optional guard hint. Never file content; names and routes are cleaned and restricted to a plain character set, and the prompt repeats the #703/#705 rule that all of it is untrusted. The list is split into batches of 20, each judged by a fresh thread in parallel (a long list in one answer lost items and, in two runs, the whole json block). The thread must give one verdict per id in the existing json answer: `variant`, `guarded` (guard cited as `file:line`), `not_reachable` or `unsure`. A candidate marked `variant` is stored as an unverified variant (#705 behaviour: severity capped, confidence 0.4) whose description and analysis carry the candidate id; a variant needs no title or description of its own, they fall back to the candidate and the reason. The report says how many candidates were listed, answered per verdict and left unanswered. A seed with no stored root cause first gets a short thread that only states it. The default tool list is unchanged (seven core tools, no new tool); the `variant-hunting` skill has a new section for the checklist.

## Measurement

`variants-tenant` (frozen fixture, 8 siblings, 18 look-alikes), `gpt-6-luna` through `chatgpt-codex` (subscription, nothing billed), fresh `HOME` per run, `ZERO_CODEX_AUTH_JSON_PATH` only, seed imported from SARIF, root cause derived by the model (no stored one), the same harness command as the hard benchmark with `--arms variants`. 5 runs per configuration, budget $3 per run, no rate limit seen. Raw results: `scripts/bench/code-index-hard/results/variants-candidates*.json`.

| configuration | found of 8 (per run) | false variants | tokens | time |
|---|---|---|---|---|
| before: `findings variants`, no checklist (hard benchmark) | 1.4 (3, 1, 1, 1, 1) | 0.2 | 53k | 32 s |
| before: plain scan, no hint (hard benchmark) | 7.2 (7, 7, 7, 7, 8) | 2 to 5 (decoy hits) | 5.85M | 1074 s |
| A: checklist, one thread for all 60 | 3.8 (6, 6, 0, 0, 7) | 0.2 | 224k | 110 s |
| B: A plus lenient parsing of a `variant` verdict | 1.6 (5, 2, 0 error, 1, 0 no verdicts) | 0 | 244k | 87 s |
| **C: checklist in batches of 20 (final)** | **5.2 (5, 5, 8, 2, 6)** | **0.4 (1, 0, 1, 0, 0)** | **201k** | **83 s** |

False variants are findings the strict oracle assigns to a decoy or a clean file. Configurations A and B are the first two attempts and are reported because the design changed after them; the changes between them were made after seeing failures (the zeros), not tuned on per-sibling results, but the final configuration is the third and not a pre-registered one. One earlier single run (4 of 8) was a smoke test from a checkout that was missing the fixtures' `services` folders (see Caveats).

Per sibling, configuration C (found in n of 5 runs): `vt-quote-pdf` 5, `vt-graphql-subscription` 4, `vt-report-shipment` 4, `vt-contract-service` 3, `vt-import-product` 3, `vt-payment-webhook` 3, `vt-ws-ticket-subscribe` 3, `vt-reminder-job` 1.

Reading it:

- It helps against the hint-only hunt: 5.2 against 1.4 of 8 at about 4 times the tokens, with 0.4 false variants. It does not match the unhinted scan: 5.2 against 7.2 of 8, at 1/29 of the tokens and 1/13 of the time (83 s against 1074 s).
- The recall limit is the judging, not the listing. Of 60 listed, the model marks about 40 `guarded` in every run, including look-alike-shaped real siblings; the reminder job (listed every time, with a guard hint because it mentions an organisation elsewhere) was found once in 5. The hint is a weak signal in both directions.
- Run-to-run variance is large (2 to 8). One source is the derived root cause: the list had 104 sites in most runs and 132 in one, depending on the sink text the model wrote.
- Failure modes seen and handled: an answer with no verdict block (now repeated once per batch, then reported as an error), a transport failure on the provider (one run in B, counted as 0 found).

## Extra seeds

Not run. The planted bugs in `ts-workspace` and `java-ledger` are deliberately ten different families, each with at most one or two relatives, so a seed taken from one of them has no honest set of siblings in the key to score against, and building one by reading the key would be peeking.

## Caveats

- One fixture, one model, 5 runs per configuration; ranges overlap with the old hint-only hunt only at the low end (C ranged 2 to 8, the old hunt 1 to 3).
- The committed fixtures were missing every `src/services` folder because the repository's `.gitignore` ignores `services/`. The earlier measurement ran from a checkout that had them; this branch restores them (regenerated by the frozen generators, every tracked file byte-identical) and adds an ignore exception. Without that fix three of the eight siblings (`vt-contract-service`, `vt-import-product`, `vt-report-shipment`) cannot be found at all from git.
- The guard words are plain substrings of identifiers, so a site that mentions the guard anywhere on its path is ranked low even if the use is unrelated.
- Methods defined in object literals are not joined to their callers by the built-in extractor, so some candidates show no entry point.
