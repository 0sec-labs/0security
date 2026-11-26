# Fix cases: reference-fix check

- Date: 2026-11-26
- Model: none. This is not a model result and says nothing about how often `0security findings fix` succeeds.
- Cases: 14, of which 4 Java

Each row runs the case's own checks twice: on the vulnerable project and with the hand-written reference fix. A valid case has green tests both times, an exploit check that works before and is blocked after, and a rescan that no longer flags the finding. The rescan column names the source of that check: FoxGuard where it flagged the original, a fixed pattern for the vulnerable construct where the case lists one, and n/a where neither applies.

| case | language | category | tests before | tests after | compiles before | compiles after | exploit before | exploit after | rescan | valid |
|---|---|---|---|---|---|---|---|---|---|---|
| command-injection | javascript | command-injection | yes | yes | n/a | n/a | works | blocked | foxguard clean | yes |
| hardcoded-secret | javascript | hardcoded-secret | yes | yes | n/a | n/a | works | blocked | foxguard clean | yes |
| java-command-injection | java | command-injection | yes | yes | yes | yes | works | blocked | foxguard clean | yes |
| java-path-traversal | java | path-traversal | yes | yes | yes | yes | works | blocked | n/a | yes |
| java-unsafe-deserialization | java | deserialization | yes | yes | yes | yes | works | blocked | n/a | yes |
| java-xxe | java | xxe | yes | yes | yes | yes | works | blocked | foxguard clean | yes |
| missing-authz | javascript | missing-authorization | yes | yes | n/a | n/a | works | blocked | n/a | yes |
| open-redirect | javascript | open-redirect | yes | yes | n/a | n/a | works | blocked | n/a | yes |
| path-traversal | javascript | path-traversal | yes | yes | n/a | n/a | works | blocked | n/a | yes |
| prototype-pollution | javascript | prototype-pollution | yes | yes | n/a | n/a | works | blocked | n/a | yes |
| sqli | javascript | sql-injection | yes | yes | n/a | n/a | works | blocked | foxguard clean | yes |
| ssrf-allowlist | javascript | ssrf | yes | yes | n/a | n/a | works | blocked | pattern clean | yes |
| unsafe-eval | javascript | unsafe-deserialization | yes | yes | n/a | n/a | works | blocked | foxguard clean | yes |
| weak-password-hash | javascript | weak-crypto | yes | yes | n/a | n/a | works | blocked | foxguard clean | yes |

Run `node scripts/bench/fix-score.mjs --dry-run --reference-table <file>` to write this table again. Model results per case come from `--run` and are not committed.
