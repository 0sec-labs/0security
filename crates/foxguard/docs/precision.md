# Precision and false-positive methodology

> Status: 2026-09-17. Source behavior; release and hosted deployment are separate.

This document describes how foxguard measures rule precision, how the built-in
rules are classified, and the known false-positive patterns we have seen and
tuned for. It is the honest, technical counterpart to the marketing-facing
coverage table in the [README](../README.md).

It is also the document [issue #9](https://github.com/0sec-labs/foxguard/issues/9)
asks for: rather than publishing a single global "precision number" without
context, we publish a per-rule tier classification, a labeled OSS precision
corpus, and an explicit list of the false-positive patterns we already know
about.

If you want the one-line version: foxguard rules fall into three tiers — tight
structural matches, intentionally-loud conservative sink rules, and
heuristic/regex-based rules — plus a fourth taint-based tier that trades recall
for precision. The labeled corpus is intentionally small and reviewed rather
than broad and unlabeled; use it as a regression baseline, not as a universal
claim about every repository.

## Section 1: Methodology

foxguard measures rule quality with four artifacts that all live in the repo:

1. **Positive fixtures** under `tests/fixtures/vulnerable_*.{py,js,rs,...}`
   and `tests/fixtures/vulnerable.{py,js,go,rs,java,php,rb,cs,swift}`. These
   are hand-crafted files with one vulnerable flow per function. Every handler
   should fire exactly once for the rule it targets. The integration tests in
   `tests/` assert that: if a positive fixture stops matching, CI fails. This
   is our **recall floor**.

2. **Negative fixtures** under `tests/fixtures/safe*.{py,js,go}`,
   `tests/fixtures/safe_py_taint.py`, `tests/fixtures/safe_js_taint.js`, and
   `tests/fixtures/safe_py_aliases.py`. These contain patterns that *look*
   dangerous but are not — for example, Django settings that read
   `SECRET_KEY` from `os.environ`, SQL-ish strings with no interpolation, or
   import aliases that rename safe functions. The integration tests assert
   these produce **zero findings**. This is our **precision floor** for the
   patterns we already know about.

   Sitting between the one-function-per-case positive fixtures and the real-
   world corpus scans is a **realistic test corpus** under
   `tests/fixtures/realistic/`. Each file there is a small-but-complete
   vulnerable application for one supported framework (Flask, Django,
   FastAPI, a CLI tool, Express, Next.js, Hono) with idiomatic routing,
   helper functions that exercise interprocedural propagation, and 2–3
   explicitly-labelled `NEAR MISS` functions per file whose patterns the
   engine might be tempted to flag but should not. The integration test
   `tests/realistic_fixtures.rs` pins the exact total finding count and the
   exact count per taint rule for every file. Any rule addition or engine
   change that shifts these counts forces explicit acknowledgement — which
   is how we catch end-to-end precision regressions that neither the
   single-function fixtures nor the public corpus scan would notice.

3. **Labeled OSS precision corpus.** `benchmarks/precision/corpus.toml` pins
   Express, Flask, Echo, and OWASP Juice Shop by full commit SHA. Every current
   foxguard finding in those scan scopes has a row in
   `benchmarks/precision/labels.jsonl` with one of `true_positive`,
   `false_positive`, or `unsure`, plus a one-line review justification. Run:

   ```sh
   ./benchmarks/precision/run.sh --check
   ```

   The command clones the corpus, scans it, joins findings to labels, and
   writes `benchmarks/precision/results/summary.md` plus machine-readable
   `summary.json`. The blessed snapshot in
   `benchmarks/precision/expected.json` currently covers 48 findings:
   16 true positives, 32 false positives, 0 unsure. Reviewed precision is
   **33.3%** and reviewed noise is **66.7%** on this seed corpus. That number is
   deliberately not softened: it shows the noisy rule families we need to fix,
   especially broad path traversal, hardcoded-secret, and framework-helper
   heuristics.

   CI validates the corpus metadata on every PR, and the scheduled
   `.github/workflows/precision-nightly.yml` run executes the full corpus,
   uploads the dashboard artifact, and fails if reviewed precision drops or
   reviewed noise rises beyond the thresholds in `corpus.toml`.

4. **Real-world corpus scans.** We have run foxguard against the latest HEAD of
   Express, Flask, Gin, Laravel, Rails (actionpack), Spring Petclinic, and a
   Next.js starter — 799 files, 369 findings, 0.86 seconds total. Numbers and
   per-repo breakdown are in the blog post
   [*I scanned Express, Flask, Rails, Gin, and Laravel for security
   issues*](https://foxguard.dev/blog/scanning-top-frameworks). That scan is
   the basis for the tier classifications in Section 2 — rules that produced
   review-worthy findings on framework source code versus rules that stayed
   silent are what informed the tight/conservative/heuristic split.

### Metrics we track

- **Recall on positive fixtures:** `(# findings on positive fixture) /
  (# expected findings)`. For well-constructed fixtures this is 1.0, and CI
  fails if it drops. This does **not** measure recall on real code — a hand-
  crafted fixture is not a representative corpus.
- **Reviewed precision on the labeled corpus:** `TP / (TP + FP)` over labels in
  `benchmarks/precision/labels.jsonl`, excluding `unsure` from the denominator.
  The current seed-corpus snapshot is 33.3% reviewed precision and 66.7%
  reviewed noise. This is a regression baseline, not a global product claim.
- **False-positive footprint on broader real code:** the count of findings our
  engineers reviewed on the seven-framework corpus and classified as "not a
  real issue." Section 3 lists every false-positive *pattern* we found and
  fixed; the labeled precision corpus is now the durable place to track these
  classifications over time.
- **Noise ratio:** findings in test/example/vendored directories versus
  findings in production code. foxguard ships a built-in noise filter in
  `src/engine/scanner.rs` that skips `vendor/`, `node_modules/`,
  `__fixtures__/`, `__mocks__/`, `dist/`, `build/`, `.next/`, `coverage/`,
  and `.cache/`, and also skips `.min.js`/`.min.css` files and any file whose
  first line is longer than 1000 characters (a minified-bundle heuristic).
  This is the single biggest FP-reduction lever and it runs by default.

### What this methodology is not

It is not a universal precision claim for all codebases. The labeled corpus is
a pinned, reviewed seed set designed to catch regressions and expose noisy rule
families. It will grow over time, but users should still treat the per-rule tier
classification and the known false-positive notes as the context for deciding
which rules to gate in their own repositories.

## Section 2: Rule classifications

Every built-in rule is placed in one of four tiers based on how its
implementation decides to fire. The tier is a property of the *rule design*,
not of a measured FP rate. The rule IDs below are the exact identifiers
emitted in foxguard's output and match the strings in `src/rules/*.rs`.

### Tier 1 — Tight (structural match on a specific shape)

These rules match a very specific AST or configuration shape where a positive
match is almost always a real issue. Expected FP rate is low.

**JavaScript / TypeScript**

- `js/jwt-none-algorithm` — flags `algorithm: 'none'` in a `jsonwebtoken`
  options object. The shape is unambiguous.
- `js/jwt-hardcoded-secret`, `js/jwt-ignore-expiration`,
  `js/jwt-decode-without-verify`, `js/jwt-verify-missing-algorithms` — all
  structural matches on `jsonwebtoken` call shapes.
- `js/express-no-hardcoded-session-secret`,
  `js/express-cookie-no-secure`, `js/express-cookie-no-httponly`,
  `js/express-cookie-no-samesite`,
  `js/express-session-saveuninitialized-true`,
  `js/express-session-resave-true` — all match on Express
  `session()`/`cookie()` option objects with a specific key/value.
- `js/no-cors-star` — `cors({ origin: '*' })` or equivalent.

**Python**

- `py/django-secret-key-hardcoded`, `py/flask-secret-key-hardcoded` —
  assignment to `SECRET_KEY` with a string literal, excluding values that
  come from `os.environ`/`os.getenv`.
- `py/flask-debug-mode`, `py/no-debug-true` — `app.run(debug=True)` and
  `DEBUG = True` at module scope.
- `py/session-cookie-*`, `py/csrf-cookie-*`, `py/wtf-csrf-*`,
  `py/django-allowed-hosts-wildcard`, `py/secure-ssl-redirect-disabled`,
  `py/csrf-exempt` — all structural matches on Django/Flask-WTF config keys.

**Rust**

- `rs/tls-verify-disabled` — `danger_accept_invalid_certs(true)` in reqwest
  or `danger().set_certificate_verifier(...)` in rustls.
- `rs/transmute-usage` — any call to `std::mem::transmute`. Rare enough in
  real code to be worth flagging on sight.

**Go**

- `go/gin-no-trusted-proxies` — `SetTrustedProxies(nil)` on a Gin engine.
- `go/insecure-tls-skip-verify` — `InsecureSkipVerify: true` in a
  `tls.Config` literal.
- `go/net-http-no-timeout` — `http.Server{...}` struct literal with no
  `ReadTimeout`/`WriteTimeout` field.

**Java**

- `java/spring-csrf-disabled`, `java/spring-cors-permissive` — structural
  matches on Spring Security builder calls.
- `java/no-xxe` — specific parser factory configurations.

**C#**

- `cs/no-xxe`, `cs/no-cors-star` — structural matches on
  `XmlReaderSettings`/`UseCors` call shapes.

**PHP**

- `php/no-extract` — any call to `extract()` on a superglobal.

**Swift**

- `swift/no-tls-disabled`, `swift/no-insecure-transport`,
  `swift/no-insecure-keychain` — configuration-value matches on
  `URLSessionConfiguration`, `NSAppTransportSecurity`, and Keychain
  attribute dictionaries.

Rationale: a match here requires the user to have written out the specific
dangerous shape. The regex-or-pattern surface is narrow enough that benign
code almost never looks like this.

### Tier 2 — Conservative (intentional high-recall sink rules)

These rules fire on *any* occurrence of a dangerous primitive, with no
attempt to decide whether the data is user-controlled. They are deliberately
loud. The point is recall: you will get a finding every time the primitive
is used, and it is the reviewer's job to decide whether that use is safe in
context. In exchange, you get zero false negatives on the primitive itself.

- `py/no-eval`, `py/no-pickle`, `py/no-yaml-load` — any call to `eval`,
  `pickle.loads`, `yaml.load` (without `SafeLoader`). Alias-aware via
  `ImportAliases`.
- `rs/unsafe-block` — every `unsafe { }` block.
- `rs/no-unwrap-in-lib` — every `.unwrap()` in a `lib.rs` target.
- `php/no-eval`, `php/no-unserialize`, `php/no-preg-eval`,
  `php/no-file-inclusion` — any occurrence of the dangerous primitive.
- `rb/no-eval` — `eval` and `instance_eval` calls. `class_eval`/`module_eval`
  are deliberately excluded (see Section 3).
- `java/no-unsafe-deserialization` — `ObjectInputStream.readObject` on any
  stream.
- `cs/no-unsafe-deserialization` — `BinaryFormatter` / `NetDataContractSerializer`.
- `swift/no-eval-js` — `WKWebView.evaluateJavaScript`.

Rationale: if you use one of these primitives, you own the review. foxguard
will not pretend to know whether the input is sanitized. The rule doc string
says "avoid" or "review" rather than "this is definitely a bug."

### Tier 3 — Heuristic (pattern- or regex-based, context-dependent)

These rules match on patterns that *correlate* with bugs but need human
context to confirm. They are where most known false positives live.

- `js/no-sql-injection` — requires a SQL keyword followed by SQL structure
  (`SELECT ... FROM`, `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`,
  `DROP/ALTER/CREATE TABLE`) in the literal, plus string concatenation or
  template interpolation. `EXEC`/`EXECUTE` additionally require the expression
  to be the SQL argument of `.query()`, `.execute()`, or `.raw()`; the same
  words in shell commands are not SQL evidence. See commit `13ea1ae` — earlier
  versions matched `res.send('delete ' + name)` and were retightened.
- `py/no-sql-injection`, `go/no-sql-injection`, `rb/no-sql-injection`,
  `php/no-sql-injection`, `java/no-sql-injection`, `cs/no-sql-injection`,
  `rs/no-sql-injection`, `swift/no-sql-injection` — same family, same
  limitation: without taint we cannot tell whether the interpolated value is
  user-controlled.
- `js/no-hardcoded-secret`, `py/no-hardcoded-secret`, and the per-language
  equivalents — regex on variable names (`password`, `secret`, `api_key`,
  `token`, `auth`, `credential`, `private_key`) assigned to string literals
  of length ≥ 4. Matches test fixtures with `password = "hunter2"` as
  intended; will also match legitimate constants named `*_TOKEN_HEADER` or
  `API_KEY_PARAM` that hold a parameter *name* rather than a value.
- `js/no-xss-innerhtml`, `js/no-document-write`, `js/no-unsafe-format-string`
  — flag dangerous DOM sinks without deciding whether the argument is
  tainted.
- `js/no-command-injection`, `py/no-command-injection`, and the per-language
  equivalents — flag `exec`/`spawn`/`Runtime.exec`/`os.system`/`shell=True`
  on any argument, not only tainted ones.
- `js/no-ssrf`, `py/no-ssrf`, `go/no-ssrf`, `rs/no-ssrf`, etc. — flag HTTP
  client calls with any non-constant URL argument.
- `js/no-path-traversal`, `py/no-path-traversal`, etc. — flag filesystem
  calls with path concatenation.
- `js/no-prototype-pollution`, `js/no-unsafe-regex` — AST patterns that
  correlate with bugs but require reviewer judgement.
- `py/no-weak-crypto`, and `*/no-weak-crypto` family — flag `md5`, `sha1`,
  `DES`, `RC4`. False positive on legitimate non-security uses (content
  addressing, cache keys, Git-compatible hashing).
  Java is the exception: `java/weak-hash` (CWE-328) and `java/no-weak-crypto`
  (CWE-327) resolve a constant algorithm name (literal, `static final`
  constant, single-assignment local, `+` concatenation) and report only when
  it is broken. A name that is not a constant is not reported, and neither is
  one read from configuration such as `props.getProperty("alg", "SHA-256")`:
  the literal there is a fallback, not the algorithm in use.
- `hygiene/java-weak-random` (CWE-330, low) — `new java.util.Random()` and
  `Math.random()` outside test sources. Hygiene, not a vulnerability claim:
  it is only a problem where the value guards something. Filter the
  `hygiene/` namespace to drop it.

Rationale: these rules answer "is a dangerous primitive used with
non-constant input?" Without flow analysis we cannot answer the stronger
question "is that input user-controlled?" The taint rules below are the
precision-focused alternative.

### Tier 4 — Taint (flow-sensitive, precision-first)

These rules reuse the intraprocedural taint engine documented in
[docs/taint-tracking.md](./taint-tracking.md). They fire only when the engine
can prove a flow from a known source (e.g. `request.args.get`, `req.body`)
into a known sink (e.g. `pickle.loads`, `innerHTML`) within a single function
body, with no intervening sanitizer. They have **near-zero false positives
within their scope** but higher false negatives than their conservative
counterparts — anything interprocedural, cross-file, or involving a flow
shape the engine does not model will be missed.

Python source coverage spans Flask, Django, and FastAPI/Starlette request
attributes, plus common CLI-tool inputs (`sys.argv`, `sys.stdin`, `input()`,
`os.environ`, `os.getenv`). Handler parameters named `request` or `req` are
treated as implicit sources. See `python_taint_sources()` in
`src/rules/python_taint.rs` for the canonical list.

- `py/taint-pickle-deserialization`
- `py/taint-eval`
- `py/taint-command-injection`
- `py/taint-ssrf`
- `py/taint-yaml-load`
- `py/taint-sql-injection`
- `js/taint-xss-innerhtml`
- `go/taint-command-injection`
- `go/taint-sql-injection`
- `go/taint-ssrf`

Go source coverage spans net/http handler parameters (`r`, `req`,
`request`), Gin `*Context` methods (`c.Query`, `c.PostForm`, `c.Param`,
`c.GetHeader`, `c.FormValue`, ...), Echo `c.QueryParam`, Fiber
`c.Params` / `c.Query`, and generic `os.Getenv` / `os.Args`. The
engine propagates taint through method calls on tainted receivers,
`fmt.Sprintf` wrapping, `+` string concatenation, one-level selector
and index chains, and Go's native multi-return destructuring
(`a, b := f()`). Interprocedural return summaries are computed per
file and keyed by function / method simple name. See
`go_taint_sources()` in `src/rules/go_taint.rs` for the canonical
source list and `docs/taint-tracking.md` for the full scope.

The taint rules and the Tier-2 conservative rules are meant to coexist. If
you want loud-and-safe, keep the Tier-2 rules on. If you want
quieter-and-precise on a subset of classes, rely on the taint rules. Both
run by default.

## Section 3: Known false-positive patterns

These are patterns we have seen produce false positives and have explicitly
tuned for. Every item here is verifiable in the code or the git log.

- **SQL injection on plain English.** Earlier versions of
  `js/no-sql-injection` flagged `res.send('delete ' + name)` because
  `delete` is a SQL keyword. Fixed in commit
  [`13ea1ae`](https://github.com/0sec-labs/foxguard/commit/13ea1ae) by
  requiring a full SQL structure in the regex (`SELECT ... FROM`,
  `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`, `DROP TABLE`, etc.) rather
  than a bare keyword. See `src/rules/javascript.rs` around the
  `NoSqlInjection` rule.
- **Minified JavaScript fixtures.** Bundled jQuery-style
  `!function(e){...}(...)` triggered `js/no-command-injection` and
  `js/no-eval` because the bundles genuinely contain `eval`/`Function`. We
  skip `.min.js` files and files whose first line exceeds 1000 characters
  (see `is_noise_path` and `is_minified` in `src/engine/scanner.rs`).
- **Rails metaprogramming.** `class_eval` and `module_eval` are standard
  Ruby metaprogramming used by Rails, ActiveRecord, and every halfway-serious
  Ruby gem. `rb/no-eval` only flags `eval` and `instance_eval`
  (`src/rules/ruby.rs` around line 86).
- **Django `SECRET_KEY` from the environment.**
  `py/django-secret-key-hardcoded` and `py/flask-secret-key-hardcoded` do
  not fire when the RHS is a call to `os.environ.get`, `os.getenv`, or a
  subscript of `os.environ`. The negative fixture
  `tests/fixtures/safe.py` covers this.
- **Test/example/generated code.** foxguard's default noise filter skips
  `vendor/`, `node_modules/`, `__fixtures__/`, `__mocks__/`, `dist/`,
  `build/`, `.next/`, `coverage/`, `.cache/`, plus `.min.js`/`.min.css`
  files and any file that looks minified by the first-line-length heuristic.
  This is the single biggest source of noise in a default scan and it is on
  by default. Users who want to scan these paths can pass them explicitly.
- **Import aliases.** `py/no-pickle` and friends are alias-aware
  (`src/rules/python_aliases.rs`). `from pickle import loads as deserialize`
  followed by `deserialize(x)` fires the rule; `from safe_module import loads`
  followed by `loads(x)` does not.
- **JavaScript and TypeScript credential metadata.** The secret rule recognizes
  matching `REDACTED_*` sentinel values, structured model identifiers used only
  in comparisons with model inputs, and lowercase field-name pattern data used
  only by an unshadowed, unmodified `RegExp`. A metadata suffix alone is not
  enough. Credential-shaped values, other consumers, and mutations retain the
  finding. Test files receive no automatic credential exemption. See
  `tests/fp_secret_names.rs`.
- **JavaScript and TypeScript fixed-origin templates.** The SSRF rule accepts
  path or query interpolation only after it proves a complete, fixed HTTP(S)
  authority. Literal bindings must be immutable and resolve in the closest
  lexical scope. Dynamic authorities, mutable bindings, shadowing, and arbitrary
  method calls remain reported. This does not establish redirect safety or
  runtime authorization. See `tests/js_ssrf_precision.rs`.

- **Java flow veto: constants and helpers.** The Java sink rules ask a small
  flow-sensitive interpreter (`src/rules/java_flow.rs`) whether every sink
  argument is provably built from constants; if so the finding is dropped.
  Two rules decide what counts as a constant:
  - An UPPER_SNAKE identifier is a constant only when it resolves to a
    `static final` field (or an interface field, enum constant or by-name static
    import) of an enclosing class in the same file, with a safe initialiser.
    Method parameters, lambda, catch and loop variables, locals, and any name
    declared in the enclosing method shadow it, so
    `void run(@RequestParam String USER_INPUT)` is request data. A constant
    declared in another file (including an inherited one) is unknown, not safe.
  - `Helper.method(args)` with only safe arguments is read from the helper's
    body when `Helper` is declared in the scanned file (a body that reads a
    `ThreadLocal`, a static field, `RequestContextHolder` or any source is
    unknown). Calls on request-context holders (`RequestContextHolder`,
    `SecurityContextHolder`, `LocaleContextHolder`, `MDC`, ...) and accessors of
    per-request state (`getAttribute`, `getSession`, `getAuthentication`, ...)
    are never trusted.

  **Cross-file helpers are unknown (sound default).** A call to a project
  helper whose class is not declared in the scanned file is never assumed safe
  just because its arguments are safe: its body is not available, so it may
  ignore its arguments and read request, thread or static state
  (`Helper.currentInput()` with `Helper` in another file is reported). Only
  JDK and well-known library types (`java.*`, `javax.*`, `org.apache.*`,
  `org.springframework.*`, and similar) are taken as functions of their
  arguments.

  **What this costs.** Extra false alarms on code that routes constants through
  helper factories declared in other files. On the shared Java benchmark scorer
  true positives are unchanged (1319) and false positives rise from 66 to 164
  (full score 0.882 to 0.808; cmdi 0.689 to 0.321, xss 0.900 to 0.804,
  pathtraver 0.776 to 0.687, sqli 0.938 to 0.860, ldapi 0.889 to 0.858, xpathi
  0.933 to 0.883), because that benchmark's own helper classes are separate
  files. The extra alarms are an intended hand-off: the verification step that
  follows a scan is the place to prune them, since a suppressed real finding
  cannot be recovered later.

  **The old behaviour still exists.** `TRUST_UNRESOLVED_PROJECT_HELPERS` in
  `src/rules/java_flow.rs` is `false`; setting it to `true` restores the
  assumption and the lost precision, at the risk of hiding a real finding
  behind a state-reading helper. It is a build-time constant, not a user-facing
  option. A per-method "safe when its arguments are safe" summary resolved
  across files would remove most of the cost for whole-project scans and is the
  intended follow-up. See `tests/fixtures/java_cross_file_helper/`.

- **Java qualified constants and argument injection.** `Type.NAME` is a
  constant only when `Type` resolves to a class whose declaration the scan can
  read: one declared in the scanned file with a `static final` field of that
  name and a safe initialiser, one of the project's other files (see the next
  paragraph), or a JDK or well-known library type (`File.separator`,
  `StandardCharsets.UTF_8`, `Integer.MAX_VALUE`, `TimeUnit.SECONDS`). Anything
  else is unknown, because that class may declare it as a public static that
  request data is assigned to (`exec(OtherState.USER_COMMAND)` is reported).
  Before the cross-file reading below, this cost false positives only on the
  shared Java benchmark scorer (full score 0.808 to 0.762, FP 164 to 225, TP
  unchanged), the benchmark's helper classes being separate files. A fixed
  non-shell program (`exec(new String[] {"ls", arg})`) no longer suppresses the
  command rule, because the argument can still be read as an option (`find
  -exec`, `tar --checkpoint-action`, `git -c`, `curl -o`). It is reported as
  `java/taint-argument-injection` (CWE-88, medium); the benchmark has no such
  flows, so the measured cost is zero.

- **Java constants declared in other files.** The scanner indexes the types and
  fields of every scanned Java file (`src/rules/java_index.rs`) and the flow
  interpreter reads `Type.NAME`, a name imported with `import static` and a
  name inherited from a scanned supertype from it. A field is a constant only
  when all of these hold: the class resolves to exactly one scanned class from
  the reading file (a single-type import, the same package, one wildcard import
  that provides it, or a qualified name; a type declared in the reading file
  wins; a name provided by two wildcard imports, a name that resolves to no
  scanned class, and a name that an unreadable file may also declare are
  unknown); the field is `static final`, an interface field or an enum constant
  of an immutable value type (a string, a primitive or its box, `File`, `Path`;
  arrays, collections and builders stay unknown); its name is not assigned,
  incremented or compound-assigned anywhere in the scanned project (the check
  is by simple name, so it errs toward unknown); exactly one declaration is
  found through the supertypes; and its initialiser is safe when read in the
  declaring file (with that file's imports), within a nesting depth of four and
  with cycle detection. A non-final field, a blank final set in an initialiser
  block, an initialiser that calls a project helper or reads the environment,
  and a constant built from one of those are unknown. The initialiser uses the
  same evaluator as same-file constants, so the trusted-JDK-call assumption of
  the audit table below applies: `System.getProperty("user.dir") +
  File.separator` is a constant. A scan that sees only some of the project's
  files (a diff scan) resolves only what it sees; the rest stays unknown. On
  the shared benchmark scorer, with the helper classes scanned alongside the
  tests, path traversal goes from 0.235 to 0.709 (FP 88 to 24, TP unchanged)
  and the full score from 0.762 to 0.811. The remaining false alarms there are
  flows through reflection-built helper objects and a `getFD()` chain, not
  constants. See `tests/fixtures/java_cross_file_constants_safe/` and
  `..._vulnerable/`.

### Java flow veto: suppression audit

Every place the Java rules may drop a sink or treat a value as safe, with the
assumption it rests on and a concrete flow it would miss.

| Heuristic | Sound? | Assumption kept / what is missed |
|---|---|---|
| UPPER_SNAKE names | Yes (fixed) | Only a `static final` field of an enclosing class, interface field, enum constant, name inherited from a scanned supertype, or by-name static import; parameters and any declared name shadow it. A static import of a scanned class is read from that class; one of a class outside the scan is assumed to be a library constant. Missed: a name statically imported from an unscanned class that a project module fills with request data. |
| `Type.NAME` / library fields | Yes (fixed) | Library types are assumed to hold no request data in static fields. Missed: a library singleton someone mutated at startup from request data. |
| `Type.NAME` of a class in another scanned file | Assumption | Constant when the class is unambiguous, the field is `static final` (or interface field or enum constant) of an immutable value type, the name is never assigned in the scan and the initialiser is safe (see above). Assumption: no reflection, no other language and no unscanned code writes the field, and the initialiser's trusted JDK calls return fixed values. Missed: `public static final String DIR = System.getProperty("app.dir")` where startup code sets `app.dir` from request data; an unscanned file that declares a same-named class in the same package. |
| Same-file static helper body | Yes | The body is interpreted with the caller's argument values; unknown calls inside stay unknown. |
| Unqualified / `this.` helper | Yes (fixed) | Resolved only to a private, static or final method (or one in a final class) of the innermost enclosing class that declares it; an overridable method may be replaced by a subclass in another file and is unknown. |
| Helper in another file | Yes (default) | Unknown; extra alarms only. `TRUST_UNRESOLVED_PROJECT_HELPERS = true` restores the old assumption: missed `exec(Helper.currentInput())`. |
| JDK / library static call with safe arguments | Assumption | Result depends only on the arguments. Missed: `System.getProperty("x")` where the property was set from request data; `Files.readString` style reads are listed as external input and stay unknown. |
| External-input and request-context lists | Partly | A denylist of method names (`getenv`, `readLine`, `lines`, `getAttribute`, `getSession`, ...). A reader not on the list, called on a value proven safe, is treated as safe. Missed: `new Foo("const").fetch()` is already unknown, but `Library.fetch("const")` of an unlisted name is trusted. |
| Request-context holders | Yes | `RequestContextHolder`, `SecurityContextHolder`, `LocaleContextHolder`, `MDC` and similar are never trusted. A holder not on the list is a library call (see above). |
| Constant folding | Yes (fixed) | Strings are not compared with `==` (reference semantics) and ints that leave the 32-bit range are not folded. Missed: none known. |
| Clean reassignment (taint engine) | Yes (fixed) | Hides taint only from statements after a straight-line reassignment: not before it, not when the assignment sits under a branch, loop, `try`, handler, ternary or short-circuit operand, and not across a loop back edge. |
| Clean reassignment (flow interpreter) | Yes (fixed) | Branches of `?:`, `&&` and `||` run on copies and are joined. Fields are not tracked at all: a call between the write and the read may change them. |
| Collections (`add`/`put`/`get` by constant index) | Yes | A collection handed to another call, aliased, or modified by an unmodelled method stops being tracked. Taint added through `add`/`put`/`append` is propagated. |
| Fixed program at argument 0 | Yes (fixed) | Reported as argument injection instead of suppressed. A program on the shell-like list (`sh`, `env`, `python`, `ssh`, ...) stays command injection. Not covered: a program that is not a literal. |
| `arg_indices` (SQL text, LDAP filter, XPath text only) | Assumption | Bound values are data. Missed: a driver or API where a later argument is also interpreted as query text (for example a `PreparedStatementCreator`, or a custom `search` overload). |
| Wrapped `new File(..)` inside another path sink | Yes | The outer constructor reports it; the outer is only a sink for the same types. |
| HTML encoders (XSS rule only) | Assumption | Any call named `escapeHtml*`, `encodeForHTML`, ... is an HTML sanitiser whatever its receiver. Missed: HTML-escaped data placed in a JavaScript string, an unquoted attribute or a `javascript:` URL. |
| Typed receiver recognition | Recall gap | Sink receivers are matched by declared type or name hint in the enclosing scopes. Missed: a `Runtime` held in an inherited field whose name does not contain `runtime`. This lowers recall, it does not suppress. |
| Test-path skips | n/a | This change adds none. |

## Section 4: How to report a false positive

If foxguard fires on code you believe is safe, open a GitHub issue with the
label **`false-positive`**. Include:

1. The rule ID exactly as emitted (e.g. `js/no-sql-injection`).
2. The smallest self-contained source snippet that reproduces the finding.
3. One or two sentences explaining why the finding is not a real issue —
   what the reviewer would have checked in their head.

We treat false-positive reports as bugs against the rule, not against the
user. If the pattern is general enough to add to the negative-fixture suite,
we do that as part of the fix so it cannot regress silently.

## Section 5: How to suppress a finding

Two mechanisms, documented more fully in the main
[README](../README.md#suppressing-deliberate-findings):

- **Inline ignores** — the `foxguard: ignore` and `foxguard: ignore[rule-id]`
  comment directives suppress a finding on the next non-empty, non-comment
  code line (or on the current line when placed as a trailing comment).
  Use these for one-off deliberate patterns. Inline ignores apply to code
  scanning findings, not to `foxguard secrets`.
- **Repo-local baselines** — `scan.baseline` and `secrets.baseline` in
  `.foxguard.yml` (see the [Configuration](../README.md#configuration)
  section of the README) snapshot the existing set of findings so legacy
  issues stop blocking adoption. New findings still fail the run; previously
  accepted findings do not.

Prefer inline ignores for deliberate patterns (it keeps the justification
next to the code) and baselines for gradual rollout on legacy repositories.

---

*This document now includes the labeled precision corpus added for
[issue #445](https://github.com/0sec-labs/foxguard/issues/445).*
