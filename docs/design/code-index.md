# Code index

Per-repo index behind the `code-index` tool pack: `callers_of`, `callees_of`, `routes`, `trace_to_sink`. Principles:
[tool-philosophy.md](tool-philosophy.md); toolset: [core-toolset.md](core-toolset.md).

## What it is

- Symbols, a name-based call graph, HTTP routes with their middleware, and sink calls (command, code-eval, sql, file,
  network, deserialize, template, redirect) for TypeScript, JavaScript and Python, and for Java and Kotlin when the
  Foxguard binary is available (Spring MVC, JAX-RS, servlets, Ktor).
- Built offline from the granted folder. Cached in memory per root, commit and working-tree state (commit plus the
  stat of every indexed file), so an edit or a new commit gives a new index.
- Loaded by skills (`seedless-depth-review`, `verify-finding`) through `tools: [code-index]`, not part of the core list. The main session and any subagent get the four tools on the turn after `load_skill` of such a skill, never before; a child does not inherit them from its parent, and a restricted worker tool list or workflow phase keeps them out. `ZERO_TOOLSET=full` (opt-in everything list) advertises them up front.
- Not data flow. A path is a lead; the model reads each hop with `cat -n` before it claims a finding. Unsupported
  languages, unknown symbols and a missing folder return a soft result that points back to `rg`.

## Backends

1. Foxguard, when a binary with `foxguard graph` is found (`ZERO_FOXGUARD_PATH`, then `PATH`). Probed once with
   `foxguard graph --help` for the text `schema version 1`; output is validated with Zod and falls back on any failure.
2. The built-in extractor (`packages/engine/src/code-index/extract-*.ts`): comment and string masking plus
   brace and indentation matching. It exists so the tools work without Foxguard and is the fallback.

## `foxguard graph <path> [--missing-guard] [--output file]` (schema version 1)

```json
{
  "version": 1,
  "producer": "foxguard",
  "root": "/abs/path",
  "files": 4,
  "symbols": [{ "id": "src/a.ts#Class.method@12", "name": "method", "qualified": "Class.method",
                "kind": "function|method|route-handler|module", "file": "src/a.ts", "line": 12, "endLine": 20,
                "language": "javascript|python|java|kotlin" }],
  "calls": [{ "from": "<symbol id>", "name": "query", "text": "db.query", "file": "src/a.ts", "line": 14,
              "sink": { "category": "sql", "text": "db.query" },
              "auth": true, "receiverType": "NoteService" }],
  "routes": [{ "method": "GET", "path": "/notes/:id", "file": "src/routes.ts", "line": 9,
               "handler": "<symbol id> | ref:<name> | unresolved:<name>", "middleware": ["requireAuth"],
               "framework": "express-like|flask-fastapi|django|nest|spring|jax-rs|servlet|ktor",
               "authSignals": ["PreAuthorize", "url-rule:hasRole(OPS)"],
               "authSources": [{ "signal": "url-rule:hasRole(OPS)", "access": "role",
                                 "source": "src/main/java/a/SecurityConfig.java:14 requestMatchers(\"/ops/**\").hasRole(\"OPS\")" }],
               "public": true, "sinksReachable": ["sql"], "missingGuard": false }],
  "taintSummaries": [{ "file": "src/A.java", "function": "run", "qualified": "A.run", "symbol": "src/A.java#A.run@7",
                       "arity": 1, "language": "java", "paramsToReturn": [0],
                       "paramsToSink": [{ "paramIndex": 0, "ruleId": "java/taint-command-injection", "description": "..." }] }],
  "unsupported": { "go": 3 },
  "truncated": false,
  "droppedCalls": 0,
  "callStats": { "jvmCalls": 1200, "external": 700, "resolved": 400, "ambiguous": 90, "ranked": 10 },
  "notes": ["spring-security-url-rules: ..."]
}
```

- The keys added after the first draft (`auth`, `receiverType`, `authSignals`, `authSources`, `public`, `sinksReachable`,
  `notes`, `droppedCalls`, `callStats`, the taint summary keys `qualified`, `symbol` and `arity`, the `java` and `kotlin`
  languages and the `spring`, `jax-rs`, `servlet` and `ktor` frameworks) are additive, so the schema stays at version 1.
- `auth` on a call and `authSignals` on a route mark authentication, authorization and ownership checks by name
  (`@PreAuthorize`, `@Secured`, `@RolesAllowed`, `SecurityContextHolder`, `hasRole`, `assertOwner`, ...). The consumer
  counts them next to its own name pattern when it lists routes without an auth signal.
- `missingGuard` is present only with `--missing-guard`: the handler reaches a data sink (command, code-eval, sql, file,
  deserialize) within four call hops and neither the route nor any call on the way carries an auth signal. A handler
  that reaches no data sink is not flagged. `sinksReachable` lists every sink category found on those hops.
- `authSources` says where a signal that is not on the handler came from: a Spring Security URL rule
  (`authorizeHttpRequests`/`authorizeRequests` with `requestMatchers`, `antMatchers`, `mvcMatchers`, `regexMatchers`,
  `anyRequest`, the Kotlin `authorize(...)` DSL, `securityMatcher` chain scopes, `web.ignoring()`), a `web.xml`
  `security-constraint` or `filter-mapping`, a Jakarta `@WebFilter` or a filter added to a chain
  (`addFilterBefore(new JwtFilter(), ...)`) that checks authentication. `source` is `file:line` and the rule as written;
  `access` is `public`, `authenticated`, `role`, `denied`, `filter` or `annotation`. Rules apply in source order, first
  match wins; a rule with an HTTP method (`requestMatchers(HttpMethod.POST, "/x")`) covers only that method; a literal
  path segment does not cover a `{var}` segment; constants (`Urls.OPEN`) are resolved from the tree. Several chains in
  one tree each take the routes nearest their file, and `securityMatcher` chains are tried first. The signals are also in
  `authSignals` (`url-rule:permitAll` is not: it is `public`). A route covered only by `permitAll`, `@PermitAll` or an
  unrestricted `web.xml` constraint has `public: true`: open on purpose, and still `missingGuard` when it reaches a sink.
  `web.xml` servlet mappings give the paths of servlets that have no `@WebServlet`. A `notes` entry names the rules the
  graph could not resolve (matchers that are not string constants, `PathRequest` helpers) and an annotation-based guard
  (`@PreAuthorize`, `@Secured`) used without `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity` in the tree.
- `receiverType` (Java, Kotlin) is the type whose methods the call reaches: the declared type of a field, parameter or
  local, or the type computed through `this`, field-of-field and chained calls (`a.b().c()`, `this.x.y.m()`), `var`
  locals, generics (`Optional<User>.get()`, `List<T>.get`, `Map<K, V>.get`, class type parameters, Spring Data
  repositories) and `new T()`. When the declared type is an interface or abstract class, the implementors present in the
  tree are the candidates; an injected field narrows them by `@Qualifier`/`@Resource`/`@Named`, then `@Primary`, then the
  bean named like the field, and a single candidate replaces `receiverType`. A call on a library type (`List`,
  `String`) joins nothing in the tree. A call joins the methods of that class before falling back to every method of
  that name.
- `taintSummaries` holds the per-method summaries of the Java taint engine (`rules/java_taint.rs`: `paramsToReturn`,
  `paramsToSink`) with `--taint-summaries` only; it costs about three times the plain run. Each summary names its
  method (`qualified`, `symbol` id, `arity`), so same-named methods of different classes and overloads stay apart. The
  scanner's own cross-file pass still keys by method name. `.load(...)` is a deserialization sink only on a receiver
  named or declared as `Yaml`, and `.exchange(...)` an SSRF sink only with three or more arguments. Path search stays in
  the consumer (`trace_to_sink`).
- Foxguard emits `express-like` and `flask-fastapi` routes for JavaScript and Python; `nest` and `django` come from the
  built-in extractor only. For Java: Spring (`@RestController`/`@Controller` classes with `@RequestMapping` and the
  verb mappings, path arrays and constants kept as `{NAME}`, `method = {...}` expanded), JAX-RS (`@Path` with `@GET`
  and the other verbs), and servlets (`doGet`, `doPost`, ... of a class extending a `*Servlet`, path from `@WebServlet`,
  otherwise the path of the `web.xml` `servlet-mapping`, or `/{servlet:Class}`). For Kotlin: the same Spring and JAX-RS
  annotations (read from the source text, because the grammar attaches class annotations unreliably) and Ktor
  routing (`routing { route("/p") { get("/x") { } } }`, `Route.` extension functions, `authenticate("name") { }` as the
  auth signal, handlers as `route-handler` symbols).
- Java and Kotlin calls are kept when they can join a bounded number of symbols of the tree, or are a sink or an auth
  signal. A name that is still shared by more than 25 methods after narrowing is ranked by proximity to the calling
  file (same file, same package, imported class, wildcard-imported package, shared directory) and kept when that singles
  out at most 25; otherwise it is dropped and counted in `droppedCalls`. `callStats` splits the calls into `external`
  (no method of that name in the tree: JDK and library calls, not dropped by lack of data), `resolved` (one symbol),
  `ambiguous` (several), `ranked` (kept after ranking). This keeps a million lines of Java within the 2,000,000-call
  limit of the reader.
- A reader must ignore unknown keys and reject a `version` it does not know.

### Limits (Java and Kotlin)

- Types come from declarations only: no overload resolution (overloads that disagree on the return type leave a chain
  unresolved), no lambda parameter types, no inference beyond `var x = <chain>`, `new T()` and the container and
  Spring Data methods listed above, no meta-annotations, and Lombok-generated members have no symbol.
- Interface and abstract methods have no body and so no symbol; their calls go to the implementors in the tree. Beans
  declared by `@Bean` factory methods, profiles and conditional beans are not modelled, so several implementors with no
  qualifier, primary or matching name stay several.
- URL rules: `access(...)` expressions are kept as text, not evaluated; matcher beans, `PathRequest` helpers and
  constants outside the tree are not resolved (a `notes` entry says so); rules built at run time, `HttpSecurity`
  customisers in other modules and Spring XML security are not read. `web.xml` constraints that list HTTP methods leave
  the other methods open (a note says so); `http-method-omission`, `jsp-property-group` and annotation-only
  `@ServletSecurity` are not read. Servlet filters are judged by name and body (a 401/403 or principal check).
- Kotlin: the Ktor DSL is followed lexically (`routing`, `route`, `authenticate`, the verbs); resources, `install`
  plugins and `Route` helpers defined elsewhere and called from a route are not expanded. Groovy is not indexed.
- The file budget (`--file-timeout`) bounds each file; a file over it, or over 1 MB, sets `truncated`.

## Limits and untrusted text

The built-in extractor runs on the event loop, so it has time limits: 2 seconds for one file and 20 seconds for a build. A file over its limit is skipped, the index is marked `truncated`, and `skippedSlow` counts the files left out. Generic-argument scans are bounded and brackets are matched in one pass per file, so a hostile file cannot make a regular expression or a loop run for minutes.

The Foxguard backend runs `foxguard graph --file-timeout 30 <folder>` with a reduced environment, a 180-second limit and 128 MB of output. The `graph` command reads no configuration file from the scanned folder, so there is no config to isolate. Over any limit, the built-in index is used.

Every tool result labels its text as repository content and returns it flattened, stripped of control and invisible characters, and cut to 160 characters.

## Dependencies

`foxguard graph` lives in `crates/foxguard/src/graph/`: `mod.rs` (JavaScript, Python, the pipeline), `java.rs` and
`kotlin.rs` (extractors), `types.rs` (declared-type model, generics, dispatch, Spring wiring), `resolve.rs` (call
resolution and ranking), `security.rs` (URL rules, `web.xml`, filters). The fixtures
`crates/foxguard/tests/fixtures/java_graph_app` and `java_graph_security_app` back cargo tests and the engine test
`code-index/foxguard-java.test.ts`, which runs the real binary through the four tools. Without a binary (or with an older
one) the built-in extractor runs for TypeScript, JavaScript and Python and Java and Kotlin are reported as unsupported.
A hidden `--legacy-resolution` flag resolves calls by name and declared receiver type only, as the first version did,
to measure the resolver against its predecessor on any tree.
