# Code index

Per-repo index behind the `code-index` tool pack: `callers_of`, `callees_of`, `routes`, `trace_to_sink`. Principles:
[tool-philosophy.md](tool-philosophy.md); toolset: [core-toolset.md](core-toolset.md).

## What it is

- Symbols, a name-based call graph, HTTP routes with their middleware, and sink calls (command, code-eval, sql, file,
  network, deserialize, template, redirect) for TypeScript, JavaScript and Python, and for Java when the Foxguard
  binary is available (Spring MVC, JAX-RS, servlets).
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
                "language": "javascript|python|java" }],
  "calls": [{ "from": "<symbol id>", "name": "query", "text": "db.query", "file": "src/a.ts", "line": 14,
              "sink": { "category": "sql", "text": "db.query" },
              "auth": true, "receiverType": "NoteService" }],
  "routes": [{ "method": "GET", "path": "/notes/:id", "file": "src/routes.ts", "line": 9,
               "handler": "<symbol id> | ref:<name> | unresolved:<name>", "middleware": ["requireAuth"],
               "framework": "express-like|flask-fastapi|django|nest|spring|jax-rs|servlet",
               "authSignals": ["PreAuthorize"], "sinksReachable": ["sql"], "missingGuard": false }],
  "taintSummaries": [{ "file": "src/A.java", "function": "run", "language": "java", "paramsToReturn": [0],
                       "paramsToSink": [{ "paramIndex": 0, "ruleId": "java/taint-command-injection", "description": "..." }] }],
  "unsupported": { "go": 3 },
  "truncated": false,
  "notes": ["spring-security-url-rules: ..."]
}
```

- The keys added after the first draft (`auth`, `receiverType`, `authSignals`, `sinksReachable`, `notes`, the `java`
  language and the `spring`, `jax-rs` and `servlet` frameworks) are additive, so the schema stays at version 1.
- `auth` on a call and `authSignals` on a route mark authentication, authorization and ownership checks by name
  (`@PreAuthorize`, `@Secured`, `@RolesAllowed`, `SecurityContextHolder`, `hasRole`, `assertOwner`, ...). The consumer
  counts them next to its own name pattern when it lists routes without an auth signal.
- `missingGuard` is present only with `--missing-guard`: the handler reaches a data sink (command, code-eval, sql, file,
  deserialize) within four call hops and neither the route nor any call on the way carries an auth signal. A handler
  that reaches no data sink is not flagged. `sinksReachable` lists every sink category found on those hops.
- `receiverType` (Java) is the declared simple type of the receiver, read from fields, parameters and locals. A call
  joins the methods of that class (exactly, or a class named like it, such as `UserService` and `UserServiceImpl`)
  before falling back to every method of that name.
- `taintSummaries` holds the per-method summaries of the Java taint engine (`rules/cross_file.rs`: `paramsToReturn`,
  `paramsToSink`) with `--taint-summaries` only; it costs about three times the plain run. Summaries are keyed by method
  name, as the scanner does, so overloads and same-named methods in one file share a name. Path search stays in the
  consumer (`trace_to_sink`).
- Foxguard emits `express-like` and `flask-fastapi` routes for JavaScript and Python; `nest` and `django` come from the
  built-in extractor only. For Java: Spring (`@RestController`/`@Controller` classes with `@RequestMapping` and the
  verb mappings, path arrays and constants kept as `{NAME}`, `method = {...}` expanded), JAX-RS (`@Path` with `@GET`
  and the other verbs), and servlets (`doGet`, `doPost`, ... of a class extending a `*Servlet`, path from `@WebServlet`,
  otherwise `/{servlet:Class}`).
- Java calls are kept when they can join a symbol of the tree (at most 25 candidates after narrowing by receiver type),
  or are a sink or an auth signal. Calls into the JDK and libraries are dropped, which keeps a million lines of Java
  within the 2,000,000-call limit of the reader.
- A reader must ignore unknown keys and reject a `version` it does not know.

### Limits (Java)

- Lexical, not type-resolved: no generics, inheritance or overload resolution. A call joins methods by name, narrowed by
  the receiver's declared type when a field, parameter or local gives one. A chained receiver (`a.b().c()`) has none.
- Interface and abstract methods have no body and so no symbol; a call through an interface type reaches the
  implementations whose class name starts or ends with it, else every method of that name.
- Spring Security rules written as URL patterns (`authorizeHttpRequests`, `requestMatchers`, web.xml constraints) are
  not mapped to routes. When such calls exist the graph carries a `notes` entry so the answer says so.
  Meta-annotations, Kotlin and Groovy controllers, `web.xml` servlet mappings and functional routes are not indexed.
- The file budget (`--file-timeout`) bounds each file; a file over it, or over 1 MB, sets `truncated`.

## Limits and untrusted text

The built-in extractor runs on the event loop, so it has time limits: 2 seconds for one file and 20 seconds for a build. A file over its limit is skipped, the index is marked `truncated`, and `skippedSlow` counts the files left out. Generic-argument scans are bounded and brackets are matched in one pass per file, so a hostile file cannot make a regular expression or a loop run for minutes.

The Foxguard backend runs `foxguard graph --file-timeout 30 <folder>` with a reduced environment, a 180-second limit and 128 MB of output. The `graph` command reads no configuration file from the scanned folder, so there is no config to isolate. Over any limit, the built-in index is used.

Every tool result labels its text as repository content and returns it flattened, stripped of control and invisible characters, and cut to 160 characters.

## Dependencies

`foxguard graph` lives in `crates/foxguard/src/graph/` (`mod.rs` for JavaScript and Python, `java.rs` for Java). The
fixture `crates/foxguard/tests/fixtures/java_graph_app` backs a cargo test and the engine test
`code-index/foxguard-java.test.ts`, which runs the real binary through the four tools. Without a binary (or with an older
one) the built-in extractor runs for TypeScript, JavaScript and Python and Java is reported as unsupported.
