/**
 * Broad matchers for the places untrusted input enters or dangerous work happens. They are patterns on lines and paths, chosen
 * to over-match: a unit that turns out harmless costs a model a short look, a missed one is code nobody reviewed.
 */
export const UNIT_KINDS = ["http-route", "webhook", "queue-consumer", "cron", "cli-main", "deserialization", "file-upload", "exec", "other"] as const;
export type UnitKind = typeof UNIT_KINDS[number];
export const isEntryPointKind = (kind: UnitKind): boolean => kind !== "other";

export interface LineMatcher {
  kind: UnitKind;
  /** File extensions (no dot) this applies to; every source file when absent. */
  exts?: readonly string[];
  /** Only files whose relative path matches. */
  pathRe?: RegExp;
  /** Lines to match. The first capture group, then the second, name the unit. */
  lineRe: RegExp;
  /** Most units this matcher gives one file (default 25). */
  perFile?: number;
  /** Format the name from the match; default is the captures joined by a space. */
  name?: (match: RegExpExecArray) => string | undefined;
  /** Stop at the first line matching this (Rails `private`). */
  stopRe?: RegExp;
}

export interface PathMatcher {
  kind: UnitKind;
  pathRe: RegExp;
  name: string;
}

export const SOURCE_EXTENSIONS: ReadonlySet<string> = new Set([
  "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "vue", "svelte", "py", "go", "java", "kt", "kts", "scala", "rb", "php", "rs", "cs", "swift", "ex", "exs", "erb", "c", "cc", "cpp", "h", "hpp", "sh",
]);

const JS = ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "vue", "svelte"] as const;
const PY = ["py"] as const;
const GO = ["go"] as const;
const JVM = ["java", "kt", "kts", "scala"] as const;
const RB = ["rb"] as const;
const PHP = ["php"] as const;

const joined = (match: RegExpExecArray): string => match.slice(1).filter(Boolean).join(" ");

export const LINE_MATCHERS: readonly LineMatcher[] = [
  // HTTP routes
  { kind: "http-route", exts: JS, lineRe: /\b[A-Za-z_$][\w$]*\.(get|post|put|patch|delete|all|head|options|use)\(\s*['"`](\/[^'"`]*|\*)/, name: m => `${m[1]!.toUpperCase()} ${m[2]}` },
  { kind: "http-route", exts: JS, lineRe: /\.route\(\s*(?:['"`]([^'"`]*)['"`]|\{)/, name: m => `ROUTE ${m[1] ?? "(options)"}` },
  { kind: "http-route", exts: JS, lineRe: /^\s*@(Get|Post|Put|Patch|Delete|All|Controller|Sse|MessagePattern|EventPattern)\(/, name: m => `@${m[1]}` },
  { kind: "http-route", exts: JS, lineRe: /^\s*['"]use server['"]/, perFile: 1, name: () => "server actions" },
  { kind: "http-route", exts: PY, lineRe: /^\s*@[\w.]+\.(route|get|post|put|patch|delete|websocket|api_route)\(\s*['"]([^'"]*)/, name: m => `${m[1]} ${m[2]}` },
  { kind: "http-route", exts: PY, pathRe: /(^|\/)urls?\.py$/, lineRe: /\b(?:re_path|path|url)\(\s*r?['"]([^'"]*)/, name: m => `path ${m[1]}` },
  { kind: "http-route", exts: PY, lineRe: /^class\s+(\w+)\((?:[\w.]*\.)?(?:\w*View|\w*ViewSet|\w*APIView|\w*Resource|\w*Handler)\)/, name: m => m[1] },
  { kind: "http-route", exts: PY, pathRe: /(^|\/)views?(\.py|\/)/, lineRe: /^(?:async\s+)?def\s+(\w+)\(\s*(?:self,\s*)?request\b/, name: m => m[1] },
  { kind: "http-route", exts: GO, lineRe: /\b(?:HandleFunc|Handle|Handler)\(\s*"([^"]*)"/, name: m => `handle ${m[1]}` },
  { kind: "http-route", exts: GO, lineRe: /\b\w+\.(GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|Group)\(\s*"(\/[^"]*)"/, name: m => `${m[1]!.toUpperCase()} ${m[2]}` },
  { kind: "http-route", exts: GO, lineRe: /^func\s+(?:\([^)]*\)\s*)?(\w+)\([^)]*(?:http\.ResponseWriter|\*gin\.Context|echo\.Context|\*fiber\.Ctx)/, name: m => m[1] },
  { kind: "http-route", exts: JVM, lineRe: /^\s*@(Get|Post|Put|Delete|Patch|Request)Mapping\b(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]*)")?/, name: m => `${m[1]!.toUpperCase()} ${m[2] ?? ""}`.trim() },
  { kind: "http-route", exts: JVM, lineRe: /^\s*@(Path|GET|POST|PUT|DELETE|PATCH)\b(?:\(\s*"([^"]*)")?/, name: m => `${m[1]} ${m[2] ?? ""}`.trim() },
  { kind: "http-route", exts: RB, pathRe: /(^|\/)config\/routes(\/.*)?\.rb$/, lineRe: /^\s*(get|post|put|patch|delete|match|resources?|namespace|mount|root|scope)\b\s*:?['"]?([\w/:.-]*)/, name: joined },
  { kind: "http-route", exts: RB, pathRe: /(^|\/)app\/controllers\//, lineRe: /^\s*def\s+(\w+[?!]?)/, stopRe: /^\s*(private|protected)\s*$/, name: m => `action ${m[1]}` },
  { kind: "http-route", exts: PHP, lineRe: /\bRoute::(get|post|put|patch|delete|any|match|resource|apiResource|group)\(\s*(?:['"]([^'"]*)['"])?/, name: m => `${m[1]!.toUpperCase()} ${m[2] ?? ""}`.trim() },
  { kind: "http-route", exts: PHP, lineRe: /\$\w+->(get|post|put|patch|delete|any|map)\(\s*['"]([^'"]*)/, name: m => `${m[1]!.toUpperCase()} ${m[2]}` },
  { kind: "http-route", exts: PHP, lineRe: /\$_(GET|POST|REQUEST|COOKIE|SERVER)\[/, perFile: 1, name: m => `reads $_${m[1]}` },
  // Queue consumers, scheduled work
  { kind: "queue-consumer", exts: JS, lineRe: /\b(?:new\s+(?:Worker|Consumer)|\w*[Qq]ueue\.process|consumer\.(?:run|subscribe)|channel\.consume|\.on\(\s*['"]message['"])\s*\(/, name: () => "consumer" },
  { kind: "queue-consumer", exts: JS, lineRe: /(?:exports\.handler\s*=|export\s+(?:async\s+)?(?:function|const)\s+handler\b)/, perFile: 1, name: () => "handler" },
  { kind: "queue-consumer", exts: PY, lineRe: /^\s*@(?:shared_task|[\w.]+\.task|[\w.]+\.consumer|[\w.]+\.subscriber)\b|^def\s+lambda_handler\b/, name: () => "task" },
  { kind: "queue-consumer", exts: JVM, lineRe: /^\s*@(KafkaListener|RabbitListener|SqsListener|JmsListener|StreamListener|EventListener)\b/, name: m => `@${m[1]}` },
  { kind: "queue-consumer", exts: GO, lineRe: /\b(?:Consume|Subscribe|QueueSubscribe|ReceiveMessage)\(/, name: () => "consumer" },
  { kind: "cron", exts: JS, lineRe: /\b(?:cron\.schedule|scheduleJob|new\s+CronJob|agenda\.define)\(/, name: () => "job" },
  { kind: "cron", exts: [...JVM, ...PY, ...RB, ...GO, ...PHP], lineRe: /^\s*@(Scheduled)\b|\bcron\.(?:New|AddFunc)\b|\b(?:schedule\.every|crontab\()|\$schedule->(?:command|call|job)/, name: () => "scheduled job" },
  // Program entry points
  { kind: "cli-main", exts: GO, lineRe: /^func\s+main\(\)/, name: () => "main" },
  { kind: "cli-main", exts: PY, lineRe: /^if\s+__name__\s*==\s*['"]__main__['"]|^@click\.(?:command|group)\b|\bargparse\.ArgumentParser\(/, perFile: 3, name: () => "main" },
  { kind: "cli-main", exts: JVM, lineRe: /\bstatic\s+void\s+main\(|^\s*fun\s+main\(/, name: () => "main" },
  { kind: "cli-main", exts: ["rs"], lineRe: /^\s*(?:async\s+)?fn\s+main\(\)/, name: () => "main" },
  { kind: "cli-main", exts: ["cs"], lineRe: /\bstatic\s+(?:async\s+)?(?:void|int|Task)\s+Main\(/, name: () => "Main" },
  { kind: "cli-main", exts: JS, lineRe: /\bprocess\.argv\b|\b(?:program|yargs)\.(?:command|parse)\(|^#!\/usr\/bin\/env\s+node/, perFile: 1, name: () => "cli" },
  // Places where hostile data becomes code or a file
  { kind: "deserialization", lineRe: /\b(?:pickle|cPickle|dill|marshal|shelve|jsonpickle)\.(?:loads?|decode)\(|\byaml\.(?:load|unsafe_load)\(|\bYAML\.load\(|\btorch\.load\(|\bObjectInputStream\b|\breadObject\(|\bunserialize\(|\bMarshal\.load\b|\bXMLDecoder\b|\bBinaryFormatter\b|\bnode-serialize\b|\bgob\.NewDecoder\(|\bXStream\b|\bSerializationUtils\.deserialize\b/, perFile: 5, name: () => "deserialization" },
  { kind: "file-upload", lineRe: /\b(?:multer|formidable|busboy|multipart)\b|\b(?:req|request)\.files?\b|\$_FILES|\bMultipartFile\b|\bFormFile\(|\bParseMultipartForm\(|\bUploadedFile\b|\bFileUpload\b|\.save\(\s*\w*[Ff]ilename/, perFile: 5, name: () => "file upload" },
  { kind: "exec", exts: JS, lineRe: /\b(?:child_process|execSync|spawnSync|execFile(?:Sync)?)\b|(?<![.\w])exec\(|\beval\(|new\s+Function\(|\bvm\.run\w*\(/, perFile: 5, name: () => "command or code execution" },
  { kind: "exec", exts: PY, lineRe: /\bsubprocess\.\w+\(|\bos\.(?:system|popen)\(|(?<![.\w])(?:eval|exec)\(/, perFile: 5, name: () => "command or code execution" },
  { kind: "exec", exts: GO, lineRe: /\bexec\.Command(?:Context)?\(/, perFile: 5, name: () => "command execution" },
  { kind: "exec", exts: JVM, lineRe: /\bRuntime\.getRuntime\(\)\.exec\(|\bProcessBuilder\b|\bScriptEngine\b/, perFile: 5, name: () => "command execution" },
  { kind: "exec", exts: PHP, lineRe: /\b(?:shell_exec|passthru|proc_open|popen|system|exec|eval|assert)\(/, perFile: 5, name: () => "command or code execution" },
  { kind: "exec", exts: [...RB, "ex", "exs"], lineRe: /\b(?:system|exec|spawn|eval|instance_eval|class_eval|send)\(|\bOpen3\.|\bKernel\.system|\bPort\.open\(/, perFile: 5, name: () => "command or code execution" },
];

/** Files that are an entry point by where they sit. */
export const PATH_MATCHERS: readonly PathMatcher[] = [
  { kind: "http-route", pathRe: /(^|\/)app\/.*route\.(?:ts|js|tsx|jsx|mjs)$/, name: "route handler" },
  { kind: "http-route", pathRe: /(^|\/)pages\/api\//, name: "api route" },
  { kind: "http-route", pathRe: /(^|\/)middleware\.(?:ts|js)$/, name: "middleware" },
  { kind: "webhook", pathRe: /(^|\/)webhooks?(\/|\.[a-z]+$)/i, name: "webhook" },
];

/** A route whose name says it receives webhooks is reported as one. */
export const WEBHOOK_NAME = /webhook|\/hooks?(?:\/|$)|callback/i;
