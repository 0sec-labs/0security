/**
 * Data model of the per-repo code index. The JSON shape is deliberately plain so a Foxguard
 * `index` export (see the proposal in the PR for #659) can be loaded into the same structure.
 */
export type IndexLanguage = "javascript" | "python" | "java";

export type SinkCategory = "command" | "code-eval" | "sql" | "file" | "network" | "deserialize" | "template" | "redirect";

export interface SinkTag { category: SinkCategory; text: string }

export interface IndexSymbol {
  /** Stable within one index: `path#qualified@line`. */
  id: string;
  name: string;
  /** `Class.method` for methods, the bare name otherwise; inline route handlers use `<GET /path>`. */
  qualified: string;
  kind: "function" | "method" | "route-handler" | "module";
  file: string;
  line: number;
  endLine: number;
  language: IndexLanguage;
}

export interface IndexCall {
  /** The symbol the call sits in (a `<module>` symbol for top-level code). */
  from: string;
  /** Last identifier of the call: `db.users.find(` gives `find`. */
  name: string;
  /** The whole dotted callee text as written. */
  text: string;
  file: string;
  line: number;
  sink?: SinkTag;
  /** The call is named like an authentication, authorization or ownership check (set by the Foxguard graph). */
  auth?: boolean;
  /** Declared type of the receiver (Java, Foxguard graph): narrows the symbols a by-name join can reach. */
  receiverType?: string;
}

export interface IndexRoute {
  method: string;
  path: string;
  file: string;
  line: number;
  /** Symbol id that runs the request: a named function or the inline handler. */
  handler: string;
  /** Names passed as middleware, decorators or dependencies before the handler. */
  middleware: string[];
  framework: string;
  /** Guard annotations or auth-like middleware on the route itself (Foxguard graph). */
  authSignals?: string[];
}

export interface CodeIndex {
  version: 1;
  root: string;
  /** `git rev-parse HEAD`, or `none` outside a git checkout. */
  commit: string;
  /** Hash of the working-tree state, so uncommitted edits never serve a stale index. */
  fingerprint: string;
  files: number;
  symbols: IndexSymbol[];
  calls: IndexCall[];
  routes: IndexRoute[];
  /** Source files seen in languages the index cannot parse, by extension. */
  unsupported: Record<string, number>;
  truncated: boolean;
  /** Which extractor produced it. */
  engine?: "builtin" | "foxguard";
}

export interface FileExtract {
  symbols: IndexSymbol[];
  calls: IndexCall[];
  routes: IndexRoute[];
}
