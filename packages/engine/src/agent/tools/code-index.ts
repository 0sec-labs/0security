/**
 * Code index tools: `callers_of`, `callees_of`, `routes`, `trace_to_sink` (0#659).
 *
 * They answer from a per-repo index (symbols, call graph, HTTP routes, bounded reachability) that is built
 * offline from the granted folder, once per commit and working-tree state. They read files and grant nothing.
 * They live in the `code-index` tool pack: a skill (source review, verify-finding) loads them on demand, so the
 * default tool list stays small. When the folder has no supported language, or a name is not in the index, the
 * result says so and points back to `rg` instead of guessing.
 */
import { z } from "zod";
import { getIndex } from "../../code-index/build.js";
import { callersOf, calleesOf, coverageOf, routesOf, traceToSink } from "../../code-index/query.js";
import type { SinkCategory } from "../../code-index/types.js";
import type { ToolDefinition, ToolResult } from "../types.js";

const SINK_CATEGORIES = ["command", "code-eval", "sql", "file", "network", "deserialize", "template", "redirect"] as const;

/** A symbol reference: `name`, `Class.method`, or `path/to/file.ts:name`. */
const symbolRef = z.string().trim().min(1).max(200).regex(/^[\w$.<>#:/\- ]+$/, "use a plain symbol name, Class.method or path:name");

export const callersOfSchema = z.object({
  symbol: symbolRef,
  depth: z.number().int().min(1).max(4).default(1),
  limit: z.number().int().min(1).max(100).default(30),
}).strip();

export const calleesOfSchema = z.object({
  symbol: symbolRef,
  depth: z.number().int().min(1).max(4).default(1),
  limit: z.number().int().min(1).max(150).default(40),
}).strip();

export const routesSchema = z.object({
  path_contains: z.string().trim().min(1).max(200).optional(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"]).optional(),
  file: z.string().trim().min(1).max(300).optional(),
  without_auth_signal: z.boolean().default(false),
  limit: z.number().int().min(1).max(200).default(60),
}).strip();

export const traceToSinkSchema = z.object({
  from: z.string().trim().min(1).max(250).regex(/^[\w$.<>#:/\- {}*]+$/, "use a symbol name or a route such as \"GET /notes/:id\""),
  sink: z.enum(SINK_CATEGORIES).optional(),
  max_depth: z.number().int().min(1).max(8).default(5),
  max_paths: z.number().int().min(1).max(20).default(8),
}).strip();

const FALLBACK = "The index is name-based and covers TypeScript, JavaScript and Python, plus Java when the Foxguard binary is installed. For anything it does not show, search with rg and read the code with cat -n.";

export const codeIndexToolDefinitions: Record<string, ToolDefinition> = {
  callers_of: {
    name: "callers_of",
    description:
      "List who calls a function or method, up to `depth` hops (1-4), and which HTTP routes reach it. Use it to see whether an ownership or auth check is called from a route. Name-based: same-named functions are merged and flagged ambiguous. TypeScript, JavaScript and Python (Java with Foxguard installed); otherwise use rg.",
    parameters: {
      symbol: { type: "string", description: "Function name, Class.method or path/to/file.ts:name" },
      depth: { type: "number", description: "Hops to follow, 1-4 (default 1)" },
      limit: { type: "number", description: "Most callers returned, 1-100 (default 30)" },
    },
    required: ["symbol"],
  },
  callees_of: {
    name: "callees_of",
    description:
      "List what a function or method calls, up to `depth` hops (1-4), marking calls that look like sinks (command, sql, file, network, eval, deserialize, template, redirect). TypeScript, JavaScript and Python (Java with Foxguard installed); otherwise use rg.",
    parameters: {
      symbol: { type: "string", description: "Function name, Class.method or path/to/file.ts:name" },
      depth: { type: "number", description: "Hops to follow, 1-4 (default 1)" },
      limit: { type: "number", description: "Most calls returned, 1-150 (default 40)" },
    },
    required: ["symbol"],
  },
  routes: {
    name: "routes",
    description:
      "List HTTP routes and entry points (Express-style, NestJS, Flask, FastAPI, Django URLConf; Spring, JAX-RS and servlets in Java) with their middleware, handler, the sink categories the handler reaches and any auth or ownership signals (middleware or calls named like auth, owner, permission). Set without_auth_signal to list routes where none was found, then confirm each with callers_of and cat -n. A missing signal is a lead, not a finding.",
    parameters: {
      path_contains: { type: "string", description: "Keep routes whose path contains this text" },
      method: { type: "string", description: "HTTP method filter", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"] },
      file: { type: "string", description: "Keep routes registered in files whose path contains this text" },
      without_auth_signal: { type: "boolean", description: "Only routes with no auth or ownership signal (default false)" },
      limit: { type: "number", description: "Most routes returned, 1-200 (default 60)" },
    },
  },
  trace_to_sink: {
    name: "trace_to_sink",
    description:
      "Find call paths from a route (for example \"GET /notes/:id\") or a function to a sink call, bounded by max_depth (1-8) and max_paths (1-20). Each path lists the hops, the sink and the auth-like names seen along it. It follows calls by name and does not prove data flow: read each hop before claiming a finding.",
    parameters: {
      from: { type: "string", description: "A route like \"GET /notes/:id\" or a symbol name" },
      sink: { type: "string", description: "Only this sink category", enum: [...SINK_CATEGORIES] },
      max_depth: { type: "number", description: "Most call hops, 1-8 (default 5)" },
      max_paths: { type: "number", description: "Most paths returned, 1-20 (default 8)" },
    },
    required: ["from"],
  },
};

export const codeIndexDispatch: Record<string, string> = {
  callers_of: "callersOfTool",
  callees_of: "calleesOfTool",
  routes: "routesTool",
  trace_to_sink: "traceToSinkTool",
};

function reject(tool: string, error: z.ZodError): ToolResult {
  return { success: false, output: null, error: `${tool}: invalid arguments: ${error.issues.map((i) => `${i.path.join(".") || "(root)"} ${i.message}`).join("; ")}` };
}

function noRoot(): ToolResult {
  return { success: false, output: null, error: `No folder is granted for this run, so there is nothing to index. ${FALLBACK}` };
}

/** Index the granted folder, or return the soft failure to hand back. */
async function indexFor(root: string | undefined): Promise<{ ok: true; index: Awaited<ReturnType<typeof getIndex>>["index"]; cached: boolean } | { ok: false; result: ToolResult }> {
  if (!root) return { ok: false, result: noRoot() };
  let built;
  try { built = await getIndex(root); } catch (err) {
    return { ok: false, result: { success: true, output: { supported: false, reason: `The folder could not be indexed (${err instanceof Error ? err.message : String(err)}).`, fallback: FALLBACK } } };
  }
  if (built.index.files === 0) {
    return { ok: false, result: { success: true, output: { supported: false, reason: built.index.unsupported["java"] ? "Java source was found but the Foxguard binary that indexes it is not available (ZERO_FOXGUARD_PATH or PATH), and no TypeScript, JavaScript or Python source was found." : "No TypeScript, JavaScript or Python source was found in the folder.", unsupported_files_by_extension: built.index.unsupported, fallback: FALLBACK } } };
  }
  return { ok: true, index: built.index, cached: built.cached };
}

export async function runCodeIndexTool(tool: string, args: unknown, root: string | undefined): Promise<ToolResult> {
  const withIndex = async (fn: (index: Awaited<ReturnType<typeof getIndex>>["index"]) => object): Promise<ToolResult> => {
    const got = await indexFor(root);
    if (!got.ok) return got.result;
    const out = fn(got.index);
    if ("error" in out && typeof out.error === "string") return { success: true, output: { found: false, message: out.error, fallback: FALLBACK } };
    return { success: true, output: { ...out, index: { ...coverageOf(got.index), cached: got.cached }, note: "Name-based index: confirm each hop by reading the code." } };
  };
  switch (tool) {
    case "callers_of": {
      const p = callersOfSchema.safeParse(args ?? {});
      if (!p.success) return reject(tool, p.error);
      return await withIndex((index) => callersOf(index, p.data.symbol, p.data.depth, p.data.limit));
    }
    case "callees_of": {
      const p = calleesOfSchema.safeParse(args ?? {});
      if (!p.success) return reject(tool, p.error);
      return await withIndex((index) => calleesOf(index, p.data.symbol, p.data.depth, p.data.limit));
    }
    case "routes": {
      const p = routesSchema.safeParse(args ?? {});
      if (!p.success) return reject(tool, p.error);
      return await withIndex((index) => routesOf(index, { ...(p.data.path_contains ? { pathContains: p.data.path_contains } : {}), ...(p.data.method ? { method: p.data.method } : {}), ...(p.data.file ? { file: p.data.file } : {}), withoutAuthSignal: p.data.without_auth_signal }, p.data.limit));
    }
    case "trace_to_sink": {
      const p = traceToSinkSchema.safeParse(args ?? {});
      if (!p.success) return reject(tool, p.error);
      return await withIndex((index) => traceToSink(index, p.data.from, p.data.sink as SinkCategory | undefined, p.data.max_depth, p.data.max_paths));
    }
    default:
      return { success: false, output: null, error: `Unknown tool: ${tool}` };
  }
}
