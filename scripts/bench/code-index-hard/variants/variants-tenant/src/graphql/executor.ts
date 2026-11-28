import { resolvers } from "./resolvers";
import type { Loaders } from "./loaders";
import type { AuthUser } from "../models/base";

export interface GraphqlContext {
  user: AuthUser;
  loaders: Loaders;
}

export interface GraphqlRequest {
  query: string;
  variables: Record<string, unknown>;
}

type Resolver = (args: Record<string, unknown>, ctx: GraphqlContext) => unknown;

// Supports one top-level field per request: { field(arg: "x", other: $var) { a b c } }
const OPERATION = /^\s*(?:query\s*\w*\s*)?\{\s*(\w+)\s*(?:\(([^)]*)\))?\s*(?:\{([^}]*)\})?\s*\}\s*$/;
const ARG = /(\w+)\s*:\s*(?:"([^"]*)"|\$(\w+))/g;

function project(value: unknown, selection: string): unknown {
  const names = selection.split(/[\s,]+/).filter(Boolean);
  if (value === null || value === undefined) return null;
  if (names.length === 0) return value;
  const shape = (row: any) => Object.fromEntries(names.filter((name) => name in row).map((name) => [name, row[name]]));
  return Array.isArray(value) ? value.map(shape) : shape(value);
}

export function execute(request: GraphqlRequest, ctx: GraphqlContext) {
  const match = OPERATION.exec(request.query);
  if (!match) return { errors: [{ message: "unsupported query" }] };
  const [, field, rawArgs = "", rawSelection = ""] = match;
  const resolver = (resolvers.Query as Record<string, Resolver>)[field];
  if (!resolver) return { errors: [{ message: "unknown field " + field }] };
  const args: Record<string, unknown> = {};
  for (const arg of rawArgs.matchAll(ARG)) args[arg[1]] = arg[2] !== undefined ? arg[2] : request.variables[arg[3]];
  return { data: { [field]: project(resolver(args, ctx), rawSelection) } };
}
