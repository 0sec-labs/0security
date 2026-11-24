// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// SCIM PATCH (RFC 7644 section 3.5.2) on a JSON resource: add, replace and remove, with or without a path,
// with value filters like members[value eq "x"] and emails[type eq "work"].value.
// Identity provider habits handled here: operation names in any case (Entra sends Add, Replace, Remove),
// a replace without a path whose value is an object (Okta), booleans sent as the strings "True" and "False".
import { ScimError, matchesFilter, parseFilter } from "./filter.js";

export const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_OPERATIONS = 100;
type Json = Record<string, unknown>;

interface Target { attr: string; filter?: string; sub?: string }

function parsePath(raw: string): Target {
  // Drop a schema prefix: urn:ietf:params:scim:schemas:core:2.0:User:userName.
  const path = raw.replace(/^urn:[^[]*:(?=[A-Za-z$][^:[]*$|[A-Za-z$][^:]*\[)/i, "");
  const m = /^([A-Za-z$][A-Za-z0-9$_-]*)(?:\[(.*)\])?(?:\.([A-Za-z][A-Za-z0-9_-]*))?$/s.exec(path);
  if (!m) throw new ScimError(400, "invalidPath", `Invalid path: ${raw.slice(0, 100)}`);
  return { attr: m[1]!, ...(m[2] !== undefined ? { filter: m[2] } : {}), ...(m[3] !== undefined ? { sub: m[3] } : {}) };
}

const keyOf = (obj: Json, name: string): string => Object.keys(obj).find((k) => k.toLowerCase() === name.toLowerCase()) ?? name;
const stable = (v: unknown): string => JSON.stringify(v, (_k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x as Json).sort(([p], [q]) => p.localeCompare(q))) : x));
const same = (a: unknown, b: unknown): boolean => stable(a) === stable(b);
const isObject = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

function coerce(attr: string, value: unknown, booleans: readonly string[]): unknown {
  if (booleans.some((b) => b.toLowerCase() === attr.toLowerCase()) && typeof value === "string") {
    const lower = value.toLowerCase();
    if (lower === "true") return true;
    if (lower === "false") return false;
    throw new ScimError(400, "invalidValue", `${attr} must be true or false`);
  }
  return value;
}

function addValue(obj: Json, attr: string, value: unknown, booleans: readonly string[]): void {
  const key = keyOf(obj, attr);
  const current = obj[key];
  if (Array.isArray(current) || (current === undefined && Array.isArray(value))) {
    const items = Array.isArray(value) ? value : [value];
    const list = Array.isArray(current) ? [...current] : [];
    for (const item of items) if (!list.some((existing) => same(existing, item))) list.push(item);
    obj[key] = list;
  } else if (isObject(current) && isObject(value)) obj[key] = { ...current, ...value };
  else obj[key] = coerce(attr, value, booleans);
}

function apply(resource: Json, op: string, path: string | undefined, value: unknown, booleans: readonly string[]): void {
  if (path === undefined || path === "") {
    if (op === "remove") throw new ScimError(400, "noTarget", "remove needs a path");
    if (!isObject(value)) throw new ScimError(400, "invalidValue", `${op} without a path needs an object value`);
    for (const [name, inner] of Object.entries(value)) {
      if (name.includes(".") && !name.startsWith("urn:")) apply(resource, op, name, inner, booleans);
      else if (op === "replace") resource[keyOf(resource, name)] = coerce(name, inner, booleans);
      else addValue(resource, name, inner, booleans);
    }
    return;
  }
  const target = parsePath(path);
  const key = keyOf(resource, target.attr);
  if (target.filter !== undefined) {
    const list = resource[key];
    const node = parseFilter(target.filter);
    if (!Array.isArray(list)) { if (op === "remove") return; throw new ScimError(400, "noTarget", `${target.attr} has no values to select from`); }
    const hit = (item: unknown) => matchesFilter(node, item);
    if (!list.some(hit)) { if (op === "remove") return; throw new ScimError(400, "noTarget", `No ${target.attr} value matches the filter`); }
    if (op === "remove" && target.sub === undefined) { resource[key] = list.filter((item) => !hit(item)); return; }
    resource[key] = list.map((item) => {
      if (!hit(item) || !isObject(item)) return item;
      const copy = { ...item };
      if (target.sub === undefined) return isObject(value) ? { ...copy, ...value } : copy;
      if (op === "remove") delete copy[keyOf(copy, target.sub)];
      else copy[keyOf(copy, target.sub)] = value;
      return copy;
    });
    return;
  }
  if (target.sub !== undefined) {
    const parent = resource[key];
    if (parent !== undefined && !isObject(parent)) {
      // A multi-valued attribute with a sub-attribute: apply to every element (Entra sends emails.value this way).
      if (Array.isArray(parent)) { resource[key] = parent.map((item) => { if (!isObject(item)) return item; const copy = { ...item }; if (op === "remove") delete copy[keyOf(copy, target.sub!)]; else copy[keyOf(copy, target.sub!)] = value; return copy; }); return; }
      throw new ScimError(400, "invalidPath", `${target.attr} has no sub-attributes`);
    }
    const obj: Json = isObject(parent) ? { ...parent } : {};
    if (op === "remove") delete obj[keyOf(obj, target.sub)];
    else obj[keyOf(obj, target.sub)] = value;
    resource[key] = obj;
    return;
  }
  if (op === "remove") {
    if (isObject(value) || Array.isArray(value)) {
      // Entra removes group members with a path of "members" and the members to remove as the value.
      const list = resource[key];
      if (Array.isArray(list)) { const gone = Array.isArray(value) ? value : [value]; resource[key] = list.filter((item) => !gone.some((g) => isObject(g) && isObject(item) && g.value === item.value)); return; }
    }
    delete resource[key]; return;
  }
  if (op === "replace") resource[key] = coerce(target.attr, value, booleans);
  else addValue(resource, target.attr, value, booleans);
}

/** Returns a patched copy of the resource. Throws ScimError for a request that cannot be applied. */
export function applyPatch(resource: Json, body: unknown, options: { booleanAttributes?: readonly string[] } = {}): Json {
  if (!isObject(body)) throw new ScimError(400, "invalidSyntax", "The request body must be a JSON object");
  const schemas = body.schemas;
  if (Array.isArray(schemas) && !schemas.includes(PATCH_SCHEMA)) throw new ScimError(400, "invalidSyntax", `schemas must include ${PATCH_SCHEMA}`);
  const ops = body.Operations ?? body.operations;
  if (!Array.isArray(ops) || ops.length === 0) throw new ScimError(400, "invalidSyntax", "Operations must be a non-empty list");
  if (ops.length > MAX_OPERATIONS) throw new ScimError(400, "tooMany", `At most ${MAX_OPERATIONS} operations per request`);
  const out = structuredClone(resource);
  for (const entry of ops) {
    if (!isObject(entry) || typeof entry.op !== "string") throw new ScimError(400, "invalidSyntax", "Each operation needs an op");
    const op = entry.op.toLowerCase();
    if (op !== "add" && op !== "replace" && op !== "remove") throw new ScimError(400, "invalidValue", `Unknown op "${entry.op.slice(0, 20)}"`);
    if (entry.path !== undefined && typeof entry.path !== "string") throw new ScimError(400, "invalidPath", "path must be a string");
    apply(out, op, entry.path as string | undefined, entry.value, options.booleanAttributes ?? []);
  }
  return out;
}
