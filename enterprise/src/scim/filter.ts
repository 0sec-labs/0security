// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// SCIM filter expressions (RFC 7644 section 3.4.2.2): eq ne co sw ew gt ge lt le pr, and, or, not, brackets.
// Attribute names and operators are case-insensitive. Values are compared as strings, numbers or booleans.

export class ScimError extends Error {
  constructor(readonly status: number, readonly scimType: string | undefined, message: string) { super(message); this.name = "ScimError"; }
}

export type FilterNode =
  | { kind: "cmp"; path: string[]; op: string; value?: string | number | boolean | null; filter?: FilterNode }
  | { kind: "and" | "or"; left: FilterNode; right: FilterNode }
  | { kind: "not"; inner: FilterNode };

const OPS = new Set(["eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le", "pr"]);
const MAX_FILTER = 2000;
const MAX_DEPTH = 20;

class Parser {
  private i = 0;
  private depth = 0;
  constructor(private readonly text: string) {}
  parse(): FilterNode {
    const node = this.or();
    this.ws();
    if (this.i < this.text.length) this.fail("unexpected text");
    return node;
  }
  private fail(why: string): never { throw new ScimError(400, "invalidFilter", `Invalid filter: ${why} at position ${this.i}`); }
  private ws() { while (this.i < this.text.length && /\s/.test(this.text[this.i]!)) this.i++; }
  private word(): string | null {
    this.ws();
    const m = /^[A-Za-z0-9_$:.\-]+/.exec(this.text.slice(this.i));
    return m ? m[0] : null;
  }
  private keyword(name: string): boolean {
    this.ws();
    const m = new RegExp(`^${name}(?=[\\s(])`, "i").exec(this.text.slice(this.i));
    if (!m) return false;
    this.i += name.length; return true;
  }
  private or(): FilterNode {
    let left = this.and();
    while (this.keyword("or")) left = { kind: "or", left, right: this.and() };
    return left;
  }
  private and(): FilterNode {
    let left = this.unary();
    while (this.keyword("and")) left = { kind: "and", left, right: this.unary() };
    return left;
  }
  private unary(): FilterNode {
    this.ws();
    if (++this.depth > MAX_DEPTH) this.fail("too deeply nested");
    try {
      if (this.keyword("not")) { this.ws(); if (this.text[this.i] !== "(") this.fail('"not" needs brackets'); return { kind: "not", inner: this.group() }; }
      if (this.text[this.i] === "(") return this.group();
      return this.comparison();
    } finally { this.depth--; }
  }
  private group(): FilterNode {
    this.i++; // (
    const inner = this.or();
    this.ws();
    if (this.text[this.i] !== ")") this.fail("missing closing bracket");
    this.i++;
    return inner;
  }
  private comparison(): FilterNode {
    const attr = this.word();
    if (!attr) this.fail("expected an attribute name");
    this.i += attr!.length;
    // The URN prefix of an attribute is accepted and dropped: urn:...:User:userName.
    const name = attr!.replace(/^urn:[^]*:(?=[A-Za-z]+(?:\.[A-Za-z]+)?$)/i, "");
    const path = name.split(".").map((part) => part.toLowerCase());
    let sub: FilterNode | undefined;
    if (this.text[this.i] === "[") {
      this.i++; sub = this.or(); this.ws();
      if (this.text[this.i] !== "]") this.fail("missing closing square bracket");
      this.i++;
      // emails[type eq "work"].value pr  is the same as  emails[type eq "work" and value pr].
      if (this.text[this.i] === ".") {
        this.i++;
        const subName = this.word();
        if (!subName) this.fail("expected a sub-attribute name");
        this.i += subName!.length;
        const subOp = this.word()?.toLowerCase();
        if (!subOp || !OPS.has(subOp)) this.fail("expected a comparison operator");
        this.i += subOp!.length;
        const inner: FilterNode = subOp === "pr" ? { kind: "cmp", path: [subName!.toLowerCase()], op: "pr" } : { kind: "cmp", path: [subName!.toLowerCase()], op: subOp!, value: (this.ws(), this.value()) };
        sub = { kind: "and", left: sub, right: inner };
      }
      return { kind: "cmp", path, op: "pr", filter: sub };
    }
    const op = this.word()?.toLowerCase();
    if (!op || !OPS.has(op)) this.fail("expected a comparison operator");
    this.i += op!.length;
    if (op === "pr") return { kind: "cmp", path, op: "pr" };
    this.ws();
    return { kind: "cmp", path, op: op!, value: this.value() };
  }
  private value(): string | number | boolean | null {
    this.ws();
    const rest = this.text.slice(this.i);
    if (rest[0] === '"') {
      let out = ""; let j = 1;
      for (; j < rest.length; j++) {
        const ch = rest[j]!;
        if (ch === "\\") { const next = rest[++j]; if (next === undefined) this.fail("unterminated string"); out += next; continue; }
        if (ch === '"') break;
        out += ch;
      }
      if (rest[j] !== '"') this.fail("unterminated string");
      this.i += j + 1; return out;
    }
    const m = /^(?:true|false|null|-?\d+(?:\.\d+)?)(?=[\s)\]]|$)/i.exec(rest);
    if (!m) this.fail("expected a quoted string, number, true, false or null");
    this.i += m![0].length;
    const lower = m![0].toLowerCase();
    return lower === "true" ? true : lower === "false" ? false : lower === "null" ? null : Number(m![0]);
  }
}

export function parseFilter(text: string): FilterNode {
  if (text.length > MAX_FILTER) throw new ScimError(400, "invalidFilter", "Invalid filter: too long");
  return new Parser(text).parse();
}

function lookup(resource: unknown, path: readonly string[]): unknown[] {
  let current: unknown[] = [resource];
  for (const part of path) {
    const next: unknown[] = [];
    for (const item of current) {
      if (Array.isArray(item)) { for (const el of item) if (el && typeof el === "object") next.push(...valuesOf(el as Record<string, unknown>, part)); }
      else if (item && typeof item === "object") next.push(...valuesOf(item as Record<string, unknown>, part));
    }
    current = next;
  }
  return current.flatMap((value) => (Array.isArray(value) ? value : [value])).filter((value) => value !== undefined);
}
function valuesOf(obj: Record<string, unknown>, lowerName: string): unknown[] {
  const key = Object.keys(obj).find((candidate) => candidate.toLowerCase() === lowerName);
  return key === undefined ? [] : [obj[key]];
}

function compare(actual: unknown, op: string, expected: string | number | boolean | null | undefined): boolean {
  if (actual === null || actual === undefined) return op === "eq" && expected === null;
  if (typeof actual === "string" && typeof expected === "string") {
    // userName, externalId and displayName compare without regard to case in practice; the core schema marks most strings caseExact false.
    const a = actual.toLowerCase(); const b = expected.toLowerCase();
    switch (op) {
      case "eq": return a === b; case "ne": return a !== b; case "co": return a.includes(b); case "sw": return a.startsWith(b); case "ew": return a.endsWith(b);
      case "gt": return a > b; case "ge": return a >= b; case "lt": return a < b; case "le": return a <= b;
    }
  }
  if (typeof actual === typeof expected) {
    switch (op) { case "eq": return actual === expected; case "ne": return actual !== expected; case "gt": return (actual as number) > (expected as number); case "ge": return (actual as number) >= (expected as number); case "lt": return (actual as number) < (expected as number); case "le": return (actual as number) <= (expected as number); }
  }
  return op === "ne";
}

/** True when the resource (a JSON object) matches the filter. */
export function matchesFilter(node: FilterNode, resource: unknown): boolean {
  switch (node.kind) {
    case "and": return matchesFilter(node.left, resource) && matchesFilter(node.right, resource);
    case "or": return matchesFilter(node.left, resource) || matchesFilter(node.right, resource);
    case "not": return !matchesFilter(node.inner, resource);
    case "cmp": {
      const found = lookup(resource, node.path);
      if (node.filter) return found.some((item) => matchesFilter(node.filter!, item));
      if (node.op === "pr") return found.some((value) => value !== null && value !== "" && !(Array.isArray(value) && value.length === 0));
      if (found.length === 0) return node.op === "ne";
      return node.op === "ne" ? found.every((value) => compare(value, "ne", node.value)) : found.some((value) => compare(value, node.op, node.value));
    }
  }
}
