/**
 * License policy for SBOM components: parses SPDX license expressions and decides, per component, whether the stated
 * license is denied, not allowed, unknown or allowed. Only what the SBOM states is judged: free-text license names and
 * ids that are not on the SPDX list are "unknown", never corrected or guessed. Information, not legal advice.
 */
import { createHash } from "node:crypto";
import { SPDX_LICENSE_IDS } from "./spdx-ids.js";

export type UnknownMode = "warn" | "fail" | "allow";
export type Verdict = "denied" | "not-allowed" | "unknown" | "allowed";
export interface PackageException { package: string; version?: string; licenses?: string[]; reason: string }
export interface LicensePolicy { allow: string[]; deny: string[]; allowByPackage: PackageException[]; unknown: UnknownMode }

export const PRESET_NAMES = ["permissive", "no-copyleft"] as const;
export type PresetName = (typeof PRESET_NAMES)[number];
export const PRESETS: Record<PresetName, { allow: string[]; deny: string[]; unknown: UnknownMode }> = {
  permissive: { allow: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0", "Zlib", "BlueOak-1.0.0", "Python-2.0"], deny: [], unknown: "warn" },
  "no-copyleft": { allow: [], deny: ["GPL-*", "AGPL-*", "LGPL-*", "SSPL-*", "EUPL-*"], unknown: "warn" },
};

// --- SPDX expressions -------------------------------------------------------------------------------------------

export interface LicenseLeaf { k: "id"; id: string; plus: boolean; exception?: string }
export type LicenseNode = LicenseLeaf | { k: "and" | "or"; left: LicenseNode; right: LicenseNode };

/** Parse an SPDX license expression (ids, `+`, `WITH`, `AND`, `OR`, parentheses; operators in upper case). Returns undefined for anything else. */
export function parseLicenseExpression(text: string): LicenseNode | undefined {
  const tokens = text.match(/[()]|[^\s()]+/g) ?? [];
  let index = 0;
  const peek = () => tokens[index];
  const operand = (token: string): { id: string; plus: boolean } | undefined => {
    const plus = token.endsWith("+");
    const id = plus ? token.slice(0, -1) : token;
    return SPDX_LICENSE_IDS.has(id) || /^LicenseRef-[A-Za-z0-9.-]+$/.test(id) ? { id, plus } : undefined;
  };
  const simple = (): LicenseNode | undefined => {
    const token = tokens[index];
    if (token === undefined) return undefined;
    if (token === "(") {
      index += 1;
      const inner = or();
      if (!inner || tokens[index] !== ")") return undefined;
      index += 1;
      return inner;
    }
    const base = operand(token);
    if (!base) return undefined;
    index += 1;
    const leaf: LicenseLeaf = { k: "id", ...base };
    if (peek() === "WITH") {
      const exception = tokens[index + 1];
      if (!exception || !SPDX_LICENSE_IDS.has(exception)) return undefined;
      leaf.exception = exception;
      index += 2;
    }
    return leaf;
  };
  const and = (): LicenseNode | undefined => {
    let left = simple();
    while (left && peek() === "AND") { index += 1; const right = simple(); if (!right) return undefined; left = { k: "and", left, right }; }
    return left;
  };
  const or = (): LicenseNode | undefined => {
    let left = and();
    while (left && peek() === "OR") { index += 1; const right = and(); if (!right) return undefined; left = { k: "or", left, right }; }
    return left;
  };
  const result = or();
  return result && index === tokens.length ? result : undefined;
}

/** The text of a leaf, as written in an expression. */
export function leafText(leaf: LicenseLeaf): string {
  return `${leaf.id}${leaf.plus ? "+" : ""}${leaf.exception ? ` WITH ${leaf.exception}` : ""}`;
}

// --- Policy entries ---------------------------------------------------------------------------------------------

const GNU = /^(A?GPL|LGPL|GFDL)-\d\.\d$/;
/** GNU licenses have two spellings each: the deprecated bare id and `+`, and `-only` and `-or-later`. Both name the same license. */
function canonical(id: string, plus: boolean): string {
  if (GNU.test(id)) return plus ? `${id}-or-later` : `${id}-only`;
  return plus ? `${id}+` : id;
}
interface Entry { id: string; plus: boolean; exception?: string; prefix?: string }

function compileEntry(raw: string): Entry | string {
  const text = raw.trim();
  const pair = /^(\S+)\s+WITH\s+(\S+)$/.exec(text);
  if (pair) {
    const base = pair[1]!; const exception = pair[2]!;
    const plus = base.endsWith("+"); const id = plus ? base.slice(0, -1) : base;
    if (!SPDX_LICENSE_IDS.has(id) || !SPDX_LICENSE_IDS.has(exception)) return `'${text}' is not an SPDX license with an exception.`;
    return { id, plus, exception };
  }
  if (text.endsWith("*")) {
    const prefix = text.slice(0, -1);
    if (!prefix || prefix.includes("*") || ![...SPDX_LICENSE_IDS].some(id => id.startsWith(prefix))) return `'${text}' matches no SPDX license id. Use a prefix such as GPL-* or LGPL-*.`;
    return { id: prefix, plus: false, prefix };
  }
  const plus = text.endsWith("+"); const id = plus ? text.slice(0, -1) : text;
  if (SPDX_LICENSE_IDS.has(id) || /^LicenseRef-[A-Za-z0-9.-]+$/.test(id)) return { id, plus };
  return `'${text}' is not an SPDX license id (names are case-sensitive, for example Apache-2.0).`;
}

function entryMatches(entry: Entry, leaf: LicenseLeaf): boolean {
  if (entry.exception !== undefined && entry.exception !== leaf.exception) return false;
  if (entry.prefix !== undefined) return canonical(leaf.id, leaf.plus).startsWith(entry.prefix) || leaf.id.startsWith(entry.prefix);
  const wanted = canonical(entry.id, entry.plus);
  if (canonical(leaf.id, leaf.plus) === wanted) return true;
  // `Apache-2.0+` means that version or any later one, so a policy entry for `Apache-2.0` covers it.
  return leaf.plus && !GNU.test(leaf.id) && !entry.plus && leaf.id === entry.id;
}

/** Check a policy's lists and exceptions. Returns one message per problem. */
export function validatePolicy(policy: LicensePolicy): string[] {
  const problems: string[] = [];
  for (const [label, list] of [["allow", policy.allow], ["deny", policy.deny]] as const) {
    for (const item of list) { const entry = compileEntry(item); if (typeof entry === "string") problems.push(`${label}: ${entry}`); }
  }
  policy.allowByPackage.forEach((exception, index) => {
    if (!exception.package.trim()) problems.push(`allowByPackage[${index}]: package is required.`);
    if (!exception.reason.trim()) problems.push(`allowByPackage[${index}] (${exception.package}): a reason is required.`);
    for (const item of exception.licenses ?? []) { const entry = compileEntry(item); if (typeof entry === "string") problems.push(`allowByPackage[${index}].licenses: ${entry}`); }
  });
  return problems;
}

/** Turn parsed JSON or YAML into a policy. Unknown keys and wrong types are errors, so a typo does not silently weaken the policy. */
export function policyFromDocument(raw: unknown): Partial<LicensePolicy> & { preset?: PresetName } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("The policy must be an object with allow, deny, allowByPackage or unknown.");
  const document = raw as Record<string, unknown>;
  const known = ["allow", "deny", "allowByPackage", "unknown", "preset"];
  const extra = Object.keys(document).filter(key => !known.includes(key));
  if (extra.length) throw new Error(`Unknown policy key${extra.length === 1 ? "" : "s"}: ${extra.join(", ")}. Use ${known.join(", ")}.`);
  const strings = (key: string): string[] | undefined => {
    const value = document[key];
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.some(item => typeof item !== "string")) throw new Error(`${key} must be a list of SPDX ids.`);
    return value as string[];
  };
  const out: Partial<LicensePolicy> & { preset?: PresetName } = {};
  const allow = strings("allow"); if (allow) out.allow = allow;
  const deny = strings("deny"); if (deny) out.deny = deny;
  if (document.unknown !== undefined) {
    if (document.unknown !== "warn" && document.unknown !== "fail" && document.unknown !== "allow") throw new Error("unknown must be warn, fail or allow.");
    out.unknown = document.unknown;
  }
  if (document.preset !== undefined) {
    if (typeof document.preset !== "string" || !(PRESET_NAMES as readonly string[]).includes(document.preset)) throw new Error(`preset must be one of ${PRESET_NAMES.join(", ")}.`);
    out.preset = document.preset as PresetName;
  }
  if (document.allowByPackage !== undefined) {
    if (!Array.isArray(document.allowByPackage)) throw new Error("allowByPackage must be a list of { package, reason } entries.");
    out.allowByPackage = document.allowByPackage.map((item: unknown, index) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`allowByPackage[${index}] must be an object.`);
      const entry = item as Record<string, unknown>;
      const bad = Object.keys(entry).filter(key => !["package", "version", "licenses", "reason"].includes(key));
      if (bad.length) throw new Error(`allowByPackage[${index}]: unknown key ${bad.join(", ")}. Use package, version, licenses, reason.`);
      if (typeof entry.package !== "string") throw new Error(`allowByPackage[${index}]: package must be text, a name or a package URL.`);
      if (typeof entry.reason !== "string") throw new Error(`allowByPackage[${index}] (${entry.package}): a reason is required.`);
      if (entry.version !== undefined && typeof entry.version !== "string") throw new Error(`allowByPackage[${index}]: version must be text.`);
      if (entry.licenses !== undefined && (!Array.isArray(entry.licenses) || entry.licenses.some(value => typeof value !== "string"))) throw new Error(`allowByPackage[${index}]: licenses must be a list of SPDX ids.`);
      return { package: entry.package, reason: entry.reason, ...(entry.version !== undefined ? { version: entry.version } : {}), ...(entry.licenses ? { licenses: entry.licenses as string[] } : {}) };
    });
  }
  return out;
}

/** Build one policy from a preset, a policy file and flags. Lists are joined; `unknown` comes from the flag, then the file, then the preset, then `warn`. */
export function mergePolicies(parts: Array<Partial<LicensePolicy> & { preset?: PresetName }>): LicensePolicy {
  const merged: LicensePolicy = { allow: [], deny: [], allowByPackage: [], unknown: "warn" };
  for (const part of parts) {
    const preset = part.preset ? PRESETS[part.preset] : undefined;
    if (preset) { merged.allow.push(...preset.allow); merged.deny.push(...preset.deny); merged.unknown = preset.unknown; }
    merged.allow.push(...(part.allow ?? [])); merged.deny.push(...(part.deny ?? [])); merged.allowByPackage.push(...(part.allowByPackage ?? []));
    if (part.unknown) merged.unknown = part.unknown;
  }
  merged.allow = [...new Set(merged.allow)]; merged.deny = [...new Set(merged.deny)];
  return merged;
}

// --- Evaluation -------------------------------------------------------------------------------------------------

const RANK: Record<Verdict, number> = { allowed: 0, unknown: 1, "not-allowed": 2, denied: 3 };
const BY_RANK: Verdict[] = ["allowed", "unknown", "not-allowed", "denied"];
interface Outcome { rank: number; leaves: string[] }
type Compiled = { allow: Entry[]; deny: Entry[] };

function compile(list: string[]): Entry[] {
  return list.map(compileEntry).filter((entry): entry is Entry => typeof entry !== "string");
}

function leafOutcome(leaf: LicenseLeaf, lists: Compiled, extraAllow: Entry[], hasAllowList: boolean): Outcome {
  const hit = (entries: Entry[], specific: boolean) => entries.some(entry => (entry.exception !== undefined) === specific && entryMatches(entry, leaf));
  const text = leafText(leaf);
  const verdict = (value: Verdict): Outcome => ({ rank: RANK[value], leaves: value === "allowed" ? [] : [text] });
  if (extraAllow.some(entry => entryMatches(entry, leaf))) return verdict("allowed");
  // An entry that names the exception is more specific than one that names only the license.
  if (leaf.exception !== undefined) {
    if (hit(lists.deny, true)) return verdict("denied");
    if (hit(lists.allow, true)) return verdict("allowed");
  }
  if (hit(lists.deny, false)) return verdict("denied");
  if (hit(lists.allow, false)) return verdict("allowed");
  return verdict(hasAllowList ? "not-allowed" : "allowed");
}

function nodeOutcome(node: LicenseNode, lists: Compiled, extraAllow: Entry[], hasAllowList: boolean): Outcome {
  if (node.k === "id") return leafOutcome(node, lists, extraAllow, hasAllowList);
  const left = nodeOutcome(node.left, lists, extraAllow, hasAllowList);
  const right = nodeOutcome(node.right, lists, extraAllow, hasAllowList);
  // OR is the licensee's choice, so the better alternative counts; AND needs every part, so the worse one counts.
  if (node.k === "or") return right.rank < left.rank ? right : left;
  const rank = Math.max(left.rank, right.rank);
  return { rank, leaves: [...(left.rank === rank ? left.leaves : []), ...(right.rank === rank ? right.leaves : [])] };
}

export interface BomComponentLike { name?: unknown; version?: unknown; purl?: unknown; scope?: unknown; licenses?: unknown; components?: unknown }
export interface ComponentVerdict {
  name: string; version: string; purl: string; dev: boolean;
  /** The licenses as the SBOM states them: an id, an expression, or a free-text name. */
  licenses: string[];
  verdict: Verdict;
  /** The license ids or expressions that caused a denied, not-allowed or unknown verdict. */
  causes: string[];
  /** Why the verdict is unknown, or what exception waived it. */
  reason?: string;
  /** Set when an allowByPackage entry applies. */
  exception?: { reason: string; waived: boolean };
  /** Set when the license came from a registry lookup (`--resolve`) and not from the SBOM. */
  resolved?: boolean;
  /** True when this verdict fails the check under the policy. */
  violation: boolean;
}

interface Stated { texts: string[]; nodes: Array<LicenseNode | { unrecognised: string }> }
function statedLicenses(component: BomComponentLike): Stated {
  const stated: Stated = { texts: [], nodes: [] };
  if (!Array.isArray(component.licenses)) return stated;
  for (const choice of component.licenses as unknown[]) {
    if (!choice || typeof choice !== "object") continue;
    const entry = choice as { license?: { id?: unknown; name?: unknown }; expression?: unknown };
    if (typeof entry.expression === "string" && entry.expression.trim()) {
      const text = entry.expression.trim();
      stated.texts.push(text);
      stated.nodes.push(parseLicenseExpression(text) ?? { unrecognised: text });
    } else if (entry.license && typeof entry.license.id === "string" && entry.license.id.trim()) {
      const text = entry.license.id.trim();
      stated.texts.push(text);
      stated.nodes.push(SPDX_LICENSE_IDS.has(text) ? { k: "id", id: text, plus: false } : { unrecognised: text });
    } else if (entry.license && typeof entry.license.name === "string" && entry.license.name.trim()) {
      const text = entry.license.name.trim();
      stated.texts.push(text);
      stated.nodes.push({ unrecognised: text });   // free text is never matched against ids
    }
  }
  return stated;
}

function exceptionFor(component: { name: string; version: string; purl: string }, exceptions: PackageException[]): PackageException | undefined {
  const bare = component.purl.split("?")[0]!.replace(/@[^@/]*$/, "");
  const names = [component.name, component.purl, bare];
  return exceptions.find(item => names.includes(item.package.trim()) && (item.version === undefined || item.version === component.version));
}

/** Decide one component's verdict. */
export function judgeComponent(component: BomComponentLike, policy: LicensePolicy): ComponentVerdict {
  const name = typeof component.name === "string" ? component.name : "(unnamed)";
  const version = typeof component.version === "string" ? component.version : "";
  const purl = typeof component.purl === "string" ? component.purl : `${name}${version ? `@${version}` : ""}`;
  const base = { name, version, purl, dev: component.scope === "excluded" };
  const stated = statedLicenses(component);
  const lists: Compiled = { allow: compile(policy.allow), deny: compile(policy.deny) };
  const exception = exceptionFor(base, policy.allowByPackage);
  const extraAllow = exception?.licenses ? compile(exception.licenses) : [];
  const hasAllowList = lists.allow.length > 0;
  let rank = 0; let causes: string[] = []; let reason: string | undefined;
  if (!stated.nodes.length) { rank = RANK.unknown; reason = "no license stated"; }
  else {
    for (const node of stated.nodes) {
      const outcome: Outcome = "unrecognised" in node
        ? { rank: RANK.unknown, leaves: [node.unrecognised] }
        : nodeOutcome(node, lists, extraAllow, hasAllowList);
      if (outcome.rank > rank) { rank = outcome.rank; causes = [...outcome.leaves]; }
      else if (outcome.rank === rank && rank > 0) causes.push(...outcome.leaves);
    }
    if (rank === RANK.unknown) reason = `license not recognised as SPDX: ${causes.join(", ")}`;
  }
  causes = [...new Set(causes)];
  const verdict = BY_RANK[rank]!;
  if (exception && verdict !== "allowed") {
    // With `licenses` the entry only adds allowed ids (already applied above); without it the component is waived.
    if (!exception.licenses) {
      return { ...base, licenses: stated.texts, verdict: "allowed", causes: [], exception: { reason: exception.reason, waived: true }, violation: false };
    }
  }
  const violation = verdict === "denied" || verdict === "not-allowed" || (verdict === "unknown" && policy.unknown === "fail");
  const result: ComponentVerdict = { ...base, licenses: stated.texts, verdict, causes, violation };
  if (reason) result.reason = reason;
  if (exception) result.exception = { reason: exception.reason, waived: false };
  return result;
}

export interface LicenseReport {
  policy: LicensePolicy;
  components: ComponentVerdict[];
  summary: { total: number; denied: number; notAllowed: number; unknown: number; allowed: number; excepted: number; violations: number };
}

function collect(components: unknown, into: BomComponentLike[]): void {
  if (!Array.isArray(components)) return;
  for (const item of components) {
    if (!item || typeof item !== "object") continue;
    into.push(item as BomComponentLike);
    collect((item as BomComponentLike).components, into);
  }
}

/** Judge every component in a CycloneDX document (nested components included). Throws when the policy is invalid. */
export function checkBomLicenses(bom: unknown, policy: LicensePolicy, options: { excludeDev?: boolean } = {}): LicenseReport {
  const problems = validatePolicy(policy);
  if (problems.length) throw new Error(problems.join("\n"));
  const flat: BomComponentLike[] = [];
  collect((bom as { components?: unknown } | undefined)?.components, flat);
  const components = flat.map(component => judgeComponent(component, policy)).filter(component => !(options.excludeDev && component.dev));
  const count = (verdict: Verdict) => components.filter(component => component.verdict === verdict).length;
  return {
    policy, components,
    summary: {
      total: components.length, denied: count("denied"), notAllowed: count("not-allowed"), unknown: count("unknown"), allowed: count("allowed"),
      excepted: components.filter(component => component.exception).length, violations: components.filter(component => component.violation).length,
    },
  };
}

// --- SARIF ------------------------------------------------------------------------------------------------------

/** The license id a violation is filed under: the first cause's license id, or `unknown`. */
function ruleSuffix(component: ComponentVerdict): string {
  if (component.verdict === "unknown") return "unknown";
  const cause = component.causes[0] ?? "unknown";
  // The part before the first ` WITH `: `split(/\s+WITH\s+/)` gives the same, in quadratic time on a long run of spaces.
  const withAt = cause.search(/\sWITH\s/);
  return (withAt === -1 ? cause : cause.slice(0, withAt).trimEnd()).replace(/\+$/, "") || "unknown";
}

/** SARIF 2.1.0: one result per violating component (and per unknown component when unknown is `warn`), rule id `license/<spdx-id>`. */
export function licensesToSarif(report: LicenseReport, options: { toolVersion: string; uri: (component: ComponentVerdict) => string }): object {
  const reportable = report.components.filter(component => component.violation || (component.verdict === "unknown" && report.policy.unknown === "warn"));
  const rules = new Map<string, string>();
  const results = reportable.map(component => {
    const suffix = ruleSuffix(component);
    const ruleId = `license/${suffix}`;
    const description = component.verdict === "unknown" ? "Component with no license data, or one that is not an SPDX license id" : component.verdict === "denied" ? `License ${suffix} is denied by the policy` : `License ${suffix} is not allowed by the policy`;
    rules.set(ruleId, description);
    const stated = component.licenses.length ? component.licenses.join(", ") : "none stated";
    const text = component.verdict === "unknown"
      ? `${component.name}@${component.version}: license unknown (${component.reason ?? "unknown"}).`
      : `${component.name}@${component.version}: license ${stated} is ${component.verdict === "denied" ? "denied" : "not allowed"} (${component.causes.join(", ")}).`;
    return {
      ruleId,
      level: component.violation ? "error" : "warning",
      message: { text },
      locations: [{ physicalLocation: { artifactLocation: { uri: options.uri(component).split("\\").join("/") } } }],
      partialFingerprints: { "0LicensePolicy/v1": createHash("sha256").update([component.purl, component.verdict, ...[...component.causes].sort()].join("\n")).digest("hex").slice(0, 32) },
      properties: { purl: component.purl, licenses: component.licenses, verdict: component.verdict },
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "0 sbom licenses", version: options.toolVersion, informationUri: "https://github.com/0sec-labs/0security",
          rules: [...rules].sort(([a], [b]) => (a < b ? -1 : 1)).map(([id, text]) => ({ id, shortDescription: { text }, defaultConfiguration: { level: id === "license/unknown" ? "warning" : "error" } })),
        },
      },
      results,
    }],
  };
}
