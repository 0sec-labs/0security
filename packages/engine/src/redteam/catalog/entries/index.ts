/** Every catalog entry in research order, and the derived lookups. */
import type { GeneratorSpec, ScenarioTemplate } from "../types.js";
import { AGENCY } from "./agency.js";
import { AUTOMATION } from "./automation.js";
import { BROWSER } from "./browser.js";
import { EVAL } from "./eval.js";
import { EXFILTRATION } from "./exfiltration.js";
import type { CatalogEntry } from "./helpers.js";
import { IDENTITY } from "./identity.js";
import { INJECTION } from "./injection.js";
import { MCP } from "./mcp.js";
import { MEMORY } from "./memory.js";
import { MULTI_AGENT } from "./multi-agent.js";
import { PAYMENTS } from "./payments.js";

export const ENTRIES: readonly CatalogEntry[] = [...INJECTION, ...AGENCY, ...EXFILTRATION, ...MEMORY, ...MCP, ...IDENTITY, ...PAYMENTS, ...MULTI_AGENT, ...BROWSER, ...AUTOMATION, ...EVAL];

/** All generator specs, open and closed. */
export const CATALOG: readonly GeneratorSpec[] = ENTRIES.map(entry => entry.spec);
export const CATALOG_BY_ID: ReadonlyMap<string, GeneratorSpec> = new Map(CATALOG.map(spec => [spec.id, spec] as const));
/** Complete scenario templates, one for each generator whose tier is open or both. */
export const TEMPLATES: readonly ScenarioTemplate[] = ENTRIES.flatMap(entry => (entry.template ? [entry.template] : []));
export const TEMPLATES_BY_ID: ReadonlyMap<string, ScenarioTemplate> = new Map(TEMPLATES.map(template => [template.generatorId, template] as const));
