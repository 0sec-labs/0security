import { createHoneypot, type Honeypot, type HoneypotTool, type ToolHandler, type TraceEvent } from "../honeypot.js";
import { CANARY_PLACEHOLDER } from "../scenario.js";
import { KITS } from "./kits.js";
import type { Kit, KitEnv } from "./types.js";

export function listKits(): readonly Kit[] { return KITS; }

export function kitByName(name: string): Kit | undefined { return KITS.find(kit => kit.name === name); }

/** Merges kits into one. A tool name defined twice is an error, never silently resolved, because it would hide which reply an oracle saw. */
export function combineKits(kits: readonly Kit[]): Kit {
  const owner = new Map<string, string>();
  const tools: HoneypotTool[] = [];
  const replies: Record<string, string> = {};
  for (const kit of kits) {
    for (const tool of kit.tools) {
      const previous = owner.get(tool.name);
      if (previous !== undefined) throw new Error(`tool ${tool.name} is defined by both kit ${previous} and kit ${kit.name}`);
      owner.set(tool.name, kit.name);
      tools.push(tool);
    }
    Object.assign(replies, kit.replies);
  }
  return {
    name: kits.map(kit => kit.name).join("+") || "empty",
    description: kits.map(kit => kit.description).join(" "),
    tools, replies,
    handlers: env => Object.assign({}, ...kits.map(kit => kit.handlers(env))) as Record<string, ToolHandler>,
  };
}

/** The fewest kits that define every named tool. Each tool lives in exactly one kit, so this is the set of their owners. Unknown names throw. */
export function kitsForTools(names: readonly string[]): Kit[] {
  const found = new Set<Kit>();
  const unknown: string[] = [];
  for (const name of names) {
    const kit = KITS.find(candidate => candidate.tools.some(tool => tool.name === name));
    if (kit) found.add(kit); else unknown.push(name);
  }
  if (unknown.length) throw new Error(`no kit defines: ${unknown.join(", ")}`);
  return KITS.filter(kit => found.has(kit));
}

export interface KitHoneypotOptions {
  canary: string;
  /** Kits or kit names. The core kit is added unless `includeCore` is false. */
  kits: readonly (Kit | string)[];
  payload?: string;
  /** Memory entries present at the start; the literal AGENT-CANARY-0 in a value becomes this run's canary. */
  seedMemory?: Readonly<Record<string, string>>;
  includeCore?: boolean;
  onCall?: (event: TraceEvent) => void;
}

const fill = (text: string, canary: string) => text.split(CANARY_PLACEHOLDER).join(canary);

export function makeKitHoneypot(options: KitHoneypotOptions): Honeypot {
  const resolved = options.kits.map(entry => {
    if (typeof entry !== "string") return entry;
    const kit = kitByName(entry);
    if (!kit) throw new Error(`unknown kit: ${entry}`);
    return kit;
  });
  const unique = [...new Set(resolved)];
  const withCore = options.includeCore === false ? unique : [...(unique.some(kit => kit.name === "core") ? [] : [kitByName("core")!]), ...unique];
  const combined = combineKits(withCore);
  const seedMemory = Object.fromEntries(Object.entries(options.seedMemory ?? {}).map(([key, value]) => [key, fill(value, options.canary)]));
  const env: KitEnv = { seedMemory };
  return createHoneypot({
    canary: options.canary,
    tools: combined.tools,
    replies: combined.replies,
    handlers: combined.handlers(env),
    ...(options.payload !== undefined ? { payload: fill(options.payload, options.canary) } : {}),
    ...(options.onCall ? { onCall: options.onCall } : {}),
  });
}
