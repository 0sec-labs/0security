/**
 * A kit is one family of fake tools (payments, memory, browser, ...) plus the replies that make a catalog oracle observable. Kits
 * only describe the environment; the honeypot still records every call, and oracles still read only that record.
 */
import type { HoneypotTool, ToolHandler } from "../honeypot.js";

/** Per-run state a kit's handlers may need that is not recoverable from the call history. */
export interface KitEnv {
  /** Memory entries present before the run starts, for example a poisoned note. Values are already canary-substituted. */
  seedMemory: Readonly<Record<string, string>>;
}

export interface Kit {
  name: string;
  description: string;
  tools: readonly HoneypotTool[];
  /** Fixed reply text per tool name. */
  replies: Readonly<Record<string, string>>;
  /** Builds the dynamic handlers for one run. Handlers derive state from the call history, so they hold none of their own. */
  handlers(env: KitEnv): Readonly<Record<string, ToolHandler>>;
}
