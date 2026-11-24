/**
 * An inventory of the AI in a folder: models, datasets, hosted model ids and MCP servers, found by reading files as
 * text. Nothing is downloaded, imported or executed, and a reference the patterns do not recognise is simply missed,
 * so this lists what it saw and does not claim to be complete.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { extractMcpServers } from "../agentconfig/mcp.js";
import { launcherIssues } from "../agentconfig/launchers.js";
import { parseJsonc } from "../agentconfig/util.js";
import { scanModelFile } from "../modelscan/index.js";

export interface AiComponent {
  type: "machine-learning-model" | "data";
  "bom-ref": string;
  name: string;
  properties: Array<{ name: string; value: string }>;
}
/** A running service the product talks to (an MCP server). CycloneDX lists these apart from components. */
export interface AiService {
  "bom-ref": string;
  name: string;
  endpoints?: string[];
  properties: Array<{ name: string; value: string }>;
}

const SKIP = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".venv", "venv", "__pycache__", ".next", ".turbo", "coverage"]);
const CODE = new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".ipynb"]);
const MODEL_FILES: Record<string, { format: string; pickle: boolean }> = {
  ".gguf": { format: "gguf", pickle: false }, ".safetensors": { format: "safetensors", pickle: false }, ".onnx": { format: "onnx", pickle: false },
  ".tflite": { format: "tflite", pickle: false }, ".mlmodel": { format: "coreml", pickle: false }, ".h5": { format: "keras-h5", pickle: false },
  ".pt": { format: "pytorch", pickle: true }, ".pth": { format: "pytorch", pickle: true }, ".ckpt": { format: "checkpoint", pickle: true },
  ".pkl": { format: "pickle", pickle: true }, ".pickle": { format: "pickle", pickle: true }, ".joblib": { format: "joblib", pickle: true },
};
const MCP_CONFIGS = new Set(["mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "opencode.json", "opencode.jsonc"]);
/** Dot-folders where coding tools keep project configuration. Every other hidden folder is skipped. */
const TOOL_DIRS = new Set([".cursor", ".vscode", ".claude", ".gemini", ".codex", ".windsurf", ".continue", ".github", ".roo", ".cline"]);
const MAX_FILES = 8000;
const MAX_TEXT_BYTES = 1024 * 1024;
const HOSTED = /(?:^|[^\w.-])(?:model|model_name|modelName|model_id|modelId)\s*[:=]\s*["']((?:gpt-|o[134](?:-|["'])|chatgpt-|claude-|gemini-|gemma|llama|mistral|mixtral|codestral|deepseek-|qwen|grok-|command-|text-embedding-|sonar)[\w.:/-]{0,60})["']/g;
const HUB: Array<{ pattern: RegExp; type: AiComponent["type"]; how: string }> = [
  { pattern: /\.from_pretrained\(\s*["']([^"'\s]{2,120})["']/g, type: "machine-learning-model", how: "from_pretrained" },
  { pattern: /pipeline\([^)]*\bmodel\s*=\s*["']([^"'\s]{2,120})["']/g, type: "machine-learning-model", how: "pipeline model" },
  { pattern: /hf_hub_download\([^)]*\brepo_id\s*=\s*["']([^"'\s]{2,120})["']/g, type: "machine-learning-model", how: "hf_hub_download" },
  { pattern: /snapshot_download\(\s*(?:repo_id\s*=\s*)?["']([^"'\s]{2,120})["']/g, type: "machine-learning-model", how: "snapshot_download" },
  { pattern: /SentenceTransformer\(\s*["']([^"'\s]{2,120})["']/g, type: "machine-learning-model", how: "SentenceTransformer" },
  { pattern: /pipeline\(\s*["'][\w-]+["']\s*,\s*["']([^"'\s]{2,120})["']/g, type: "machine-learning-model", how: "transformers.js pipeline" },
  { pattern: /load_dataset\(\s*["']([^"'\s]{2,120})["']/g, type: "data", how: "load_dataset" },
];
const provider = (id: string): string => /^(gpt-|o[134]|chatgpt-|text-embedding-)/.test(id) ? "openai" : id.startsWith("claude-") ? "anthropic" : /^(gemini-|gemma)/.test(id) ? "google" : /^(llama)/.test(id) ? "meta" : /^(mistral|mixtral|codestral)/.test(id) ? "mistral" : id.startsWith("deepseek-") ? "deepseek" : id.startsWith("qwen") ? "alibaba" : id.startsWith("grok-") ? "xai" : id.startsWith("command-") ? "cohere" : "unspecified";
const clean = (value: string, max = 200): string => value.replace(/[^\x20-\x7e]/g, "").slice(0, max);
const lineOf = (source: string, index: number): number => source.slice(0, index).split("\n").length;

function listFiles(folder: string): string[] {
  const found: string[] = [];
  const walk = (dir: string, depth: number): void => {
    if (found.length >= MAX_FILES) return;
    let entries: string[];
    try { entries = readdirSync(dir).sort(); } catch { return; }
    for (const name of entries) {
      const path = join(dir, name);
      let info; try { info = statSync(path); } catch { continue; }
      if (info.isDirectory()) { if (depth < 8 && !SKIP.has(name) && (!name.startsWith(".") || TOOL_DIRS.has(name))) walk(path, depth + 1); continue; }
      found.push(path);
      if (found.length >= MAX_FILES) return;
    }
  };
  walk(folder, 0);
  return found;
}

/** What the pickle scanner found in a model file, as an extra risk property; nothing when it found no dangerous import. */
function pickleScanRisk(path: string): Array<{ name: string; value: string }> {
  const scan = scanModelFile(path);
  if (scan.verdict !== "dangerous") return [];
  const names = [...new Set(scan.findings.filter(item => item.risk === "dangerous").map(item => item.qualified))];
  return [{ name: "0:risk", value: clean(`dangerous pickle imports found (loading runs code): ${names.slice(0, 5).join(", ")}${names.length > 5 ? ` and ${names.length - 5} more` : ""}`, 300) }];
}

export function detectAi(folder: string): { components: AiComponent[]; services: AiService[] } {
  const components = new Map<string, AiComponent>();
  const services = new Map<string, AiService>();
  const add = (component: AiComponent): void => {
    const existing = components.get(component["bom-ref"]);
    if (!existing) components.set(component["bom-ref"], component);
    else for (const property of component.properties) if (!existing.properties.some(item => item.name === property.name && item.value === property.value)) existing.properties.push(property);
  };
  for (const path of listFiles(folder)) {
    const rel = relative(folder, path).replace(/\\/g, "/");
    const name = path.split(/[\\/]/).pop()!;
    const extension = extname(name).toLowerCase();
    const model = MODEL_FILES[extension];
    if (model) {
      add({ type: "machine-learning-model", "bom-ref": `ml-file:${rel}`, name: name, properties: [{ name: "0:source", value: rel }, { name: "0:found-by", value: "model file" }, { name: "0:format", value: model.format }, ...(model.pickle ? [{ name: "0:risk", value: "pickle-based format: loading can run code" }, ...pickleScanRisk(path)] : [])] });
      continue;
    }
    if (MCP_CONFIGS.has(name) || (name === "settings.json" && /^\.(?:gemini|vscode|cursor|claude)\//.test(rel))) {
      let info; try { info = statSync(path); } catch { continue; }
      if (info.size > MAX_TEXT_BYTES) continue;
      let config: unknown;
      try { config = parseJsonc(readFileSync(path, "utf8")); } catch { continue; }
      for (const server of extractMcpServers(config)) {
        const command = (server.command ?? []).join(" ").trim();
        const unpinned = command !== "" && launcherIssues(command).length > 0;
        const ref = `mcp:${rel}:${clean(server.name, 80)}`;
        services.set(ref, { "bom-ref": ref, name: `mcp:${clean(server.name, 80)}`, ...(server.url && /^https?:\/\//.test(server.url) ? { endpoints: [clean(server.url)] } : {}), properties: [{ name: "0:source", value: rel }, { name: "0:found-by", value: "MCP configuration" }, ...(command ? [{ name: "0:launch", value: clean(command) }] : []), ...(server.url ? [{ name: "0:url", value: clean(server.url) }] : []), ...(unpinned ? [{ name: "0:risk", value: "launched without a pinned version" }] : [])] });
      }
      continue;
    }
    if (!CODE.has(extension)) continue;
    let info; try { info = statSync(path); } catch { continue; }
    if (info.size > MAX_TEXT_BYTES) continue;
    let source: string;
    try { source = readFileSync(path, "utf8"); } catch { continue; }
    for (const hub of HUB) {
      for (const match of source.matchAll(hub.pattern)) {
        const id = clean(match[1]!);
        add({ type: hub.type, "bom-ref": `${hub.type === "data" ? "dataset" : "hub-model"}:${id}`, name: id, properties: [{ name: "0:source", value: `${rel}:${lineOf(source, match.index ?? 0)}` }, { name: "0:found-by", value: hub.how }] });
      }
    }
    for (const match of source.matchAll(HOSTED)) {
      const id = clean(match[1]!);
      add({ type: "machine-learning-model", "bom-ref": `hosted-model:${id}`, name: id, properties: [{ name: "0:source", value: `${rel}:${lineOf(source, match.index ?? 0)}` }, { name: "0:found-by", value: "hosted model id" }, { name: "0:provider", value: provider(id) }] });
    }
  }
  const byRef = (a: { "bom-ref": string }, b: { "bom-ref": string }) => (a["bom-ref"] < b["bom-ref"] ? -1 : a["bom-ref"] > b["bom-ref"] ? 1 : 0);
  return { components: [...components.values()].sort(byRef), services: [...services.values()].sort(byRef) };
}
