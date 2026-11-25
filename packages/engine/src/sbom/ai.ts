/**
 * An inventory of the AI in a folder: models, datasets, hosted model ids and MCP servers, found by reading files as
 * text. Nothing is downloaded, imported, loaded or executed, and a reference the patterns do not recognise is simply
 * missed, so this lists what it saw and does not claim to be complete. Local model and data files are hashed (SHA-256)
 * up to a size limit and, for safetensors, GGUF and ONNX, their header is read as data. Nothing is checked against the
 * Hugging Face Hub: a Hub reference is a URL built from the id written in the code.
 */
import { closeSync, lstatSync, opendirSync, realpathSync, type Dirent } from "node:fs";
import { extname, join, relative, resolve, sep } from "node:path";
import { extractMcpServers } from "../agentconfig/mcp.js";
import { launcherIssues } from "../agentconfig/launchers.js";
import { parseJsonc } from "../agentconfig/util.js";
import { scanModelFile } from "../modelscan/index.js";
import { cardFacts, clean, configFacts, insideRoot, licenseFileId, MAX_DATA_HASH_BYTES, MAX_MODEL_HASH_BYTES, MAX_TOTAL_HASH_BYTES, MAX_TOTAL_TEXT_BYTES, modelFacts, openRegular, readTextSafe, sha256Of, spdxId, type Props } from "./ai-files.js";

type Property = { name: string; value: string };
export interface AiLicense { license: { id: string; acknowledgement: "declared" } | { name: string; acknowledgement: "declared" } }
export interface AiModelCard { modelParameters?: { task?: string; architectureFamily?: string; modelArchitecture?: string; datasets?: Array<{ ref: string }> } }
export interface AiData { type: "dataset"; name: string; contents?: { url: string } }

export interface AiComponent {
  type: "machine-learning-model" | "data";
  "bom-ref": string;
  name: string;
  version?: string;
  hashes?: Array<{ alg: "SHA-256"; content: string }>;
  licenses?: AiLicense[];
  externalReferences?: Array<{ type: "distribution"; url: string; comment: string }>;
  evidence?: { occurrences: Array<{ location: string; line?: number }> };
  modelCard?: AiModelCard;
  data?: AiData[];
  properties: Property[];
}
/** A running service the product talks to (an MCP server). CycloneDX lists these apart from components. */
export interface AiService {
  "bom-ref": string;
  name: string;
  endpoints?: string[];
  properties: Property[];
}
export interface AiInventory { components: AiComponent[]; services: AiService[]; /** What was cut short or skipped, for the SBOM's metadata. */ notes: string[] }
export interface AiOptions { maxModelHashBytes?: number; maxDataHashBytes?: number }

const SKIP = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".venv", "venv", "__pycache__", ".next", ".turbo", "coverage"]);
const CODE = new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".ipynb"]);
const MODEL_FILES: Record<string, { format: string; pickle: boolean }> = {
  ".gguf": { format: "gguf", pickle: false }, ".safetensors": { format: "safetensors", pickle: false }, ".onnx": { format: "onnx", pickle: false },
  ".ort": { format: "onnx-runtime", pickle: false }, ".tflite": { format: "tflite", pickle: false }, ".mlmodel": { format: "coreml", pickle: false },
  ".h5": { format: "keras-h5", pickle: false }, ".hdf5": { format: "keras-h5", pickle: false }, ".keras": { format: "keras", pickle: false },
  ".pt": { format: "pytorch", pickle: true }, ".pth": { format: "pytorch", pickle: true }, ".ckpt": { format: "checkpoint", pickle: true },
  ".pkl": { format: "pickle", pickle: true }, ".pickle": { format: "pickle", pickle: true }, ".joblib": { format: "joblib", pickle: true },
};
/** A `.bin` file is only called a model when its name is one a model library writes. */
const BIN_MODEL = /^(?:pytorch_model|adapter_model|consolidated|model)(?:[-.\w]*)\.bin$/i;
const DATA_FILES = new Set([".csv", ".tsv", ".jsonl", ".ndjson", ".parquet", ".arrow", ".feather", ".tfrecord", ".avro", ".orc", ".npy"]);
const MCP_CONFIGS = new Set(["mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "opencode.json", "opencode.jsonc"]);
/** Dot-folders where coding tools keep project configuration. Every other hidden folder is skipped. */
const TOOL_DIRS = new Set([".cursor", ".vscode", ".claude", ".gemini", ".codex", ".windsurf", ".continue", ".github", ".roo", ".cline"]);
const MAX_FILES = 8000;
const MAX_DIRS = 4000;
const MAX_DIR_ENTRIES = 10000;
const MAX_OCCURRENCES = 100;
/** Largest pickle file scanned for dangerous imports, and the most bytes scanned in one run. */
const MAX_PICKLE_SCAN_BYTES = 256 * 1024 ** 2;
const MAX_TOTAL_PICKLE_SCAN_BYTES = 1024 ** 3;
const MAX_DATA_COMPONENTS = 200;
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
/** `load_dataset` names that pick a file reader, not a dataset on the Hub. */
const DATASET_BUILDERS = new Set(["csv", "json", "jsonl", "parquet", "text", "arrow", "pandas", "imagefolder", "audiofolder", "videofolder", "webdataset", "sql", "xml", "hdf5"]);
const HUB_ID = /^[A-Za-z0-9][\w.-]*(?:\/[A-Za-z0-9][\w.-]*)?$/;
const COMMIT = /^[0-9a-f]{40}$/;
const provider = (id: string): string => /^(gpt-|o[134]|chatgpt-|text-embedding-)/.test(id) ? "openai" : id.startsWith("claude-") ? "anthropic" : /^(gemini-|gemma)/.test(id) ? "google" : /^(llama)/.test(id) ? "meta" : /^(mistral|mixtral|codestral)/.test(id) ? "mistral" : id.startsWith("deepseek-") ? "deepseek" : id.startsWith("qwen") ? "alibaba" : id.startsWith("grok-") ? "xai" : id.startsWith("command-") ? "cohere" : "unspecified";
const lineOf = (source: string, index: number): number => source.slice(0, index).split("\n").length;
const props = (items: Props): Property[] => items.map(([name, value]) => ({ name, value }));

interface Side { license: Array<{ id?: string; name?: string; source: string }>; task?: string; datasets: string[]; architecture?: string; family?: string }
interface Entry { path: string; rel: string; name: string; size: number }
/** Every regular file under the folder, in sorted order. Symlinks are never followed, and devices, FIFOs and sockets are skipped. */
function listFiles(folder: string, notes: string[]): Entry[] {
  const found: Entry[] = [];
  let dirs = 0; let cut = false;
  let realRoot = resolve(folder); try { realRoot = realpathSync(realRoot); } catch { /* keep the given path */ }
  const walk = (dir: string, depth: number): void => {
    if (cut) return;
    // A folder swapped for a symlink after it was listed must not lead out of the root.
    if (depth > 0 && !insideRoot(join(dir, "x"), realRoot)) return;
    let entries: Dirent[];
    try {
      // Read the folder in a stream and stop at the limit, so a folder with millions of entries costs bounded memory.
      const handle = opendirSync(dir); entries = [];
      try { for (let entry = handle.readSync(); entry; entry = handle.readSync()) { entries.push(entry); if (entries.length >= MAX_DIR_ENTRIES) { cut = true; break; } } } finally { handle.closeSync(); }
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } catch { return; }
    dirs += 1;
    for (const entry of entries) {
      const path = join(dir, entry.name);
      let directory = entry.isDirectory(); let file = entry.isFile();
      if (!directory && !file && !entry.isSymbolicLink() && !entry.isBlockDevice() && !entry.isCharacterDevice() && !entry.isFIFO() && !entry.isSocket()) {
        try { const info = lstatSync(path); directory = info.isDirectory(); file = info.isFile(); } catch { continue; }
      }
      if (directory) {
        if (depth >= 8 || SKIP.has(entry.name) || (entry.name.startsWith(".") && !TOOL_DIRS.has(entry.name))) continue;
        if (dirs >= MAX_DIRS) { cut = true; return; }
        walk(path, depth + 1);
        if (cut) return;
        continue;
      }
      if (!file) continue;
      let size = 0; try { size = lstatSync(path).size; } catch { continue; }
      found.push({ path, rel: relative(folder, path).replace(/\\/g, "/"), name: entry.name, size });
      if (found.length >= MAX_FILES) { cut = true; return; }
    }
  };
  walk(folder, 0);
  if (cut) notes.push(`AI inventory stopped after ${found.length} files and ${dirs} folders (limits ${MAX_FILES} files, ${MAX_DIRS} folders and ${MAX_DIR_ENTRIES} entries in one folder); later files were not read`);
  return found;
}

/** What the pickle scanner found in a model file, as an extra risk property; nothing when it found no dangerous import. */
function pickleScanRisk(path: string): Property[] {
  const scan = scanModelFile(path);
  if (scan.verdict !== "dangerous") return [];
  const names = [...new Set(scan.findings.filter(item => item.risk === "dangerous").map(item => item.qualified))];
  return [{ name: "0:risk", value: clean(`dangerous pickle imports found (loading runs code): ${names.slice(0, 5).join(", ")}${names.length > 5 ? ` and ${names.length - 5} more` : ""}`, 300) }];
}

/** The call's own text, from its opening parenthesis to the matching one (at most 600 characters). */
function callText(source: string, from: number): string {
  const open = source.indexOf("(", from);
  if (open < 0) return "";
  let depth = 0; let quote = "";
  for (let index = open; index < Math.min(source.length, open + 600); index += 1) {
    const ch = source[index]!;
    if (quote) { if (ch === quote && source[index - 1] !== "\\") quote = ""; continue; }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "(") depth += 1;
    else if (ch === ")") { depth -= 1; if (depth === 0) return source.slice(open, index + 1); }
  }
  return source.slice(open, open + 600);
}

const hubUrl = (kind: "models" | "datasets", id: string, revision?: string): string => {
  const base = `https://huggingface.co/${kind === "datasets" ? "datasets/" : ""}${id.split("/").map(encodeURIComponent).join("/")}`;
  return revision ? `${base}/tree/${encodeURIComponent(revision)}` : base;
};

export function detectAi(folder: string, options: AiOptions = {}): AiInventory {
  const modelCap = options.maxModelHashBytes ?? MAX_MODEL_HASH_BYTES;
  const dataCap = options.maxDataHashBytes ?? MAX_DATA_HASH_BYTES;
  const notes: string[] = [];
  const components = new Map<string, AiComponent>();
  const services = new Map<string, AiService>();
  const root = resolve(folder);
  let realRoot = root; try { realRoot = realpathSync(root); } catch { /* keep the given path */ }
  let pickleLeft = MAX_TOTAL_PICKLE_SCAN_BYTES;
  const pickleRisk = (path: string, size: number): Property[] => {
    if (size > MAX_PICKLE_SCAN_BYTES || size > pickleLeft) return [{ name: "0:pickle-scan-skipped", value: `too large: ${size} bytes is over the ${MAX_PICKLE_SCAN_BYTES} byte file limit or the ${MAX_TOTAL_PICKLE_SCAN_BYTES} byte limit for one run` }];
    pickleLeft -= size;
    return insideRoot(path, realRoot) ? pickleScanRisk(path) : [];
  };
  let textLeft = MAX_TOTAL_TEXT_BYTES; let hashLeft = MAX_TOTAL_HASH_BYTES;
  const add = (component: AiComponent): void => {
    const existing = components.get(component["bom-ref"]);
    if (!existing) { components.set(component["bom-ref"], component); return; }
    if (existing.properties.length < 200) for (const property of component.properties) if (!existing.properties.some(item => item.name === property.name && item.value === property.value)) existing.properties.push(property);
    if (component.evidence && (existing.evidence?.occurrences.length ?? 0) < MAX_OCCURRENCES * 4) existing.evidence = { occurrences: [...(existing.evidence?.occurrences ?? []), ...component.evidence.occurrences] };
    if (component.version && !existing.version) {
      existing.version = component.version;
      if (component.externalReferences) existing.externalReferences = component.externalReferences;
      if (component.data) existing.data = component.data;
    } else {
      if (component.externalReferences && !existing.externalReferences) existing.externalReferences = component.externalReferences;
      if (component.data && !existing.data) existing.data = component.data;
    }
    if (component.modelCard && !existing.modelCard) existing.modelCard = component.modelCard;
  };
  const text = (path: string, max: number, size: number): string | undefined => {
    if (size > max || size > textLeft) { if (size <= max) notes.push("AI inventory read-size limit reached; some files were not read"); return undefined; }
    const body = readTextSafe(path, max, realRoot);
    if (body !== undefined) textLeft -= size;
    return body;
  };
  const files = listFiles(folder, notes);
  const byDir = new Map<string, Map<string, Entry>>();
  for (const file of files) { const dir = file.rel.includes("/") ? file.rel.slice(0, file.rel.lastIndexOf("/")) : ""; (byDir.get(dir) ?? byDir.set(dir, new Map()).get(dir)!).set(file.name.toLowerCase(), file); }
  /** The model card, licence file and config.json beside a model, read once per folder. */
  const sideFacts = new Map<string, Side>();
  const beside = (dir: string): Side => {
    const cached = sideFacts.get(dir); if (cached) return cached;
    const names = byDir.get(dir) ?? new Map<string, Entry>();
    const result: Side = { license: [], datasets: [] };
    const readme = names.get("readme.md");
    if (readme) {
      const card = cardFacts(text(readme.path, 256 * 1024, readme.size) ?? "");
      result.task = card.task; result.datasets = card.datasets;
      if (card.license) { const id = spdxId(card.license); result.license.push(id ? { id, source: `${readme.rel} front matter` } : { name: card.license, source: `${readme.rel} front matter` }); }
    }
    for (const name of ["license", "license.txt", "license.md", "copying"]) {
      const file = names.get(name); if (!file) continue;
      const id = licenseFileId(text(file.path, 256 * 1024, file.size) ?? "");
      if (id && !result.license.some(item => item.id === id)) result.license.push({ id, source: file.rel });
      break;
    }
    const config = names.get("config.json");
    if (config) Object.assign(result, configFacts(text(config.path, 256 * 1024, config.size) ?? ""));
    sideFacts.set(dir, result);
    return result;
  };
  /** Hash a regular file with a size limit; the caller supplies the cap. */
  const hashed = (fd: number, size: number, cap: number): { hashes?: AiComponent["hashes"]; note?: Property } => {
    if (size > cap || size > hashLeft) return { note: { name: "0:hash-skipped", value: size > cap ? `too large: ${size} bytes is over the ${cap} byte limit` : `too large: the ${MAX_TOTAL_HASH_BYTES} byte limit for one run is used up` } };
    const content = sha256Of(fd, size);
    hashLeft -= size;
    return content ? { hashes: [{ alg: "SHA-256", content }] } : { note: { name: "0:hash-skipped", value: "the file changed while it was read" } };
  };
  let dataFiles = 0;
  const addDataset = (id: string, source: string, how: string, line: number | undefined, revision: string | undefined): string => {
    const local = !HUB_ID.test(id) || DATASET_BUILDERS.has(id) || existsInside(root, id);
    const ref = `dataset:${id}`;
    add({ type: "data", "bom-ref": ref, name: id, ...(revision && COMMIT.test(revision) ? { version: revision } : {}), evidence: { occurrences: [{ location: source, ...(line ? { line } : {}) }] },
      ...(local ? {} : { externalReferences: [{ type: "distribution" as const, url: hubUrl("datasets", id, revision), comment: "Hugging Face Hub dataset named in the code; not contacted or checked" }], data: [{ type: "dataset" as const, name: id, contents: { url: hubUrl("datasets", id, revision) } }] }),
      properties: [{ name: "0:source", value: line ? `${source}:${line}` : source }, { name: "0:found-by", value: how }, ...(local ? [{ name: "0:reference", value: "a file reader name or local path, not a Hub dataset" }] : revisionProps(revision, source, line))] });
    return ref;
  };
  for (const file of files) {
    const { path, rel, name } = file;
    const extension = extname(name).toLowerCase();
    const model = MODEL_FILES[extension] ?? (extension === ".bin" && BIN_MODEL.test(name) ? { format: "pytorch-bin", pickle: true } : undefined);
    if (model) {
      const open = openRegular(path, realRoot);
      const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "";
      const side = beside(dir);
      let hash: ReturnType<typeof hashed> = {}; let facts: ReturnType<typeof modelFacts>; let size = file.size;
      if (open) {
        try { size = open.size; hash = hashed(open.fd, open.size, modelCap); facts = modelFacts(model.format, open.fd, open.size); } finally { try { closeSync(open.fd); } catch { /* ignore */ } }
      } else hash = { note: { name: "0:hash-skipped", value: "the file could not be opened as a regular file" } };
      const family = facts?.family ?? side.family; const architecture = side.architecture;
      const datasetRefs = side.datasets.map(id => addDataset(id, `${dir ? `${dir}/` : ""}README.md`, "model card front matter", undefined, undefined));
      const card: AiModelCard["modelParameters"] = { ...(side.task ? { task: side.task } : {}), ...(family ? { architectureFamily: family } : {}), ...(architecture ? { modelArchitecture: architecture } : {}), ...(datasetRefs.length ? { datasets: datasetRefs.map(ref => ({ ref })) } : {}) };
      add({
        type: "machine-learning-model", "bom-ref": `ml-file:${rel}`, name,
        ...(hash.hashes ? { hashes: hash.hashes } : {}),
        ...(side.license.length ? { licenses: side.license.map((item): AiLicense => ({ license: item.id ? { id: item.id, acknowledgement: "declared" } : { name: item.name!, acknowledgement: "declared" } })) } : {}),
        evidence: { occurrences: [{ location: rel }] },
        ...(Object.keys(card).length ? { modelCard: { modelParameters: card } } : {}),
        properties: [{ name: "0:source", value: rel }, { name: "0:found-by", value: "model file" }, { name: "0:format", value: model.format }, { name: "0:size-bytes", value: String(size) },
          ...(hash.note ? [hash.note] : []), ...props(facts?.props ?? []),
          ...(side.license.length ? [{ name: "0:license-source", value: clean(side.license.map(item => item.source).join("; "), 200) }] : []),
          ...(model.pickle ? [{ name: "0:risk", value: "pickle-based format: loading can run code" }, ...pickleRisk(path, size)] : [])],
      });
      continue;
    }
    if (DATA_FILES.has(extension)) {
      if (dataFiles < MAX_DATA_COMPONENTS) {
        dataFiles += 1;
        const open = openRegular(path, realRoot);
        let hash: ReturnType<typeof hashed> = { note: { name: "0:hash-skipped", value: "the file could not be opened as a regular file" } };
        if (open) { try { hash = hashed(open.fd, open.size, dataCap); } finally { try { closeSync(open.fd); } catch { /* ignore */ } } }
        add({ type: "data", "bom-ref": `data-file:${rel}`, name, ...(hash.hashes ? { hashes: hash.hashes } : {}), evidence: { occurrences: [{ location: rel }] }, data: [{ type: "dataset", name }],
          properties: [{ name: "0:source", value: rel }, { name: "0:found-by", value: "data file" }, { name: "0:format", value: extension.slice(1) }, { name: "0:size-bytes", value: String(file.size) }, ...(hash.note ? [hash.note] : [])] });
      } else if (!notes.some(note => note.startsWith("AI inventory listed"))) notes.push(`AI inventory listed the first ${MAX_DATA_COMPONENTS} local data files and skipped the rest`);
      continue;
    }
    if (MCP_CONFIGS.has(name) || (name === "settings.json" && /^\.(?:gemini|vscode|cursor|claude)\//.test(rel))) {
      const body = text(path, MAX_TEXT_BYTES, file.size);
      if (body === undefined) continue;
      let config: unknown;
      try { config = parseJsonc(body); } catch { continue; }
      for (const server of extractMcpServers(config)) {
        const command = (server.command ?? []).join(" ").trim();
        const unpinned = command !== "" && launcherIssues(command).length > 0;
        const ref = `mcp:${rel}:${clean(server.name, 80)}`;
        services.set(ref, { "bom-ref": ref, name: `mcp:${clean(server.name, 80)}`, ...(server.url && /^https?:\/\//.test(server.url) ? { endpoints: [clean(server.url)] } : {}), properties: [{ name: "0:source", value: rel }, { name: "0:found-by", value: "MCP configuration" }, ...(command ? [{ name: "0:launch", value: clean(command) }] : []), ...(server.url ? [{ name: "0:url", value: clean(server.url) }] : []), ...(unpinned ? [{ name: "0:risk", value: "launched without a pinned version" }] : [])] });
      }
      continue;
    }
    if (!CODE.has(extension)) continue;
    const source = text(path, MAX_TEXT_BYTES, file.size);
    if (source === undefined) continue;
    for (const hub of HUB) {
      for (const match of source.matchAll(hub.pattern)) {
        const id = clean(match[1]!);
        const line = lineOf(source, match.index ?? 0);
        const revision = /\brevision\s*[=:]\s*["']([\w./-]{1,100})["']/.exec(callText(source, match.index ?? 0))?.[1];
        if (hub.type === "data") { addDataset(id, rel, hub.how, line, revision); continue; }
        const local = !HUB_ID.test(id) || existsInside(root, id);
        add({ type: "machine-learning-model", "bom-ref": `hub-model:${id}`, name: id, ...(revision && COMMIT.test(revision) ? { version: revision } : {}), evidence: { occurrences: [{ location: rel, line }] },
          ...(local ? {} : { externalReferences: [{ type: "distribution" as const, url: hubUrl("models", id, revision), comment: "Hugging Face Hub repository named in the code; not contacted or checked" }] }),
          properties: [{ name: "0:source", value: `${rel}:${line}` }, { name: "0:found-by", value: hub.how }, ...(local ? [{ name: "0:reference", value: "a local path or not a Hub id" }] : revisionProps(revision, rel, line))] });
      }
    }
    for (const match of source.matchAll(HOSTED)) {
      const id = clean(match[1]!);
      const line = lineOf(source, match.index ?? 0);
      add({ type: "machine-learning-model", "bom-ref": `hosted-model:${id}`, name: id, evidence: { occurrences: [{ location: rel, line }] }, properties: [{ name: "0:source", value: `${rel}:${line}` }, { name: "0:found-by", value: "hosted model id" }, { name: "0:provider", value: provider(id) }] });
    }
  }
  const byRef = (a: { "bom-ref": string }, b: { "bom-ref": string }) => (a["bom-ref"] < b["bom-ref"] ? -1 : a["bom-ref"] > b["bom-ref"] ? 1 : 0);
  const sorted = [...components.values()].sort(byRef);
  for (const component of sorted) if (component.evidence) {
    const unique = new Map<string, { location: string; line?: number }>();
    for (const item of component.evidence.occurrences) unique.set(`${item.location}\0${item.line ?? ""}`, item);
    component.evidence.occurrences = [...unique.values()].sort((a, b) => (a.location < b.location ? -1 : a.location > b.location ? 1 : (a.line ?? 0) - (b.line ?? 0))).slice(0, MAX_OCCURRENCES);
  }
  return { components: sorted, services: [...services.values()].sort(byRef), notes: [...new Set(notes)].sort() };
}

/** Properties for a Hub reference: the pinned commit, or why the reference is not pinned. */
function revisionProps(revision: string | undefined, source: string, line: number | undefined): Property[] {
  const where = line ? `${source}:${line}` : source;
  if (revision && COMMIT.test(revision)) return [{ name: "0:revision", value: `${revision} (${where})` }];
  return [{ name: "0:unpinned-revision", value: revision ? `${clean(revision, 100)} is a branch or tag name, not a commit hash (${where})` : `no revision in the reference (${where})` }];
}

/** True when the name, taken as a path under the folder, is something that exists there (so it is a local path, not a Hub id). */
function existsInside(root: string, id: string): boolean {
  const target = resolve(root, id);
  if (target !== root && !target.startsWith(root + sep)) return false;
  try { lstatSync(target); return true; } catch { return false; }
}
