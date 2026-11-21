/**
 * Scans model files for unsafe deserialization without Python and without running anything. It recognises pickle
 * streams (.pkl, .joblib, old .pt), zip containers with pickle members (PyTorch >= 1.6), numpy .npy/.npz with object
 * arrays, and gzip/zlib wrapped pickles, walks the opcodes and classifies every imported callable. Content decides,
 * not the extension: a pickle named `.safetensors` is scanned as a pickle. "None found" always means only that no
 * dangerous import was found in what was read; it is never a statement that a file is safe.
 */
import { closeSync, lstatSync, openSync, readdirSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import { inflateRawSync, inflateSync, gunzipSync } from "node:zlib";
import { classifyImport } from "./classify.js";
import { scanPickleStream, type PickleLimits } from "./pickle.js";
import { bufferBacking, fileBacking, readExact, Reader, ScanError, sliceBacking, type Backing } from "./reader.js";
import { entryDataStart, listZip, unsafeMemberName, type ZipLimits } from "./zip.js";

export type ModelVerdict = "dangerous" | "unrecognised" | "none-found" | "not-pickle" | "not-scanned";
export interface ImportFinding {
  risk: "dangerous" | "unrecognised";
  module: string;
  name: string;
  qualified: string;
  reason: string;
  opcodes: string[];
  called: boolean;
  /** The archive member it was found in, when the file is a zip. */
  member?: string;
}
export interface ModelFileResult {
  path: string;
  size: number;
  format: string;
  verdict: ModelVerdict;
  summary: string;
  findings: ImportFinding[];
  /** References on the expected-ML list, counted and not listed. */
  expectedImports: number;
  warnings: string[];
  /** False when part of the file could not be read (truncated, over a limit, unsupported compression). */
  complete: boolean;
  protocol?: number;
}
export interface ModelScanOptions {
  maxInflatedBytes?: number;
  maxTotalInflatedBytes?: number;
  maxMembers?: number;
  pickle?: Partial<PickleLimits>;
  zip?: Partial<ZipLimits>;
}
export interface ModelScanReport {
  root: string;
  files: ModelFileResult[];
  skippedSymlinks: number;
  /** True when the folder walk stopped at its entry limit. */
  truncated: boolean;
}

const PICKLE_EXTENSIONS = new Set([".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".dill", ".sav"]);
const MODEL_EXTENSIONS = new Set([...PICKLE_EXTENSIONS, ".bin", ".npy", ".npz", ".safetensors", ".gguf", ".onnx", ".tflite", ".h5", ".hdf5", ".keras"]);
export const MODEL_FILE_EXTENSIONS: readonly string[] = [...MODEL_EXTENSIONS].sort();
const CODE_CAPABLE_EXTENSIONS = new Set([".h5", ".hdf5", ".keras"]);
const MAX_INFLATED = 128 * 1024 * 1024;
const MAX_TOTAL_INFLATED = 256 * 1024 * 1024;
const MAX_MEMBERS = 64;
const MAX_WALK_ENTRIES = 50_000;
const MAX_WALK_DEPTH = 16;
const SKIP_DIRS = new Set([".git", "node_modules"]);

interface Acc {
  options: Required<Pick<ModelScanOptions, "maxInflatedBytes" | "maxTotalInflatedBytes" | "maxMembers">> & ModelScanOptions;
  findings: Map<string, ImportFinding>;
  expected: number;
  warnings: string[];
  unscanned: string[];
  complete: boolean;
  protocol: number | undefined;
  pickles: number;
  arrays: number;
  inflated: number;
  nonPickle: string | undefined;
  archiveWithoutPickles: boolean;
}

function absorb(acc: Acc, scan: ReturnType<typeof scanPickleStream>, member?: string): boolean {
  const where = member ? `${member}: ` : "";
  if (scan.stop && scan.stop.offset === 0 && scan.stop.kind !== "limit") return false; // not a pickle at all
  if (scan.protocol !== undefined) acc.protocol = Math.max(acc.protocol ?? 0, scan.protocol);
  for (const item of scan.imports) {
    const computed = item.module === "<computed>";
    const verdict = computed ? { risk: "unrecognised" as const, reason: "STACK_GLOBAL whose module or name is not a constant string, so it could not be resolved" } : classifyImport(item.module, item.name);
    if (verdict.risk === "expected") { acc.expected++; continue; }
    const qualified = computed ? "<unresolved STACK_GLOBAL>" : `${item.module}.${item.name}`;
    const key = `${member ?? ""}\u0000${qualified}`;
    const existing = acc.findings.get(key);
    if (existing) { existing.called ||= item.called; continue; }
    acc.findings.set(key, { risk: verdict.risk, module: item.module, name: item.name, qualified, reason: verdict.reason, opcodes: item.opcodes, called: item.called, ...(member ? { member } : {}) });
  }
  acc.pickles++;
  if (scan.stop) { acc.complete = false; acc.warnings.push(`${where}scan stopped at byte ${scan.stop.offset}: ${scan.stop.message}`); }
  if (scan.trailing) acc.warnings.push(`${where}data after the first pickle was not parsed: ${scan.trailing}`);
  return true;
}

function scanPickleBacking(backing: Backing, acc: Acc, member?: string): boolean {
  return absorb(acc, scanPickleStream(new Reader(backing), acc.options.pickle ?? {}), member);
}

function npyHeader(backing: Backing): { dataStart: number; objects: boolean } | undefined {
  if (backing.size < 10) return undefined;
  const head = readExact(backing, 0, 10);
  if (head[0] !== 0x93 || head.toString("latin1", 1, 6) !== "NUMPY") return undefined;
  const major = head[6]!;
  const lengthWidth = major === 1 ? 2 : 4;
  const prefix = 8 + lengthWidth;
  if (backing.size < prefix) return undefined;
  const lengthBytes = readExact(backing, 8, lengthWidth);
  const headerLength = lengthWidth === 2 ? lengthBytes.readUInt16LE(0) : lengthBytes.readUInt32LE(0);
  if (headerLength > 1024 * 1024 || prefix + headerLength > backing.size) throw new ScanError("malformed", "numpy header is larger than any real one", 8);
  const text = readExact(backing, prefix, headerLength).toString("latin1");
  const descr = /'descr'\s*:\s*([\s\S]*?),\s*'fortran_order'/.exec(text)?.[1] ?? text;
  return { dataStart: prefix + headerLength, objects: /['"][|<>=]?O\d*['"]/.test(descr) };
}

function scanNpy(backing: Backing, acc: Acc, member?: string): void {
  const header = npyHeader(backing);
  if (!header) { acc.unscanned.push(`${member ?? "file"} does not have a numpy header`); return; }
  if (!header.objects) { acc.arrays++; return; }
  if (!scanPickleBacking(sliceBacking(backing, header.dataStart, backing.size - header.dataStart), acc, member)) acc.unscanned.push(`${member ?? "file"}: object array whose data is not a pickle stream`);
}

function inflateBounded(acc: Acc, data: Buffer, kind: "raw" | "zlib" | "gzip", label: string): Buffer | undefined {
  const room = Math.min(acc.options.maxInflatedBytes, acc.options.maxTotalInflatedBytes - acc.inflated);
  if (room <= 0) { acc.unscanned.push(`${label}: decompression budget used up`); return undefined; }
  try {
    const out = kind === "raw" ? inflateRawSync(data, { maxOutputLength: room }) : kind === "zlib" ? inflateSync(data, { maxOutputLength: room }) : gunzipSync(data, { maxOutputLength: room });
    acc.inflated += out.length;
    return out;
  } catch (error) {
    const code = (error as { code?: string }).code;
    acc.unscanned.push(code === "ERR_BUFFER_TOO_LARGE" ? `${label}: inflates to more than ${Math.floor(room / 1048576)} MB (limit; possible zip bomb), not scanned` : `${label}: could not be decompressed (${(error as Error).message})`);
    return undefined;
  }
}

function scanZip(backing: Backing, ext: string, acc: Acc): string {
  const listing = listZip(backing, acc.options.zip ?? {});
  acc.warnings.push(...listing.warnings);
  let scannedMembers = 0;
  let sawPickleMember = false;
  for (const entry of listing.entries) {
    if (unsafeMemberName(entry.name)) acc.warnings.push(`archive member name '${entry.name.replace(/[^\x20-\x7e]/g, "?").slice(0, 120)}' would escape the folder if extracted (not extracted here)`);
    const isPickle = /\.(?:pkl|pickle)$/i.test(entry.name);
    const isNpy = /\.npy$/i.test(entry.name);
    if (!isPickle && !isNpy) continue;
    if (scannedMembers >= acc.options.maxMembers) { acc.unscanned.push(`archive has more than ${acc.options.maxMembers} pickle or numpy members; the rest were not read`); break; }
    scannedMembers++;
    if (isPickle) sawPickleMember = true;
    const label = entry.name.replace(/[^\x20-\x7e]/g, "?").slice(0, 120);
    if (entry.encrypted) { acc.unscanned.push(`${label}: encrypted, not scanned`); continue; }
    try {
      const start = entryDataStart(backing, entry);
      let member: Backing;
      if (entry.method === 0) member = sliceBacking(backing, start, entry.compressedSize);
      else if (entry.method === 8) {
        if (entry.compressedSize > acc.options.maxInflatedBytes) { acc.unscanned.push(`${label}: compressed data over the ${Math.floor(acc.options.maxInflatedBytes / 1048576)} MB limit, not scanned`); continue; }
        if (entry.uncompressedSize > acc.options.maxInflatedBytes) { acc.unscanned.push(`${label}: declares ${Math.floor(entry.uncompressedSize / 1048576)} MB uncompressed (limit ${Math.floor(acc.options.maxInflatedBytes / 1048576)} MB), not scanned`); continue; }
        const inflated = inflateBounded(acc, readExact(backing, start, entry.compressedSize), "raw", label);
        if (!inflated) continue;
        member = bufferBacking(inflated);
      } else { acc.unscanned.push(`${label}: compression method ${entry.method} is not supported, not scanned`); continue; }
      if (isNpy) scanNpy(member, acc, label);
      else if (!scanPickleBacking(member, acc, label)) acc.unscanned.push(`${label}: does not parse as a pickle stream`);
    } catch (error) {
      if (!(error instanceof ScanError)) throw error;
      acc.unscanned.push(`${label}: ${error.message}`);
    }
  }
  if (!acc.pickles && !acc.unscanned.length) {
    if (acc.arrays) acc.nonPickle = "numeric arrays only; no object arrays, so nothing is unpickled";
    else acc.archiveWithoutPickles = true;
  }
  return ext === ".npz" ? "npz" : sawPickleMember ? "pytorch-zip" : "zip";
}

function safetensorsHeader(backing: Backing, head: Buffer): boolean {
  if (head.length < 9 || backing.size < 9) return false;
  const length = head.readBigUInt64LE(0);
  return length > 0n && length <= 104_857_600n && length <= BigInt(backing.size - 8) && head[8] === 0x7b;
}

function scanContent(backing: Backing, ext: string, acc: Acc, depth: number): string {
  if (backing.size === 0) { acc.unscanned.push("the file is empty"); return "empty"; }
  const head = readExact(backing, 0, Math.min(backing.size, 16));
  const isZip = head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && ((head[2] === 3 && head[3] === 4) || (head[2] === 5 && head[3] === 6));
  if (isZip) return scanZip(backing, ext, acc);
  if (head[0] === 0x93 && head.toString("latin1", 1, 6) === "NUMPY") { scanNpy(backing, acc); if (acc.arrays && !acc.pickles && !acc.unscanned.length) acc.nonPickle = "numeric array; no object dtype, so nothing is unpickled"; return "npy"; }
  const gzip = head[0] === 0x1f && head[1] === 0x8b;
  const zlibHeader = head.length >= 2 && head[0] === 0x78 && (head[0]! * 256 + head[1]!) % 31 === 0;
  if ((gzip || zlibHeader) && depth < 2 && (PICKLE_EXTENSIONS.has(ext) || ext === ".bin")) {
    if (backing.size > acc.options.maxInflatedBytes) { acc.unscanned.push("compressed file over the size limit for decompression, not scanned"); return "compressed"; }
    const inflated = inflateBounded(acc, readExact(backing, 0, backing.size), gzip ? "gzip" : "zlib", "compressed content");
    if (!inflated) return "compressed";
    const inner = scanContent(bufferBacking(inflated), ext, acc, depth + 1);
    return `${gzip ? "gzip" : "zlib"}-compressed ${inner}`;
  }
  if (head[0] === 0x80 && head[1] !== undefined && head[1] >= 1 && head[1] <= 5) {
    if (!scanPickleBacking(backing, acc)) acc.unscanned.push("does not parse as a pickle stream");
    return "pickle";
  }
  if (safetensorsHeader(backing, head)) { acc.nonPickle = "no code execution possible in this format (a JSON header and raw tensor bytes)"; return "safetensors"; }
  if (head.toString("latin1", 0, 4) === "GGUF") { acc.nonPickle = "not a pickle format; stores tensors and metadata only (an embedded chat template is text for a template engine and was not examined)"; return "gguf"; }
  if (head.length >= 8 && head.toString("latin1", 4, 8) === "TFL3") { acc.nonPickle = "no code execution possible in this format (a FlatBuffers graph and tensors)"; return "tflite"; }
  if (ext === ".onnx") { acc.nonPickle = "not a pickle format: an ONNX file is a protobuf graph of operators and weights, with no embedded Python code"; return "onnx"; }
  if (PICKLE_EXTENSIONS.has(ext)) {
    if (!scanPickleBacking(backing, acc)) acc.unscanned.push("does not parse as a pickle stream (not a recognised model container either)");
    return "pickle";
  }
  acc.unscanned.push(`content is not a recognised pickle, zip or model format (extension ${ext || "none"})`);
  return "unknown";
}

function describe(findings: ImportFinding[], risk: ImportFinding["risk"]): string {
  const names = [...new Set(findings.filter(item => item.risk === risk).map(item => item.qualified))];
  return `${names.slice(0, 6).join(", ")}${names.length > 6 ? `, and ${names.length - 6} more` : ""}`;
}

export function scanModelFile(path: string, options: ModelScanOptions = {}): ModelFileResult {
  const ext = extname(path).toLowerCase();
  const base = { path, findings: [] as ImportFinding[], expectedImports: 0, warnings: [] as string[] };
  let size = 0;
  let fd: number | undefined;
  try {
    const info = lstatSync(path);
    size = info.size;
    if (!info.isFile()) return { ...base, size, format: "unknown", verdict: "not-scanned", summary: "not a regular file", complete: false };
    if (CODE_CAPABLE_EXTENSIONS.has(ext)) return { ...base, size, format: ext === ".keras" ? "keras" : "hdf5", verdict: "not-scanned", summary: "not scanned: Keras models can embed Python code (Lambda layers), and this scanner reads pickle containers only", complete: false };
    fd = openSync(path, "r");
    const acc: Acc = {
      options: { maxInflatedBytes: MAX_INFLATED, maxTotalInflatedBytes: MAX_TOTAL_INFLATED, maxMembers: MAX_MEMBERS, ...options },
      findings: new Map(), expected: 0, warnings: [], unscanned: [], complete: true, protocol: undefined, pickles: 0, arrays: 0, inflated: 0, nonPickle: undefined, archiveWithoutPickles: false,
    };
    let format: string;
    try { format = scanContent(fileBacking(fd, size), ext, acc, 0); } catch (error) {
      if (!(error instanceof ScanError)) throw error;
      acc.unscanned.push(error.message);
      format = ext === ".npz" || ext === ".pt" || ext === ".pth" ? "zip" : "unknown";
    }
    const findings = [...acc.findings.values()].sort((a, b) => (a.risk === b.risk ? (a.qualified < b.qualified ? -1 : 1) : a.risk === "dangerous" ? -1 : 1));
    const complete = acc.complete && !acc.unscanned.length;
    const gaps = [...(acc.complete ? [] : acc.warnings.filter(text => /scan stopped|not parsed/.test(text)).slice(0, 2)), ...acc.unscanned.slice(0, 3)];
    const incomplete = complete ? "" : ` (scan incomplete: ${gaps.join("; ")})`;
    const warnings = [...acc.warnings, ...(acc.unscanned.length && acc.pickles ? acc.unscanned : [])];
    const hasDangerous = findings.some(item => item.risk === "dangerous");
    const hasUnknown = findings.some(item => item.risk === "unrecognised");
    let verdict: ModelVerdict;
    let summary: string;
    if (hasDangerous) { verdict = "dangerous"; summary = `dangerous imports: ${describe(findings, "dangerous")}${hasUnknown ? `; also unrecognised: ${describe(findings, "unrecognised")}` : ""}; loading this file can run code`; }
    else if (hasUnknown) { verdict = "unrecognised"; summary = `unrecognised imports (no dangerous ones found): ${describe(findings, "unrecognised")}${incomplete}`; }
    else if (acc.pickles > 0 || acc.archiveWithoutPickles) { verdict = "none-found"; summary = acc.archiveWithoutPickles ? "no dangerous imports found; the archive has no pickle members" : `no dangerous imports found${incomplete}`; }
    else if (acc.nonPickle && !acc.unscanned.length) { verdict = "not-pickle"; summary = acc.nonPickle; }
    else { verdict = "not-scanned"; summary = `not scanned: ${acc.unscanned.slice(0, 3).join("; ") || "no pickle data found"}`; }
    const mislabelled = ((ext === ".safetensors" || ext === ".gguf" || ext === ".onnx" || ext === ".tflite") && (format === "pickle" || format === "pytorch-zip" || format === "zip" || format === "npz" || format === "npy"));
    if (mislabelled) warnings.push(`the extension says ${ext.slice(1)} but the content is ${format}, which can run code when loaded`);
    return { ...base, size, format, verdict, summary, findings, expectedImports: acc.expected, warnings, complete, ...(acc.protocol !== undefined ? { protocol: acc.protocol } : {}) };
  } catch (error) {
    return { ...base, size, format: "unknown", verdict: "not-scanned", summary: `not scanned: could not read the file (${(error as NodeJS.ErrnoException).code ?? "error"})`, complete: false };
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing to do */ }
  }
}

/** Scan one file, or every model file under a folder (skipping `.git`, `node_modules` and symbolic links). */
export function scanModelPath(path: string, options: ModelScanOptions = {}): ModelScanReport {
  const info = lstatSync(path);
  if (!info.isDirectory()) return { root: path, files: [scanModelFile(path, options)], skippedSymlinks: 0, truncated: false };
  const files: string[] = [];
  let visited = 0;
  let skippedSymlinks = 0;
  let truncated = false;
  const walk = (dir: string, depth: number): void => {
    let names: string[];
    try { names = readdirSync(dir).sort(); } catch { return; }
    for (const name of names) {
      if (++visited > MAX_WALK_ENTRIES) { truncated = true; return; }
      const full = join(dir, name);
      let entry;
      try { entry = lstatSync(full); } catch { continue; }
      if (entry.isSymbolicLink()) { skippedSymlinks++; continue; }
      if (entry.isDirectory()) { if (depth < MAX_WALK_DEPTH && !SKIP_DIRS.has(name)) walk(full, depth + 1); if (truncated) return; continue; }
      if (entry.isFile() && MODEL_EXTENSIONS.has(extname(name).toLowerCase())) files.push(full);
    }
  };
  walk(path, 0);
  return { root: path, files: files.map(file => ({ ...scanModelFile(file, options), path: relative(path, file).split(sep).join("/") })), skippedSymlinks, truncated };
}
