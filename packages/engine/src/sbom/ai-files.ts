/**
 * Safe, bounded file access and header readers for the AI inventory. Everything here treats file contents as untrusted:
 * a file is opened only if it is a regular file (never through a symlink, never a device or FIFO), reads are capped,
 * and model files are never loaded, only their first bytes are parsed as data. Nothing is executed.
 */
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import { dirname, sep } from "node:path";
import { createHash } from "node:crypto";
import { SPDX_LICENSE_IDS } from "./spdx-ids.js";

export type Props = Array<[name: string, value: string]>;
export const clean = (value: string, max = 200): string => value.replace(/[^\x20-\x7e]/g, "").slice(0, max);

/** Largest model file that is hashed. A bigger file gets a `0:hash-skipped` property instead. */
export const MAX_MODEL_HASH_BYTES = 2 * 1024 ** 3;
/** Largest dataset file that is hashed. */
export const MAX_DATA_HASH_BYTES = 256 * 1024 ** 2;
/** Most bytes hashed in one run, over all files. */
export const MAX_TOTAL_HASH_BYTES = 4 * 1024 ** 3;
/** Most bytes read as text in one run, over all files. */
export const MAX_TOTAL_TEXT_BYTES = 64 * 1024 ** 2;

const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/** True when the file's real parent folder is still under the real root (a folder swapped for a symlink since the walk is refused). */
export function insideRoot(path: string, root: string): boolean {
  try { const parent = realpathSync(dirname(path)); return parent === root || parent.startsWith(root.endsWith(sep) ? root : root + sep); } catch { return false; }
}

/** Open a regular file for reading: refuse symlinks, devices, FIFOs and anything that changed between the check and the open. */
export function openRegular(path: string, root?: string): { fd: number; size: number } | undefined {
  if (root !== undefined && !insideRoot(path, root)) return undefined;
  let before; try { before = lstatSync(path); } catch { return undefined; }
  if (!before.isFile()) return undefined;
  let fd: number; try { fd = openSync(path, OPEN_FLAGS); } catch { return undefined; }
  try {
    const after = fstatSync(fd);
    if (after.isFile() && after.ino === before.ino && after.dev === before.dev) return { fd, size: after.size };
  } catch { /* fall through */ }
  try { closeSync(fd); } catch { /* ignore */ }
  return undefined;
}

export function readAt(fd: number, position: number, length: number): Buffer {
  const buffer = Buffer.alloc(Math.max(0, length));
  let done = 0;
  while (done < buffer.length) {
    const n = readSync(fd, buffer, done, buffer.length - done, position + done);
    if (n <= 0) break;
    done += n;
  }
  return done === buffer.length ? buffer : buffer.subarray(0, done);
}

/** The text of a regular file no larger than `max` bytes, or nothing. */
export function readTextSafe(path: string, max: number, root?: string): string | undefined {
  const file = openRegular(path, root);
  if (!file) return undefined;
  try { return file.size > max ? undefined : readAt(file.fd, 0, file.size).toString("utf8"); } catch { return undefined; } finally { try { closeSync(file.fd); } catch { /* ignore */ } }
}

/** SHA-256 of the file's bytes, read in chunks so memory stays small. Undefined if the file changed while it was read. */
export function sha256Of(fd: number, size: number): string | undefined {
  const hash = createHash("sha256");
  const chunk = Buffer.alloc(1024 * 1024);
  let position = 0;
  try {
    while (position < size) {
      const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - position), position);
      if (n <= 0) break;
      hash.update(chunk.subarray(0, n));
      position += n;
    }
  } catch { return undefined; }
  return position === size ? hash.digest("hex") : undefined;
}

export interface ModelFacts { props: Props; family?: string; architecture?: string }

/** The safetensors header is a length, then JSON naming each tensor's type and shape. Only that JSON is read. */
function safetensorsFacts(fd: number, size: number): ModelFacts {
  const bad: ModelFacts = { props: [["0:header", "not a readable safetensors header"]] };
  if (size < 10) return bad;
  const length = Number(readAt(fd, 0, 8).readBigUInt64LE(0));
  if (!Number.isSafeInteger(length) || length < 2 || length > 4 * 1024 * 1024 || length + 8 > size) return bad;
  let header: unknown;
  try { header = JSON.parse(readAt(fd, 8, length).toString("utf8")); } catch { return bad; }
  if (typeof header !== "object" || header === null || Array.isArray(header)) return bad;
  let parameters = 0; let tensors = 0; let exact = true;
  const dtypes = new Set<string>();
  let format: string | undefined;
  for (const [key, value] of Object.entries(header as Record<string, unknown>)) {
    if (key === "__metadata__") { const f = (value as Record<string, unknown> | null)?.["format"]; if (typeof f === "string") format = clean(f, 40); continue; }
    if (typeof value !== "object" || value === null) continue;
    const { dtype, shape } = value as { dtype?: unknown; shape?: unknown };
    if (typeof dtype !== "string" || !Array.isArray(shape) || shape.length > 16) continue;
    tensors += 1;
    dtypes.add(clean(dtype, 16));
    let count = 1;
    for (const dim of shape) { if (typeof dim !== "number" || !Number.isInteger(dim) || dim < 0) { exact = false; count = 0; break; } count *= dim; }
    parameters += count;
    if (!Number.isSafeInteger(parameters)) { exact = false; break; }
    if (tensors >= 200000) { exact = false; break; }
  }
  const props: Props = [["0:tensor-count", `${tensors}${exact ? "" : " or more"}`]];
  if (exact) props.push(["0:parameter-count", String(parameters)]);
  if (dtypes.size) props.push(["0:tensor-dtypes", [...dtypes].sort().join(",")]);
  if (format) props.push(["0:header-format", format]);
  return { props };
}

class Reader {
  pos = 0;
  constructor(readonly buf: Buffer) {}
  need(n: number): void { if (n < 0 || this.pos + n > this.buf.length) throw new RangeError("end of header"); }
  u32(): number { this.need(4); const v = this.buf.readUInt32LE(this.pos); this.pos += 4; return v; }
  u64(): bigint { this.need(8); const v = this.buf.readBigUInt64LE(this.pos); this.pos += 8; return v; }
  skip(n: bigint | number): void { const count = Number(n); this.need(count); this.pos += count; }
  str(max: number): string { const length = Number(this.u64()); if (length > max * 8) { this.skip(length); return ""; } this.need(length); const s = this.buf.toString("utf8", this.pos, this.pos + length); this.pos += length; return s; }
}
const GGUF_FIXED = [1, 1, 2, 2, 4, 4, 4, 1, 0, 0, 8, 8, 8];

/** The GGUF header is key/value metadata before the tensors. Only the first megabyte is read, and parsing stops where it ends. */
function ggufFacts(fd: number, size: number): ModelFacts {
  const buf = readAt(fd, 0, Math.min(size, 1024 * 1024));
  if (buf.length < 24 || buf.toString("latin1", 0, 4) !== "GGUF") return { props: [["0:header", "not a readable GGUF header"]] };
  const r = new Reader(buf); r.skip(4);
  const version = r.u32();
  if (version < 2 || version > 3) return { props: [["0:gguf-version", String(version)], ["0:header", "GGUF version not read"]] };
  const tensors = r.u64(); const entries = Number(r.u64());
  const props: Props = [["0:gguf-version", String(version)], ["0:tensor-count", tensors.toString()]];
  const facts = new Map<string, string>();
  try {
    for (let index = 0; index < Math.min(entries, 2000); index += 1) {
      const key = r.str(256); const type = r.u32();
      let value: string | undefined;
      if (type === 8) value = r.str(200);
      else if (type === 9) {
        const element = r.u32(); const count = r.u64();
        if (element === 8) for (let i = 0n; i < count; i += 1n) r.str(0); else if (element < GGUF_FIXED.length && GGUF_FIXED[element]) r.skip(count * BigInt(GGUF_FIXED[element]!)); else throw new RangeError("unknown type");
      } else if (type < 13 && GGUF_FIXED[type]) {
        const width = GGUF_FIXED[type]!; r.need(width);
        if (type === 4) value = String(buf.readUInt32LE(r.pos)); else if (type === 10) value = buf.readBigUInt64LE(r.pos).toString();
        r.pos += width;
      } else throw new RangeError("unknown type");
      if (value !== undefined && clean(key, 80)) facts.set(clean(key, 80), clean(value, 120));
    }
  } catch { props.push(["0:header-note", "GGUF metadata read only as far as the first megabyte"]); }
  const arch = facts.get("general.architecture");
  const wanted: Array<[string, string | undefined]> = [["0:gguf-name", facts.get("general.name")], ["0:gguf-size-label", facts.get("general.size_label")], ["0:gguf-file-type", facts.get("general.file_type")], ["0:context-length", arch ? facts.get(`${arch}.context_length`) : undefined], ["0:block-count", arch ? facts.get(`${arch}.block_count`) : undefined]];
  for (const [name, value] of wanted) if (value) props.push([name, value]);
  return { props, ...(arch ? { family: arch } : {}) };
}

function varint(buf: Buffer, at: number): { value: number; next: number } | undefined {
  let value = 0; let scale = 1;
  for (let index = 0; index < 8; index += 1) {
    const byte = buf[at + index];
    if (byte === undefined) return undefined;
    value += (byte & 0x7f) * scale; scale *= 128;
    if (!(byte & 0x80)) return Number.isSafeInteger(value) ? { value, next: at + index + 1 } : undefined;
  }
  return undefined;
}

/** An ONNX file is a protobuf message. The top-level fields are walked by length, so the graph and its weights are skipped. */
function onnxFacts(fd: number, size: number): ModelFacts {
  const props: Props = [];
  let position = 0; let steps = 0; let opset: number | undefined;
  while (position < size && steps < 64) {
    steps += 1;
    const head = readAt(fd, position, Math.min(24, size - position));
    const tag = varint(head, 0);
    if (!tag) break;
    const field = Math.floor(tag.value / 8); const wire = tag.value % 8;
    if (field < 1 || field > 30) return { props: props.length ? props : [["0:header", "not a readable ONNX header"]] };
    let next = position + tag.next;
    if (wire === 0) {
      const v = varint(head, tag.next); if (!v) break;
      if (field === 1) props.push(["0:onnx-ir-version", String(v.value)]); else if (field === 5) props.push(["0:model-version", String(v.value)]);
      next = position + v.next;
    } else if (wire === 2) {
      const l = varint(head, tag.next); if (!l) break;
      const start = position + l.next; next = start + l.value;
      if (next > size) return { props: props.length ? props : [["0:header", "not a readable ONNX header"]] };
      if (l.value <= 4096 && (field === 2 || field === 3 || field === 4 || field === 8)) {
        const body = readAt(fd, start, l.value);
        if (field === 8) {
          let at = 0; let domain = ""; let version: number | undefined;
          while (at < body.length) {
            const t = varint(body, at); if (!t) break; at = t.next;
            if (t.value === 10) { const n = varint(body, at); if (!n) break; domain = body.toString("utf8", n.next, n.next + n.value); at = n.next + n.value; }
            else if (t.value === 16) { const v = varint(body, at); if (!v) break; version = v.value; at = v.next; } else break;
          }
          if ((domain === "" || domain === "ai.onnx") && version !== undefined) opset = version;
        } else props.push([field === 2 ? "0:onnx-producer" : field === 3 ? "0:onnx-producer-version" : "0:onnx-domain", clean(body.toString("utf8"), 100)]);
      }
    } else if (wire === 1) next += 8; else if (wire === 5) next += 4; else break;
    position = next;
  }
  if (opset !== undefined) props.push(["0:onnx-opset", String(opset)]);
  return { props: props.length ? props : [["0:header", "not a readable ONNX header"]] };
}

/** What the first bytes of a model file say about it, for the formats whose header is plain data. Other formats are not opened. */
export function modelFacts(format: string, fd: number, size: number): ModelFacts | undefined {
  try {
    if (format === "safetensors") return safetensorsFacts(fd, size);
    if (format === "gguf") return ggufFacts(fd, size);
    if (format === "onnx") return onnxFacts(fd, size);
  } catch { return { props: [["0:header", `not a readable ${format} header`]] }; }
  return undefined;
}

const SPDX_LOWER = new Map([...SPDX_LICENSE_IDS].map(id => [id.toLowerCase(), id] as const));
/** An SPDX id when the text is one (any letter case); nothing otherwise. */
export const spdxId = (text: string): string | undefined => SPDX_LOWER.get(text.trim().toLowerCase());

/** The SPDX id of a licence text when it is plainly one of a few well-known licences. Anything else is not guessed. */
export function licenseFileId(text: string): string | undefined {
  const t = text.slice(0, 40000).replace(/\s+/g, " ").toLowerCase();
  if (t.includes("apache license") && t.includes("version 2.0")) return "Apache-2.0";
  if (t.includes("gnu affero general public license") && t.includes("version 3")) return "AGPL-3.0-only";
  if (t.includes("gnu general public license") && t.includes("version 3")) return "GPL-3.0-only";
  if (t.includes("mozilla public license") && t.includes("version 2.0")) return "MPL-2.0";
  if (t.includes("attribution-noncommercial 4.0 international")) return "CC-BY-NC-4.0";
  if (t.includes("attribution-sharealike 4.0 international")) return "CC-BY-SA-4.0";
  if (t.includes("attribution 4.0 international")) return "CC-BY-4.0";
  if (t.includes("permission is hereby granted, free of charge") && t.includes("the software is provided \"as is\"")) return "MIT";
  if (t.includes("redistribution and use in source and binary forms")) return t.includes("neither the name") ? "BSD-3-Clause" : "BSD-2-Clause";
  if (t.includes("this is free and unencumbered software released into the public domain")) return "Unlicense";
  return undefined;
}

export interface CardFacts { license?: string; task?: string; datasets: string[] }
/** The front matter of a model card (README.md): `license`, `pipeline_tag` and a `datasets` list. Only plain scalars and lists are read. */
export function cardFacts(text: string): CardFacts {
  const facts: CardFacts = { datasets: [] };
  if (!text.startsWith("---")) return facts;
  const end = text.indexOf("\n---", 3);
  if (end < 0) return facts;
  const lines = text.slice(3, end).split(/\r?\n/);
  const scalar = (raw: string): string => clean(raw.trim().replace(/^["']|["']$/g, ""), 100);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    const match = /^(license|pipeline_tag|datasets):\s*(.*)$/.exec(line);
    if (!match) continue;
    const value = match[2]!.trim();
    if (match[1] === "datasets") {
      if (value.startsWith("[")) facts.datasets.push(...value.replace(/^\[|\]$/g, "").split(",").map(scalar).filter(Boolean));
      else for (let next = index + 1; next < lines.length; next += 1) { const item = /^\s*-\s+(.+)$/.exec(lines[next]!); if (!item) break; const id = scalar(item[1]!); if (id) facts.datasets.push(id); }
    } else if (value && !value.startsWith("[") && !value.startsWith("|") && !value.startsWith(">")) {
      const text2 = scalar(value);
      if (text2) { if (match[1] === "license") facts.license ??= text2; else facts.task ??= text2; }
    }
  }
  facts.datasets = [...new Set(facts.datasets.filter(id => /^[\w.-]+(\/[\w.-]+)?$/.test(id)))].slice(0, 20);
  return facts;
}

/** `architectures` and `model_type` from a Hugging Face config.json next to a model. */
export function configFacts(text: string): { architecture?: string; family?: string } {
  let json: unknown; try { json = JSON.parse(text); } catch { return {}; }
  if (typeof json !== "object" || json === null || Array.isArray(json)) return {};
  const { architectures, model_type: type } = json as { architectures?: unknown; model_type?: unknown };
  const first = Array.isArray(architectures) ? architectures[0] : undefined;
  return { ...(typeof first === "string" && clean(first, 80) ? { architecture: clean(first, 80) } : {}), ...(typeof type === "string" && clean(type, 60) ? { family: clean(type, 60) } : {}) };
}
