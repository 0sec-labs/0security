/**
 * A zip central-directory reader with limits. It lists entries and locates their data; it never extracts to disk, so a
 * name such as `../../x` is only reported, never followed. Sizes in the directory are claims: callers still bound what
 * they inflate.
 */
import { readExact, ScanError, type Backing } from "./reader.js";

export interface ZipEntry {
  name: string;
  method: number;
  encrypted: boolean;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
}
export interface ZipListing { entries: ZipEntry[]; warnings: string[] }
export interface ZipLimits { maxEntries: number; maxDirectoryBytes: number; maxNameBytes: number }
export const DEFAULT_ZIP_LIMITS: ZipLimits = { maxEntries: 10_000, maxDirectoryBytes: 16 * 1024 * 1024, maxNameBytes: 1024 };

const safe = (value: bigint | number): number => {
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new ScanError("malformed", "a zip size or offset is larger than any real file", 0);
    return Number(value);
  }
  return value;
};

export function listZip(backing: Backing, overrides: Partial<ZipLimits> = {}): ZipListing {
  const limits = { ...DEFAULT_ZIP_LIMITS, ...overrides };
  const warnings: string[] = [];
  const tailLength = Math.min(backing.size, 22 + 65535);
  const tailStart = backing.size - tailLength;
  const tail = readExact(backing, tailStart, tailLength);
  let eocd = -1;
  for (let at = tail.length - 22; at >= 0; at--) {
    if (tail.readUInt32LE(at) !== 0x06054b50) continue;
    if (at + 22 + tail.readUInt16LE(at + 20) > tail.length) continue; // a fake record inside the comment
    eocd = at;
    break;
  }
  if (eocd < 0) throw new ScanError("malformed", "no zip end-of-central-directory record", backing.size);
  let total = tail.readUInt16LE(eocd + 10);
  let directorySize = tail.readUInt32LE(eocd + 12);
  let directoryOffset = tail.readUInt32LE(eocd + 16);
  if ((total === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) && eocd >= 20 && tail.readUInt32LE(eocd - 20) === 0x07064b50) {
    const recordAt = safe(tail.readBigUInt64LE(eocd - 20 + 8));
    const record = readExact(backing, recordAt, 56);
    if (record.readUInt32LE(0) !== 0x06064b50) throw new ScanError("malformed", "bad zip64 end-of-central-directory record", recordAt);
    total = safe(record.readBigUInt64LE(32));
    directorySize = safe(record.readBigUInt64LE(40));
    directoryOffset = safe(record.readBigUInt64LE(48));
  }
  if (directorySize > limits.maxDirectoryBytes) throw new ScanError("limit", `zip directory is ${directorySize} bytes (limit ${limits.maxDirectoryBytes})`, directoryOffset);
  if (directoryOffset + directorySize > backing.size) throw new ScanError("malformed", "zip directory lies outside the file", directoryOffset);
  if (total > limits.maxEntries) warnings.push(`archive lists ${total} entries; only the first ${limits.maxEntries} were read`);
  const directory = readExact(backing, directoryOffset, directorySize);
  const entries: ZipEntry[] = [];
  let at = 0;
  while (at + 46 <= directory.length && entries.length < Math.min(total, limits.maxEntries)) {
    if (directory.readUInt32LE(at) !== 0x02014b50) throw new ScanError("malformed", "bad zip central directory entry", directoryOffset + at);
    const flags = directory.readUInt16LE(at + 8);
    const method = directory.readUInt16LE(at + 10);
    let compressedSize = directory.readUInt32LE(at + 20);
    let uncompressedSize = directory.readUInt32LE(at + 24);
    const nameLength = directory.readUInt16LE(at + 28);
    const extraLength = directory.readUInt16LE(at + 30);
    const commentLength = directory.readUInt16LE(at + 32);
    let localOffset = directory.readUInt32LE(at + 42);
    const next = at + 46 + nameLength + extraLength + commentLength;
    if (next > directory.length) throw new ScanError("malformed", "zip entry runs past the directory", directoryOffset + at);
    if (nameLength > limits.maxNameBytes) { warnings.push(`an entry name is ${nameLength} bytes long; skipped`); at = next; continue; }
    const name = directory.toString("utf8", at + 46, at + 46 + nameLength);
    const extra = directory.subarray(at + 46 + nameLength, at + 46 + nameLength + extraLength);
    if (uncompressedSize === 0xffffffff || compressedSize === 0xffffffff || localOffset === 0xffffffff) {
      for (let e = 0; e + 4 <= extra.length;) {
        const id = extra.readUInt16LE(e);
        const size = extra.readUInt16LE(e + 2);
        if (id === 1) {
          let cursor = e + 4;
          const take = (): number => { const value = safe(extra.readBigUInt64LE(cursor)); cursor += 8; return value; };
          try {
            if (uncompressedSize === 0xffffffff) uncompressedSize = take();
            if (compressedSize === 0xffffffff) compressedSize = take();
            if (localOffset === 0xffffffff) localOffset = take();
          } catch (error) { if (error instanceof ScanError) throw error; throw new ScanError("malformed", "bad zip64 extra field", directoryOffset + at); }
          break;
        }
        e += 4 + size;
      }
    }
    entries.push({ name, method, encrypted: (flags & 1) !== 0, compressedSize, uncompressedSize, localOffset });
    at = next;
  }
  return { entries, warnings };
}

/** Where the entry's bytes start in the file, from its local header (which can differ from the directory's view). */
export function entryDataStart(backing: Backing, entry: ZipEntry): number {
  const header = readExact(backing, entry.localOffset, 30);
  if (header.readUInt32LE(0) !== 0x04034b50) throw new ScanError("malformed", `bad local header for ${entry.name}`, entry.localOffset);
  const start = entry.localOffset + 30 + header.readUInt16LE(26) + header.readUInt16LE(28);
  if (start + entry.compressedSize > backing.size) throw new ScanError("malformed", `data of ${entry.name} lies outside the file`, start);
  return start;
}

/** A member name that would escape its folder if someone extracted the archive naively. */
export function unsafeMemberName(name: string): boolean {
  return name.startsWith("/") || name.startsWith("\\") || /^[A-Za-z]:/.test(name) || name.split(/[\\/]/).includes("..") || name.includes("\0");
}
