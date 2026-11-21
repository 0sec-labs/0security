/**
 * Bounded byte access for the scanners. A `Backing` is anything that can be read at a position (a file descriptor, a
 * slice of one, a buffer); `Reader` walks it through a small window so a multi-gigabyte checkpoint is never held in
 * memory and large payloads are skipped without being read.
 */
import { readSync } from "node:fs";

export interface Backing {
  readonly size: number;
  /** Copy up to `length` bytes starting at `position` into `target`; returns how many were copied (0 at the end). */
  read(position: number, target: Buffer, length: number): number;
}

export class ScanError extends Error {
  constructor(readonly kind: "truncated" | "malformed" | "limit", message: string, readonly offset: number) {
    super(message);
    this.name = "ScanError";
  }
}

export function fileBacking(fd: number, size: number): Backing {
  return {
    size,
    read(position, target, length) {
      if (position >= size) return 0;
      return readSync(fd, target, 0, Math.min(length, size - position), position);
    },
  };
}
export function bufferBacking(buffer: Uint8Array): Backing {
  const source = Buffer.from(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  return {
    size: source.length,
    read(position, target, length) {
      if (position >= source.length) return 0;
      return source.copy(target, 0, position, Math.min(position + length, source.length));
    },
  };
}
export function sliceBacking(parent: Backing, start: number, length: number): Backing {
  const size = Math.max(0, Math.min(length, parent.size - start));
  return {
    size,
    read(position, target, wanted) {
      if (position >= size) return 0;
      return parent.read(start + position, target, Math.min(wanted, size - position));
    },
  };
}
/** Read exactly `length` bytes at `position` (small, caller-bounded reads such as headers). */
export function readExact(backing: Backing, position: number, length: number): Buffer {
  if (position < 0 || length < 0 || position + length > backing.size) throw new ScanError("truncated", "read past the end of the file", position);
  const out = Buffer.allocUnsafe(length);
  let done = 0;
  while (done < length) {
    const chunk = Buffer.allocUnsafe(Math.min(65536, length - done));
    const got = backing.read(position + done, chunk, chunk.length);
    if (got <= 0) throw new ScanError("truncated", "read past the end of the file", position + done);
    chunk.copy(out, done, 0, got);
    done += got;
  }
  return out;
}

const WINDOW = 65536;
export class Reader {
  position = 0;
  private readonly window = Buffer.allocUnsafe(WINDOW);
  private start = 0;
  private end = 0;
  constructor(private readonly backing: Backing) {}
  get size(): number { return this.backing.size; }
  get remaining(): number { return this.backing.size - this.position; }
  private fill(): boolean {
    const got = this.backing.read(this.position, this.window, WINDOW);
    this.start = this.position;
    this.end = this.position + Math.max(0, got);
    return got > 0;
  }
  /** Next byte without consuming it, or -1 at the end. */
  peek(): number {
    if ((this.position < this.start || this.position >= this.end) && !this.fill()) return -1;
    return this.window[this.position - this.start]!;
  }
  byte(): number {
    if ((this.position < this.start || this.position >= this.end) && !this.fill()) throw new ScanError("truncated", "ended in the middle of an opcode", this.position);
    return this.window[this.position++ - this.start]!;
  }
  take(length: number): Buffer {
    if (length > this.remaining) throw new ScanError("truncated", "an argument runs past the end of the data", this.position);
    const out = Buffer.allocUnsafe(length);
    for (let done = 0; done < length;) {
      if ((this.position < this.start || this.position >= this.end) && !this.fill()) throw new ScanError("truncated", "ended in the middle of an argument", this.position);
      const from = this.position - this.start;
      const copied = this.window.copy(out, done, from, Math.min(this.end - this.start, from + (length - done)));
      done += copied;
      this.position += copied;
    }
    return out;
  }
  skip(length: number): void {
    if (length > this.remaining) throw new ScanError("truncated", "an argument runs past the end of the data", this.position);
    this.position += length;
  }
  /** Bytes up to a newline (consumed, not returned in the text), at most `max` of them. */
  line(max: number): string {
    const bytes: number[] = [];
    for (;;) {
      const value = this.byte();
      if (value === 0x0a) break;
      if (bytes.length >= max) throw new ScanError("malformed", "a text argument is longer than any real one", this.position);
      bytes.push(value);
    }
    if (bytes[bytes.length - 1] === 0x0d) bytes.pop();
    return Buffer.from(bytes).toString("utf8");
  }
  uint(width: 1 | 2 | 4 | 8): number {
    const bytes = this.take(width);
    if (width === 1) return bytes[0]!;
    if (width === 2) return bytes.readUInt16LE(0);
    if (width === 4) return bytes.readUInt32LE(0);
    const big = bytes.readBigUInt64LE(0);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new ScanError("malformed", "a length is larger than any real file", this.position);
    return Number(big);
  }
}
