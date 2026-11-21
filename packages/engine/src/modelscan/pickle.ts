/**
 * A pickle opcode walker. It reads the opcode stream of protocols 0 to 5 and records every reference to a Python
 * callable (GLOBAL, INST, STACK_GLOBAL, and the OBJ / NEWOBJ / NEWOBJ_EX / REDUCE opcodes that call one). Nothing is
 * executed or imported. A small simulated stack lets STACK_GLOBAL (protocol 4) resolve its module and name even when
 * they were memoised and fetched again. Everything is bounded: arguments are read at most 64 KB at a time, large
 * payloads are skipped, the stack, memo and opcode count have ceilings, and any failure ends the walk with a reason
 * instead of an exception.
 */
import { Reader, ScanError } from "./reader.js";

export interface RawImport {
  module: string;
  name: string;
  opcodes: string[];
  /** Whether a CALL-type opcode (REDUCE, NEWOBJ, OBJ, INST) was seen using it. */
  called: boolean;
  offset: number;
}
export interface PickleLimits {
  maxOpcodes: number;
  maxStack: number;
  maxMemo: number;
  maxPickles: number;
  deadlineMs: number;
}
export const DEFAULT_PICKLE_LIMITS: PickleLimits = { maxOpcodes: 50_000_000, maxStack: 1_000_000, maxMemo: 1_000_000, maxPickles: 16, deadlineMs: 60_000 };
export interface PickleScan {
  imports: RawImport[];
  /** Pickles that reached STOP. */
  pickles: number;
  protocol: number | undefined;
  opcodes: number;
  /** Set when the first pickle did not end cleanly: what stopped the walk and where. */
  stop?: { kind: "truncated" | "malformed" | "limit"; message: string; offset: number };
  /** Set when data after the first pickle could not be parsed (raw tensor storage follows the pickles of old torch files). */
  trailing?: string;
}

interface Item { text?: string; ref?: RawImport }
const MAX_ARG = 65536;
const MAX_TEXT_LINE = 1 << 20;
const MAX_NAME_LINE = 512;
const IDENT = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const NO_ITEM: Item = {};

function unquote(text: string): string {
  const match = /^(["'])([\s\S]*)\1$/.exec(text.trim());
  return match ? match[2]!.replace(/\\(.)/g, "$1") : text;
}

export function scanPickleStream(reader: Reader, overrides: Partial<PickleLimits> = {}): PickleScan {
  const limits = { ...DEFAULT_PICKLE_LIMITS, ...overrides };
  const found = new Map<string, RawImport>();
  const result: PickleScan = { imports: [], pickles: 0, protocol: undefined, opcodes: 0 };
  const started = Date.now();
  let stack: Item[] = [];
  let marks: number[] = [];
  let memo = new Map<number, Item>();
  let current = 0;

  const push = (item: Item): void => {
    if (stack.length >= limits.maxStack) throw new ScanError("limit", "the pickle stack is larger than any real model", reader.position);
    stack.push(item);
  };
  const pop = (): Item => stack.pop() ?? NO_ITEM;
  const popMark = (): Item[] => {
    const at = marks.pop() ?? 0;
    return stack.splice(Math.min(at, stack.length));
  };
  const remember = (index: number, item: Item): void => { if (memo.size < limits.maxMemo || memo.has(index)) memo.set(index, item); };
  const record = (opcode: string, module: string, name: string, offset: number, called: boolean): Item => {
    const key = `${module}\u0000${name}`;
    let entry = found.get(key);
    if (!entry) { entry = { module, name, opcodes: [], called: false, offset }; found.set(key, entry); }
    if (!entry.opcodes.includes(opcode)) entry.opcodes.push(opcode);
    if (called) entry.called = true;
    return { ref: entry };
  };
  const identifier = (value: string, offset: number): string => {
    if (!IDENT.test(value) || value.length > MAX_NAME_LINE) throw new ScanError("malformed", "an import name is not a Python identifier", offset);
    return value;
  };
  /** A string argument: kept when short, skipped (value unknown) when long. */
  const sized = (length: number): Item => {
    if (length > reader.remaining) throw new ScanError("truncated", "a string runs past the end of the data", reader.position);
    if (length > MAX_ARG) { reader.skip(length); return {}; }
    return { text: reader.take(length).toString("utf8") };
  };
  const calls = (item: Item | undefined): void => { if (item?.ref) item.ref.called = true; };

  const walk = (): void => {
    for (;;) {
      if (result.opcodes++ >= limits.maxOpcodes) throw new ScanError("limit", "too many opcodes", reader.position);
      if ((result.opcodes & 0xfff) === 0 && Date.now() - started > limits.deadlineMs) throw new ScanError("limit", "scan time limit reached", reader.position);
      const at = reader.position;
      const op = reader.byte();
      switch (op) {
        case 0x80: { const protocol = reader.byte(); if (protocol > 5) throw new ScanError("malformed", `protocol ${protocol} does not exist`, at); result.protocol = Math.max(result.protocol ?? 0, protocol); break; } // PROTO
        case 0x95: reader.skip(8); break; // FRAME
        case 0x2e: return; // STOP
        case 0x28: marks.push(stack.length); break; // MARK
        case 0x30: pop(); break; // POP
        case 0x31: popMark(); break; // POP_MARK
        case 0x32: push(stack[stack.length - 1] ?? NO_ITEM); break; // DUP
        case 0x46: case 0x49: case 0x4c: reader.line(MAX_NAME_LINE); push({}); break; // FLOAT INT LONG
        case 0x4a: reader.skip(4); push({}); break; // BININT
        case 0x4b: reader.skip(1); push({}); break; // BININT1
        case 0x4d: reader.skip(2); push({}); break; // BININT2
        case 0x8a: reader.skip(reader.uint(1)); push({}); break; // LONG1
        case 0x8b: reader.skip(reader.uint(4)); push({}); break; // LONG4
        case 0x47: reader.skip(8); push({}); break; // BINFLOAT
        case 0x4e: case 0x88: case 0x89: case 0x5d: case 0x7d: case 0x29: case 0x8f: case 0x97: push({}); break; // NONE NEWTRUE NEWFALSE EMPTY_LIST EMPTY_DICT EMPTY_TUPLE EMPTY_SET NEXT_BUFFER
        case 0x50: reader.line(MAX_NAME_LINE); push({}); break; // PERSID
        case 0x51: pop(); push({}); break; // BINPERSID
        case 0x52: { const args = pop(); void args; calls(pop()); push({}); break; } // REDUCE
        case 0x53: case 0x56: push({ text: unquote(reader.line(MAX_TEXT_LINE)) }); break; // STRING UNICODE
        case 0x54: push(sized(reader.uint(4))); break; // BINSTRING
        case 0x55: push(sized(reader.uint(1))); break; // SHORT_BINSTRING
        case 0x58: push(sized(reader.uint(4))); break; // BINUNICODE
        case 0x8c: push(sized(reader.uint(1))); break; // SHORT_BINUNICODE
        case 0x8d: push(sized(reader.uint(8))); break; // BINUNICODE8
        case 0x42: reader.skip(reader.uint(4)); push({}); break; // BINBYTES
        case 0x43: reader.skip(reader.uint(1)); push({}); break; // SHORT_BINBYTES
        case 0x8e: case 0x96: reader.skip(reader.uint(8)); push({}); break; // BINBYTES8 BYTEARRAY8
        case 0x98: break; // READONLY_BUFFER
        case 0x61: pop(); break; // APPEND
        case 0x65: popMark(); break; // APPENDS
        case 0x62: pop(); break; // BUILD
        case 0x63: { const module = identifier(reader.line(MAX_NAME_LINE), at); const name = identifier(reader.line(MAX_NAME_LINE), at); push(record("GLOBAL", module, name, at, false)); break; } // GLOBAL
        case 0x64: popMark(); push({}); break; // DICT
        case 0x67: { const index = Number(reader.line(32)); push(memo.get(index) ?? NO_ITEM); break; } // GET
        case 0x68: push(memo.get(reader.uint(1)) ?? NO_ITEM); break; // BINGET
        case 0x6a: push(memo.get(reader.uint(4)) ?? NO_ITEM); break; // LONG_BINGET
        case 0x69: { const module = identifier(reader.line(MAX_NAME_LINE), at); const name = identifier(reader.line(MAX_NAME_LINE), at); popMark(); push(record("INST", module, name, at, true)); break; } // INST
        case 0x6c: popMark(); push({}); break; // LIST
        case 0x6f: { const items = popMark(); calls(items[0]); push({}); break; } // OBJ
        case 0x70: { remember(Number(reader.line(32)), stack[stack.length - 1] ?? NO_ITEM); break; } // PUT
        case 0x71: remember(reader.uint(1), stack[stack.length - 1] ?? NO_ITEM); break; // BINPUT
        case 0x72: remember(reader.uint(4), stack[stack.length - 1] ?? NO_ITEM); break; // LONG_BINPUT
        case 0x94: remember(memo.size, stack[stack.length - 1] ?? NO_ITEM); break; // MEMOIZE
        case 0x73: pop(); pop(); break; // SETITEM
        case 0x75: popMark(); break; // SETITEMS
        case 0x74: popMark(); push({}); break; // TUPLE
        case 0x81: { pop(); calls(pop()); push({}); break; } // NEWOBJ
        case 0x92: { pop(); pop(); calls(pop()); push({}); break; } // NEWOBJ_EX
        case 0x82: reader.skip(1); push({}); break; // EXT1
        case 0x83: reader.skip(2); push({}); break; // EXT2
        case 0x84: reader.skip(4); push({}); break; // EXT4
        case 0x85: pop(); push({}); break; // TUPLE1
        case 0x86: pop(); pop(); push({}); break; // TUPLE2
        case 0x87: pop(); pop(); pop(); push({}); break; // TUPLE3
        case 0x90: popMark(); break; // ADDITEMS
        case 0x91: popMark(); push({}); break; // FROZENSET
        case 0x93: { // STACK_GLOBAL
          const name = pop();
          const module = pop();
          if (module.text !== undefined && name.text !== undefined && IDENT.test(module.text) && IDENT.test(name.text) && module.text.length <= MAX_NAME_LINE && name.text.length <= MAX_NAME_LINE) push(record("STACK_GLOBAL", module.text, name.text, at, false));
          else push(record("STACK_GLOBAL", "<computed>", "<computed>", at, false));
          break;
        }
        default: throw new ScanError("malformed", `unknown opcode 0x${op.toString(16).padStart(2, "0")}`, at);
      }
    }
  };

  for (; current < limits.maxPickles; current++) {
    stack = []; marks = []; memo = new Map();
    const first = current === 0;
    try {
      walk();
      result.pickles++;
    } catch (error) {
      if (!(error instanceof ScanError)) throw error;
      if (first) result.stop = { kind: error.kind, message: error.message, offset: error.offset };
      else result.trailing = `${error.message} at byte ${error.offset}`;
      break;
    }
    if (reader.remaining <= 0) break;
  }
  if (!result.stop && !result.trailing && current >= limits.maxPickles && reader.remaining > 0) result.trailing = `more than ${limits.maxPickles} pickles in the file; the rest were not read`;
  result.imports = [...found.values()];
  return result;
}
