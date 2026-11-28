/**
 * Chat drivers. `scriptedChatDriver` is for tests. `commandChatDriver` runs a real conversational agent as a child process that speaks
 * JSON lines on stdin and stdout (see PROTOCOL.md) while a honeypot trace file records its tool calls.
 */
import { spawn, type SpawnOptions } from "node:child_process";
import { open } from "node:fs/promises";
import type { Privilege, TraceEvent } from "../honeypot.js";
import type { ChatDriver } from "./types.js";

export interface ScriptedCall { tool: string; privilege?: Privilege | "unknown"; args?: Record<string, unknown> }
export interface ScriptedChatOptions {
  /** The agent's reply to a message. `turn` is 1-based. */
  reply: (message: string, turn: number) => string | Promise<string>;
  /** Calls made during a turn: a function, or an array with one entry per turn. Sequence numbers are assigned here. */
  calls?: ((message: string, turn: number) => ScriptedCall[]) | readonly (readonly ScriptedCall[])[];
}

export function scriptedChatDriver(options: ScriptedChatOptions): ChatDriver {
  let turn = 0; let seq = 0;
  return {
    async send(message) {
      turn++;
      const reply = await options.reply(message, turn);
      const raw = typeof options.calls === "function" ? options.calls(message, turn) : options.calls?.[turn - 1] ?? [];
      const calls: TraceEvent[] = raw.map(call => ({ seq: ++seq, tool: call.tool, privilege: call.privilege ?? "unknown", args: call.args ?? {} }));
      return { reply, calls };
    },
  };
}

/** The part of a child process the driver uses; node's ChildProcess satisfies it. */
export interface ChatChild {
  stdin: { write(chunk: string): unknown; end(): unknown; on?(event: "error", listener: (error: Error) => void): unknown } | null;
  stdout: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  /** Drained and discarded so a full pipe cannot block the agent. */
  stderr?: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  /** When set and the child leads its own process group (spawned detached), close() signals the whole group. */
  pid?: number | undefined;
  on(event: "exit" | "error", listener: (...args: unknown[]) => void): unknown;
  kill(signal?: NodeJS.Signals): unknown;
}

/** Spawns the agent as a process group leader with piped stdio, so close() can stop it and anything it started. */
export function spawnAgentProcess(command: string, args: readonly string[], options: SpawnOptions = {}): ChatChild {
  return spawn(command, [...args], { ...options, detached: true, stdio: ["pipe", "pipe", "pipe"] }) as unknown as ChatChild;
}

export interface TraceChunk { bytes: Buffer; /** Total size of the file now. */ size: number }
export interface CommandChatOptions {
  /** The honeypot trace file the agent's tool server appends to (JSON lines). Without isolation the agent can write it, so it is untrusted (see PROTOCOL.md). */
  tracePath: string;
  /** How long to wait for one reply. Default 30000. */
  turnTimeoutMs?: number;
  /** Reads at most `maxBytes` of the trace file from byte `offset`, and reports the file's size. Default reads the file; a missing file is empty. */
  readTrace?: (path: string, offset: number, maxBytes: number) => Promise<TraceChunk>;
  /** Most trace bytes accepted in one turn; more is a driver error. Default 4 MiB. */
  maxTraceBytes?: number;
  /** Most trace events accepted in one turn; more is a driver error. Default 1000. */
  maxTraceEvents?: number;
  /** Longest accepted stdout line without a newline, in bytes. Default 1 MiB. */
  maxLineBytes?: number;
  /** After SIGTERM, how long close() waits before SIGKILL. Default 2000. */
  killGraceMs?: number;
}

const PRIVILEGES: ReadonlySet<string> = new Set(["source", "read-local", "write-local", "network-out", "exec", "unknown"]);
const MAX_TOOL_CHARS = 128;
const MAX_EVENT_BYTES = 64 * 1024;

const defaultReadTrace = async (path: string, offset: number, maxBytes: number): Promise<TraceChunk> => {
  let handle;
  try { handle = await open(path, "r"); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return { bytes: Buffer.alloc(0), size: 0 }; throw error; }
  try {
    const { size } = await handle.stat();
    const length = Math.max(0, Math.min(size - offset, maxBytes));
    const bytes = Buffer.alloc(length);
    const { bytesRead } = length ? await handle.read(bytes, 0, length, offset) : { bytesRead: 0 };
    return { bytes: bytes.subarray(0, bytesRead), size };
  } finally { await handle.close(); }
};

/** One validated event, or undefined for a line that is not a well-formed event (skipped). */
function toEvent(line: string): TraceEvent | undefined {
  if (Buffer.byteLength(line) > MAX_EVENT_BYTES) return undefined;
  let value: unknown;
  try { value = JSON.parse(line); } catch { return undefined; }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const { seq, tool, privilege, args } = value as Record<string, unknown>;
  if (typeof seq !== "number" || !Number.isFinite(seq) || !Number.isInteger(seq) || seq < 0) return undefined;
  if (typeof tool !== "string" || tool.length === 0 || tool.length > MAX_TOOL_CHARS) return undefined;
  if (privilege !== undefined && (typeof privilege !== "string" || !PRIVILEGES.has(privilege))) return undefined;
  if (typeof args !== "object" || args === null || Array.isArray(args)) return undefined;
  return { seq, tool, privilege: (privilege ?? "unknown") as TraceEvent["privilege"], args: args as Record<string, unknown> };
}

const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; } };

export function commandChatDriver(spawnAgent: () => ChatChild, options: CommandChatOptions): ChatDriver {
  const timeoutMs = options.turnTimeoutMs ?? 30_000;
  const readTrace = options.readTrace ?? defaultReadTrace;
  const maxTraceBytes = options.maxTraceBytes ?? 4 * 1024 * 1024;
  const maxTraceEvents = options.maxTraceEvents ?? 1000;
  const maxLineBytes = options.maxLineBytes ?? 1024 * 1024;
  const graceMs = options.killGraceMs ?? 2000;
  let child: ChatChild | undefined;
  let buffer = ""; let ended: Error | undefined; let offset = 0; let lastSeq = -1; let exited = false; let closing: Promise<void> | undefined;
  let waiter: { resolve(text: string): void; reject(error: Error): void } | undefined;

  const fail = (error: Error) => { ended ??= error; const w = waiter; waiter = undefined; w?.reject(error); };
  const onLine = (line: string) => {
    let value: unknown;
    try { value = JSON.parse(line); } catch { return; } // the agent may log plain text; only protocol lines count
    if (typeof value !== "object" || value === null) return;
    const record = value as { type?: unknown; text?: unknown };
    if (record.type !== "reply" || typeof record.text !== "string") return;
    const w = waiter;
    if (w) { waiter = undefined; w.resolve(record.text); } // a reply nobody waits for (after a timeout) is dropped
  };
  let grouped = false;
  const signal = (proc: ChatChild, sig: NodeJS.Signals) => {
    const pid = proc.pid;
    // A negative pid addresses the process group; it only exists when the child was spawned detached, otherwise this fails and the child alone is signalled.
    if (process.platform !== "win32" && typeof pid === "number" && pid > 1) { try { process.kill(-pid, sig); grouped = true; return; } catch { /* not a group leader, or already gone */ } }
    try { proc.kill(sig); } catch { /* already gone */ }
  };
  /** The child has exited and, when it led a group, nothing is left in that group. */
  const gone = (proc: ChatChild): boolean => exited && !(grouped && typeof proc.pid === "number" && alive(-proc.pid));
  const waitGone = async (proc: ChatChild, ms: number): Promise<boolean> => {
    const until = Date.now() + ms;
    while (!gone(proc)) { if (Date.now() >= until) return false; await new Promise(resolve => setTimeout(resolve, 20)); }
    return true;
  };
  const terminate = (proc: ChatChild): Promise<void> => closing ??= (async () => {
    try { proc.stdin?.end(); } catch { /* already closed */ }
    signal(proc, "SIGTERM");
    if (!(await waitGone(proc, graceMs))) { signal(proc, "SIGKILL"); await waitGone(proc, 2000); }
  })();
  const start = (): ChatChild => {
    if (child) return child;
    const proc = child = spawnAgent();
    proc.stdout?.on("data", chunk => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      let at: number;
      while ((at = buffer.indexOf("\n")) >= 0) { const line = buffer.slice(0, at).trim(); buffer = buffer.slice(at + 1); if (line) onLine(line); }
      if (Buffer.byteLength(buffer) > maxLineBytes) { buffer = ""; fail(new Error(`the agent wrote more than ${maxLineBytes} bytes without a newline`)); void terminate(proc); }
    });
    proc.stderr?.on("data", () => { /* drained so a full pipe cannot block the agent; never kept */ });
    proc.stdin?.on?.("error", error => fail(error instanceof Error ? error : new Error(String(error)))); // EPIPE when the agent has gone
    proc.on("exit", () => { exited = true; fail(new Error("the agent process ended before it replied")); });
    proc.on("error", error => fail(error instanceof Error ? error : new Error(String(error))));
    return proc;
  };

  /** Events appended since the last turn. The file is untrusted: a shrinking file, a non-increasing seq, or too much data is an error. */
  async function newEvents(): Promise<TraceEvent[]> {
    const { bytes, size } = await readTrace(options.tracePath, offset, maxTraceBytes);
    if (size < offset) throw new Error("the trace file shrank; it cannot be trusted");
    if (size - offset > maxTraceBytes) throw new Error(`the trace grew by more than ${maxTraceBytes} bytes in one turn`);
    const end = bytes.lastIndexOf(10) + 1; // only complete lines count; a partial last line waits for the next turn
    if (end === 0 && bytes.length >= maxTraceBytes) throw new Error("a trace line is longer than the byte limit");
    const events: TraceEvent[] = [];
    for (const line of bytes.subarray(0, end).toString("utf8").split(/\r?\n/)) {
      if (!line.trim()) continue;
      const event = toEvent(line);
      if (!event) continue;
      if (event.seq <= lastSeq) throw new Error("the trace sequence numbers are not increasing; it cannot be trusted");
      if (events.length >= maxTraceEvents) throw new Error(`the trace has more than ${maxTraceEvents} events in one turn`);
      lastSeq = event.seq;
      events.push(event);
    }
    offset += end;
    return events;
  }

  return {
    async send(message) {
      if (ended) throw ended;
      const proc = start();
      const reply = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => { waiter = undefined; reject(new Error(`the agent did not reply within ${timeoutMs} ms`)); }, timeoutMs);
        waiter = { resolve: text => { clearTimeout(timer); resolve(text); }, reject: error => { clearTimeout(timer); reject(error); } };
        try { proc.stdin?.write(`${JSON.stringify({ type: "user", text: message })}\n`); } catch (error) { clearTimeout(timer); waiter = undefined; reject(error instanceof Error ? error : new Error(String(error))); }
      });
      try { return { reply, calls: await newEvents() }; } catch (error) { const e = error instanceof Error ? error : new Error(String(error)); ended ??= e; throw e; }
    },
    async close() {
      ended ??= new Error("the driver is closed");
      if (child) await terminate(child);
    },
  };
}
