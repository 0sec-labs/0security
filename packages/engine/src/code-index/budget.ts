/**
 * A wall-clock deadline for synchronous extraction. The extractors run on the event loop, so a hostile file must
 * not be able to hold it: loops call `tick()`, and the build wraps each file in `withDeadline`.
 */
export class IndexBudgetExceeded extends Error {
  constructor() { super("code index time budget exceeded"); this.name = "IndexBudgetExceeded"; }
}

let deadline = Infinity;
let counter = 0;

/** Run `fn` with a deadline `ms` from now. Nested calls keep the earlier deadline. */
export function withDeadline<T>(ms: number, fn: () => T): T {
  const previous = deadline;
  deadline = Math.min(previous, Date.now() + ms);
  try { return fn(); } finally { deadline = previous; }
}

/** Cheap checkpoint for hot loops: reads the clock once in 512 calls. */
export function tick(): void {
  if ((++counter & 511) === 0 && Date.now() > deadline) throw new IndexBudgetExceeded();
}

/** Push without spreading: `push(...list)` throws on very large arrays. */
export function appendAll<T>(into: T[], items: readonly T[]): void {
  for (const item of items) into.push(item);
}

export interface Range { id: string; start: number; end: number }

/**
 * The innermost range holding an offset, for offsets asked in increasing order. A stack keeps this linear: ranges
 * sort by start (larger first on ties), and a range leaves the stack once the offset passes its end.
 */
export function innermostFinder(ranges: readonly Range[], fallback: string): (offset: number) => string {
  const sorted = [...ranges].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const stack: Range[] = [];
  let next = 0;
  let last = -1;
  return (offset: number): string => {
    if (offset < last) { stack.length = 0; next = 0; } // out of order: start over, still correct
    last = offset;
    while (next < sorted.length && sorted[next]!.start <= offset) { stack.push(sorted[next]!); next++; }
    while (stack.length > 0 && stack[stack.length - 1]!.end <= offset) stack.pop();
    return stack.length > 0 ? stack[stack.length - 1]!.id : fallback;
  };
}
