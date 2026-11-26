import { afterEach, describe, expect, it, vi } from "vitest";
import { cancellationRetry } from "./cancellation-retry.js";
afterEach(() => vi.useRealTimers());
describe("cancellation confirmation", () => {
  it("keeps a hung request unconfirmed without piling concurrent cancellation calls", async () => {
    vi.useFakeTimers();
    let resolve!: () => void;
    const cancel = vi.fn(() => new Promise<void>(done => { resolve = done; }));
    const pending = vi.fn();
    const watcher = cancellationRetry({ cancel, pending, active: () => true });
    const first = watcher.request();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(pending).toHaveBeenLastCalledWith(expect.stringContaining("not acknowledged"));
    await watcher.request(); expect(cancel).toHaveBeenCalledTimes(1);
    watcher.dispose(); resolve(); await first;
    await vi.advanceTimersByTimeAsync(60_000); expect(cancel).toHaveBeenCalledTimes(1);
  });
  it("backs repeated failures off to at most one request per 30 seconds and disposes retries", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn().mockRejectedValue(new Error("unreachable"));
    const watcher = cancellationRetry({ cancel, pending: vi.fn(), active: () => true });
    await watcher.request();
    await vi.advanceTimersByTimeAsync(61_000);
    expect(cancel).toHaveBeenCalledTimes(7);
    watcher.dispose(); await vi.advanceTimersByTimeAsync(60_000);
    expect(cancel).toHaveBeenCalledTimes(7);
  });
});
