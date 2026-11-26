/** A cancellation RPC acknowledges a request, never that execution has stopped. Keep watching until a terminal event. */
export function cancellationRetry(options: { cancel(): Promise<unknown>; pending(note: string): void; active(): boolean }) {
  let disposed = false;
  let inFlight = false;
  let attempts = 0;
  let nextAt = 0;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  const note = (text: string) => { if (!disposed && options.active()) options.pending(text); };
  const dispose = () => { disposed = true; clearTimeout(retry); clearTimeout(watchdog); };
  const request = async (): Promise<void> => {
    if (disposed || !options.active() || inFlight || Date.now() < nextAt) return;
    clearTimeout(retry); retry = undefined;
    inFlight = true; attempts++;
    note("Cancellation requested; waiting for the runtime to confirm execution stopped.");
    // A hanging RPC is still unconfirmed. Do not pile concurrent cancellation requests on it.
    watchdog = setTimeout(() => note("Cancellation is not acknowledged; execution may still be running."), 5_000);
    watchdog.unref?.();
    try { await options.cancel(); }
    catch { note("Cancellation failed; execution may still be running. Retrying cancellation."); }
    finally {
      clearTimeout(watchdog); watchdog = undefined; inFlight = false;
      if (!disposed && options.active()) {
        const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempts - 1, 5));
        nextAt = Date.now() + delay;
        retry = setTimeout(() => { void request(); }, delay);
        retry.unref?.();
      }
    }
  };
  return { request, dispose };
}
