// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Leader election with a PostgreSQL session advisory lock. Each replica keeps one dedicated connection and
// calls pg_try_advisory_lock on it every few seconds. The holder is the leader. If the connection drops,
// PostgreSQL releases the lock and another replica takes over within one interval. Leadership only saves
// duplicate work: jobs still claim their own rows, so a leader change in the middle of a tick cannot start
// a job twice.
import type { Pool, PoolClient } from "pg";

/** Fixed lock keys. They are arbitrary, never reused, and unlike the migration key. */
export const LEADER_KEYS = { scheduler: 7_204_061_101 } as const;
export type LeaderRole = keyof typeof LEADER_KEYS;

export interface LeaderElectorOptions {
  pool: Pool;
  /** The advisory lock key. Tests pass their own so they do not contend with a running server. */
  key: number;
  /** How often to try to take the lock, or to check that the held connection still answers. */
  intervalMs?: number;
  onChange?: (leader: boolean) => void;
  onError?: (error: unknown) => void;
}

export class LeaderElector {
  readonly #pool: Pool;
  readonly #key: number;
  readonly #intervalMs: number;
  readonly #onChange: ((leader: boolean) => void) | undefined;
  readonly #onError: ((error: unknown) => void) | undefined;
  #client: PoolClient | undefined;
  #leader = false;
  #timer: ReturnType<typeof setInterval> | undefined;
  #stopped = false;
  #busy: Promise<void> | undefined;

  constructor(options: LeaderElectorOptions) {
    if (!Number.isSafeInteger(options.key) || options.key <= 0) throw new Error("The leader lock key must be a positive whole number.");
    this.#pool = options.pool;
    this.#key = options.key;
    this.#intervalMs = options.intervalMs ?? 5_000;
    if (this.#intervalMs < 20) throw new Error("The leader interval must be at least 20 milliseconds.");
    this.#onChange = options.onChange;
    this.#onError = options.onError;
  }

  isLeader(): boolean { return this.#leader && !this.#stopped; }

  /** Try once now, then keep trying every interval. */
  async start(): Promise<void> {
    if (this.#timer || this.#stopped) return;
    this.#timer = setInterval(() => void this.tick(), this.#intervalMs);
    this.#timer.unref();
    await this.tick();
  }

  /** One election round. Rounds never overlap: a slow database cannot stack up connections. */
  tick(): Promise<void> {
    if (this.#stopped) return Promise.resolve();
    this.#busy ??= this.#round().finally(() => { this.#busy = undefined; });
    return this.#busy;
  }

  async #round(): Promise<void> {
    try {
      if (!this.#client) {
        const client = await this.#withTimeout(this.#pool.connect());
        // A dropped connection loses the lock at the server. Forget leadership as soon as the driver notices.
        client.on("error", () => this.#drop(client));
        if (this.#stopped) { client.release(true); return; }
        this.#client = client;
      }
      const client = this.#client;
      if (this.#leader) {
        // The lock lives as long as this connection, so a connection that answers still holds it.
        await this.#withTimeout(client.query("SELECT 1"));
        return;
      }
      const result = await this.#withTimeout(client.query("SELECT pg_try_advisory_lock($1::bigint) AS ok", [this.#key]));
      const ok = result.rows[0]?.ok === true;
      this.#set(ok);
    } catch (error) {
      this.#drop(this.#client);
      this.#onError?.(error);
    }
  }

  /** A connection that does not answer within two intervals counts as lost. */
  #withTimeout<T>(work: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const limit = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("The shared database did not answer in time.")), this.#intervalMs * 2); timer.unref(); });
    return Promise.race([work, limit]).finally(() => clearTimeout(timer));
  }

  #set(leader: boolean): void {
    if (leader === this.#leader) return;
    this.#leader = leader;
    try { this.#onChange?.(leader); } catch (error) { this.#onError?.(error); }
  }

  #drop(client: PoolClient | undefined): void {
    if (client && this.#client === client) this.#client = undefined;
    // Destroy the connection rather than return it, so a lock it still holds is released by the server.
    if (client) try { client.release(true); } catch { /* already released */ }
    this.#set(false);
  }

  /** Give up leadership now, so another replica can take it on its next round. */
  async stop(): Promise<void> {
    if (this.#stopped) return;
    this.#stopped = true;
    if (this.#timer) clearInterval(this.#timer);
    await this.#busy?.catch(() => undefined);
    const client = this.#client;
    this.#client = undefined;
    if (client) {
      if (this.#leader) await client.query("SELECT pg_advisory_unlock($1::bigint)", [this.#key]).catch(() => undefined);
      client.release(true);
    }
    const was = this.#leader;
    this.#leader = false;
    if (was) try { this.#onChange?.(false); } catch (error) { this.#onError?.(error); }
  }
}
