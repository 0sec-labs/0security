// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import type { CacheItem, CacheProvider } from "@node-saml/node-saml";
import { SamlError } from "./errors.js";

const DEFAULT_TTL_MS = 10 * 60 * 1000;

/**
 * In-memory store for outstanding request ids and for the ids of assertions already accepted.
 * Bounded, so an anonymous visitor cannot grow it without limit. It lives in one process; a restart
 * forgets it, which is safe because every entry also expires on its own clock.
 */
export class BoundedCache implements CacheProvider {
  private readonly entries = new Map<string, { value: string; createdAt: number; expiresAt: number }>();
  constructor(private readonly capacity: number, private readonly now: () => number = Date.now) {}

  private prune(): void {
    const t = this.now();
    for (const [key, entry] of this.entries) if (entry.expiresAt <= t) this.entries.delete(key);
  }

  private live(key: string) {
    const entry = this.entries.get(key);
    if (entry && entry.expiresAt <= this.now()) { this.entries.delete(key); return undefined; }
    return entry;
  }

  private store(key: string, value: string, expiresAt: number): CacheItem {
    if (this.entries.size >= this.capacity) this.prune();
    if (this.entries.size >= this.capacity) throw new SamlError("pending-full", "Too many pending sign-ins.", 429);
    const entry = { value, createdAt: this.now(), expiresAt };
    this.entries.set(key, entry);
    return { value, createdAt: entry.createdAt };
  }

  async saveAsync(key: string, value: string): Promise<CacheItem | null> {
    if (this.live(key)) return null;
    return this.store(key, value, this.now() + DEFAULT_TTL_MS);
  }
  async getAsync(key: string): Promise<string | null> { return this.live(key)?.value ?? null; }
  async removeAsync(key: string | null): Promise<string | null> {
    if (key === null) return null;
    const entry = this.live(key); this.entries.delete(key); return entry?.value ?? null;
  }
  async consumeAsync(key: string): Promise<string | null> { return this.removeAsync(key); }
  async saveIfAbsentAsync(key: string, value: string, expiresAtMs: number): Promise<boolean> {
    if (this.live(key)) return false;
    this.store(key, value, expiresAtMs);
    return true;
  }
  get size(): number { return this.entries.size; }
}
