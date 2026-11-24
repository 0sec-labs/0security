import { createHash, randomBytes, randomUUID } from "node:crypto";
import { ensureDatabaseDirectory } from "./db-directory.js";
import { resolveOsecDbPath } from "./database.js";
import { createShimmedDatabase, type ShimmedDatabase } from "./wasm-shim.js";

export interface ScimTokenRecord { id: string; name: string; createdAt: string; revokedAt: string | null; lastUsedAt: string | null }
export interface ScimGroupRecord { id: string; displayName: string; externalId: string | null; memberIds: string[]; createdAt: string; updatedAt: string }

const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

/** Bearer tokens for identity providers and the SCIM groups, in the server database next to the accounts. */
export class ScimTable {
  private readonly db: ShimmedDatabase;
  constructor(dbPath?: string) {
    const path = dbPath === ":memory:" ? ":memory:" : resolveOsecDbPath(dbPath);
    if (path !== ":memory:") ensureDatabaseDirectory(path);
    this.db = createShimmedDatabase(path);
    this.db.pragma("busy_timeout = 5000");
    this.db.exec(`CREATE TABLE IF NOT EXISTS scim_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT, last_used_at TEXT);
      CREATE TABLE IF NOT EXISTS scim_groups (id TEXT PRIMARY KEY, display_name TEXT NOT NULL UNIQUE, external_id TEXT, members_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`);
  }

  /** Make a token. The token is returned once; only its hash is stored. */
  createToken(name: string): { record: ScimTokenRecord; token: string } {
    const token = `scim_${randomBytes(32).toString("base64url")}`;
    const record: ScimTokenRecord = { id: randomUUID(), name, createdAt: new Date().toISOString(), revokedAt: null, lastUsedAt: null };
    this.db.prepare("INSERT INTO scim_tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)").run(record.id, name, hashToken(token), record.createdAt);
    return { record, token };
  }
  listTokens(): ScimTokenRecord[] {
    return (this.db.prepare("SELECT id, name, created_at, revoked_at, last_used_at FROM scim_tokens ORDER BY created_at").all() as Array<Record<string, unknown>>)
      .map(row => ({ id: String(row.id), name: String(row.name), createdAt: String(row.created_at), revokedAt: row.revoked_at === null ? null : String(row.revoked_at), lastUsedAt: row.last_used_at === null ? null : String(row.last_used_at) }));
  }
  revokeToken(id: string): ScimTokenRecord | null {
    this.db.prepare("UPDATE scim_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?").run(new Date().toISOString(), id);
    return this.listTokens().find(token => token.id === id) ?? null;
  }
  /** The record for a presented token, or null when it is unknown or revoked. */
  verifyToken(token: string): ScimTokenRecord | null {
    const raw = this.db.prepare("SELECT id, name, created_at, revoked_at, last_used_at FROM scim_tokens WHERE token_hash = ?").get(hashToken(token)) as Record<string, unknown> | undefined;
    if (!raw || raw.revoked_at !== null) return null;
    const now = new Date().toISOString();
    this.db.prepare("UPDATE scim_tokens SET last_used_at = ? WHERE id = ?").run(now, String(raw.id));
    return { id: String(raw.id), name: String(raw.name), createdAt: String(raw.created_at), revokedAt: null, lastUsedAt: now };
  }

  private toGroup(raw: Record<string, unknown>): ScimGroupRecord {
    let memberIds: string[] = [];
    try { const parsed: unknown = JSON.parse(String(raw.members_json)); if (Array.isArray(parsed)) memberIds = parsed.filter((id): id is string => typeof id === "string"); } catch { /* keep empty */ }
    return { id: String(raw.id), displayName: String(raw.display_name), externalId: raw.external_id === null ? null : String(raw.external_id), memberIds, createdAt: String(raw.created_at), updatedAt: String(raw.updated_at) };
  }
  listGroups(): ScimGroupRecord[] { return (this.db.prepare("SELECT * FROM scim_groups ORDER BY created_at, id").all() as Array<Record<string, unknown>>).map(row => this.toGroup(row)); }
  getGroup(id: string): ScimGroupRecord | null {
    const raw = this.db.prepare("SELECT * FROM scim_groups WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    return raw ? this.toGroup(raw) : null;
  }
  groupNameTaken(displayName: string, exceptId?: string): boolean {
    const raw = this.db.prepare("SELECT id FROM scim_groups WHERE lower(display_name) = lower(?)").get(displayName) as { id: string } | undefined;
    return Boolean(raw && raw.id !== exceptId);
  }
  saveGroup(group: { id?: string; displayName: string; externalId: string | null; memberIds: string[] }): ScimGroupRecord {
    const now = new Date().toISOString();
    const existing = group.id ? this.getGroup(group.id) : null;
    const id = existing?.id ?? group.id ?? randomUUID();
    const members = JSON.stringify([...new Set(group.memberIds)]);
    if (existing) this.db.prepare("UPDATE scim_groups SET display_name = ?, external_id = ?, members_json = ?, updated_at = ? WHERE id = ?").run(group.displayName, group.externalId, members, now, id);
    else this.db.prepare("INSERT INTO scim_groups (id, display_name, external_id, members_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)").run(id, group.displayName, group.externalId, members, now, now);
    return this.getGroup(id)!;
  }
  deleteGroup(id: string): boolean {
    const had = this.getGroup(id) !== null;
    this.db.prepare("DELETE FROM scim_groups WHERE id = ?").run(id);
    return had;
  }
  close(): void { try { this.db.close(); } catch { /* already closed */ } }
}
