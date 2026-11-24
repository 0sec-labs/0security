import { readFileSync } from "node:fs";
import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { promisify } from "node:util";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { TeamAuthError } from "./team-auth-error.js";
import { TeamSaml, samlConfigSchema, validateSamlConfig } from "./team-saml.js";
import { ScimTable, TeamUserConflictError, type TeamUserRow, type TeamUserTable } from "@0/engine/storage";
import { BUILT_IN_ROLES, hasFeature, nearestBuiltInRole, parseScope, resolveRoles, roleFromGroups, scopePatterns, type Permission, type RoleDefinition, type RoleScope } from "../enterprise-bridge.js";

const scrypt = promisify(scryptCallback);
const COOKIE = "zero_team_session";
const SSO_COOKIE = "zero_team_sso";
const SESSION_MS = 8 * 60 * 60 * 1000;
const SSO_MS = 10 * 60 * 1000;
const userSchema = z.object({
  id: z.string().min(1).max(160), name: z.string().min(1).max(160),
  role: z.string().min(1).max(64), passwordHash: z.string().optional(), oidcSub: z.string().min(1).optional(), samlNameId: z.string().min(1).max(512).optional(),
}).strict();
const configSchema = z.object({
  workspace: z.object({ id: z.string().min(1).max(160), name: z.string().min(1).max(160) }).strict(),
  users: z.array(userSchema).min(1).max(1000),
  oidc: z.object({
    issuer: z.string().url(), clientId: z.string().min(1), clientSecretEnv: z.string().min(1).optional(), redirectUri: z.string().url(),
    /** Create an account the first time an OIDC user signs in. Needs the rbac license feature. */
    jit: z.object({ role: z.enum(["editor", "viewer"]) }).strict().optional(),
    /** Group name in the groups claim to role name, in order of preference. Needs the rbac license feature. */
    groupRoles: z.record(z.string().min(1).max(256), z.string().min(1).max(64)).optional(),
    /** Name of the claim that lists the user's groups. Default "groups". */
    groupsClaim: z.string().min(1).max(64).optional(),
  }).strict().optional(),
  saml: samlConfigSchema.optional(),
  /** SCIM provisioning (needs the scim license feature). Group names to roles, in order of preference, and the role for everyone else. */
  scim: z.object({ defaultRole: z.string().min(1).max(64).optional(), groupRoles: z.record(z.string().min(1).max(256), z.string().min(1).max(64)).optional() }).strict().optional(),
  /** Custom roles (needs the rbac license feature to take effect). See the server mode page. */
  roles: z.record(z.string(), z.unknown()).optional(),
  /** Business units: a name for a group of repository patterns, used in role and account scopes. */
  businessUnits: z.record(z.string().min(1).max(64), z.array(z.string().min(1).max(200)).max(200)).optional(),
}).strict();
export type TeamConfig = z.infer<typeof configSchema>;
/** Accounts the free tier can hold. A server with the rbac license feature has no limit. */
export const FREE_MEMBER_LIMIT = 1000;
const NEEDS_LICENSE = "This needs an enterprise license that includes role-based access control.";
export function parseTeamConfig(input: unknown): TeamConfig { return configSchema.parse(input); }
/** The roles that need no license. */
const FREE_ROLES: ReadonlySet<string> = new Set(["owner", "editor", "viewer"]);
export interface TeamIdentity {
  workspaceId: string; userId: string; displayName: string;
  /** The nearest of owner, editor and viewer. Code that only knows the three free roles reads this. */
  role: "owner" | "editor" | "viewer";
  /** The role as assigned, for example "triager" or a custom name. */
  roleName: string;
  permissions: Permission[];
  /** Repository patterns the account is limited to, or null for no limit. */
  scope: string[] | null;
}
export interface TeamMember { userId: string; displayName: string; role: string; scope?: RoleScope; disabled?: true }
/** A role change made by an administrator or by the identity provider's group mapping. */
export interface TeamRoleChange { userId: string; old: string; new: string; source: "admin" | "oidc-group" | "scim-group" }
export { TeamAuthError };
const fileRow = (user: { id: string; name: string; role: string; passwordHash?: string | undefined; oidcSub?: string | undefined }): TeamUserRow => ({ id: user.id, name: user.name, role: user.role, roleSource: "admin", scopeJson: null, active: true, deleted: false, userName: null, externalId: null, email: null, oidcIssuer: null, passwordHash: user.passwordHash ?? null, oidcSub: user.oidcSub ?? null, source: "file", createdAt: "", updatedAt: "" });
function opaque(): string { return randomBytes(32).toString("base64url"); }
export function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const part of (header ?? "").split(";")) {
    const at = part.indexOf("="); if (at < 0) continue;
    const name = part.slice(0, at).trim();
    // Reject duplicates rather than selecting an attacker-controlled shadow cookie.
    if (Object.hasOwn(cookies, name)) { cookies[name] = ""; continue; }
    cookies[name] = part.slice(at + 1).trim();
  }
  return cookies;
}
export function getSessionId(req: Pick<IncomingMessage, "headers">): string | undefined {
  const id = parseCookies(req.headers.cookie)[COOKIE]; return id && /^[\w-]{43}$/.test(id) ? id : undefined;
}
export async function hashTeamPassword(password: string): Promise<string> {
  if (!password || password.length > 1024) throw new TeamAuthError("Password must contain 1–1024 characters", 400);
  const salt = randomBytes(16); const key = await scrypt(password, salt, 64) as Buffer;
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}
function validHash(hash: string): boolean { return /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/.test(hash); }
async function passwordMatches(password: string, hash: string): Promise<boolean> {
  const [, salt, expected] = hash.split("$");
  const key = await scrypt(password, Buffer.from(salt!, "hex"), 64) as Buffer;
  return timingSafeEqual(key, Buffer.from(expected!, "hex"));
}
interface Discovery { authorization_endpoint: string; token_endpoint: string; jwks_uri: string }
export class TeamAuth {
  private readonly config?: TeamConfig;
  private readonly origin: string;
  private readonly now: () => number;
  /** Live accounts. The server database is the source of truth once a store is attached; until then the file users. */
  private readonly users = new Map<string, TeamUserRow>();
  private table?: TeamUserTable;
  private scimTable?: ScimTable;
  private roles: Map<string, RoleDefinition>;
  private readonly sessions = new Map<string, { userId: string; expires: number; role?: string }>();
  private readonly saml?: TeamSaml;
  private readonly pending = new Map<string, { nonce: string; verifier: string; browser: string; expires: number }>();
  private readonly attempts = new Map<string, { count: number; expires: number }>();
  private discovery?: Discovery;
  private keys?: ReturnType<typeof createRemoteJWKSet>;
  private readonly dummyHash: Promise<string>;
  constructor(options: { configPath?: string; config?: TeamConfig; origin: string; now?: () => number }) {
    this.origin = new URL(options.origin).origin; this.now = options.now ?? Date.now;
    this.roles = new Map(Object.entries(BUILT_IN_ROLES));
    const source = options.config ?? (options.configPath ? JSON.parse(readFileSync(options.configPath, "utf8")) as unknown : undefined);
    if (source !== undefined) {
      this.config = configSchema.parse(source);
      if (new Set(this.config.users.map(user => user.id)).size !== this.config.users.length) throw new Error("Team user IDs must be unique");
      const subjects = this.config.users.flatMap(user => user.oidcSub ? [user.oidcSub] : []);
      if (new Set(subjects).size !== subjects.length) throw new Error("OIDC subjects must be unique");
      const samlIds = this.config.users.flatMap(user => user.samlNameId ? [user.samlNameId] : []);
      if (new Set(samlIds).size !== samlIds.length) throw new Error("SAML NameIDs must be unique");
      for (const user of this.config.users) if (user.passwordHash && !validHash(user.passwordHash)) throw new Error("Invalid team password hash; use hashTeamPassword");
      try { this.roles = resolveRoles(this.config.roles); } catch (error) { throw new Error(`Invalid team roles: ${error instanceof Error ? error.message : "unreadable"}`); }
      for (const user of this.config.users) if (!this.roles.has(user.role)) throw new Error(`Team user "${user.id}" has the unknown role "${user.role}"`);
      for (const [group, role] of Object.entries(this.config.saml?.groupRoles ?? {})) if (!this.roles.has(role)) throw new Error(`SAML group "${group}" maps to the unknown role "${role}"`);
      for (const [group, role] of Object.entries(this.config.oidc?.groupRoles ?? {})) if (!this.roles.has(role)) throw new Error(`OIDC group "${group}" maps to the unknown role "${role}"`);
      for (const role of [...Object.values(this.config.scim?.groupRoles ?? {}), ...(this.config.scim?.defaultRole ? [this.config.scim.defaultRole] : [])]) if (!this.roles.has(role)) throw new Error(`The SCIM settings name the unknown role "${role}"`);
      for (const user of this.config.users) this.users.set(user.id, fileRow(user));
      if (this.config.oidc) {
        this.requireProviderURL(this.config.oidc.issuer);
        if (new URL(this.config.oidc.redirectUri).origin !== this.origin) throw new Error("OIDC redirect URI must use this engine origin");
        if (new URL(this.config.oidc.redirectUri).pathname !== "/api/team/auth/callback") throw new Error("OIDC redirect URI must use /api/team/auth/callback");
        if (this.config.oidc.clientSecretEnv && !process.env[this.config.oidc.clientSecretEnv]) throw new Error("Configured OIDC client secret environment variable is missing");
      }
      if (this.config.saml) {
        validateSamlConfig(this.config.saml, this.origin);
        this.saml = new TeamSaml(this.config.saml, { now: this.now, cookie: (name, value, seconds) => this.cookie(name, value, seconds), findMember: nameId => { const user = this.config!.users.find(row => row.samlNameId === nameId); return user ? { id: user.id, role: this.users.get(user.id)?.role ?? user.role } : undefined; }, roleRank: role => this.roles.get(role)?.permissions.length ?? 0 });
      }
    }
    this.dummyHash = hashTeamPassword(opaque());
  }
  get enabled(): boolean { return !!this.config; }
  get workspaceId(): string | undefined { return this.config?.workspace.id; }
  get name(): string | undefined { return this.config?.workspace.name; }
  private cookie(name: string, value: string, seconds: number): string {
    return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}${this.origin.startsWith("https:") ? "; Secure" : ""}`;
  }
  lookupUser(id: string, role?: string): TeamIdentity | null {
    const user = this.users.get(id);
    // A deprovisioned account has no identity, so every session it had stops working at the next request.
    if (!user || !user.active || user.deleted) return null;
    // A role from a SAML group answers for this session; every other fact about the account comes from its row.
    return this.identityFor(role && role !== user.role && this.roles.has(role) ? { ...user, role } : user);
  }
  /**
   * Work out what an account may do. With the rbac license a role means its permissions. Without it only owner,
   * editor and viewer exist; any other role counts as the nearest of those and never as owner. A scope always applies,
   * licensed or not, so a lapsed license cannot widen what a scoped account sees.
   */
  private identityFor(user: TeamUserRow): TeamIdentity {
    const def = this.roles.get(user.role) ?? BUILT_IN_ROLES.viewer!;
    let role = nearestBuiltInRole(def.permissions);
    // Owner-only handlers read `role`. Only the role named owner is ever "owner", however many permissions another role holds.
    if (role === "owner" && user.role !== "owner") role = "editor";
    let permissions = def.permissions;
    if (!FREE_ROLES.has(user.role) && !hasFeature("rbac")) permissions = BUILT_IN_ROLES[role]!.permissions;
    if (user.role === "owner") role = "owner";
    return { workspaceId: this.config!.workspace.id, userId: user.id, displayName: user.name, role, roleName: user.role, permissions: [...permissions], scope: this.scopeOf(user, def) };
  }
  private scopeOf(user: TeamUserRow, def: RoleDefinition): string[] | null {
    let own: RoleScope | undefined;
    if (user.scopeJson) { try { own = parseScope(JSON.parse(user.scopeJson)); } catch { return []; } }
    return scopePatterns(own ?? def.scope, this.config?.businessUnits);
  }
  /**
   * Move the accounts into the server database. Accounts in the configuration file that the database does
   * not know yet are added; accounts already in the database are never changed by the file. After this call
   * the database is the source of truth and every change is stored as it happens.
   */
  attachStore(table: TeamUserTable): { imported: number; total: number } {
    if (!this.config) throw new TeamAuthError("Team sign-in is not configured", 404);
    const added = table.importMissing(this.config.users.map(user => ({ id: user.id, name: user.name, role: user.role, passwordHash: user.passwordHash ?? null, oidcSub: user.oidcSub ?? null, source: "file" as const })));
    this.table = table; this.scimTable?.close(); this.scimTable = new ScimTable(table.databasePath); this.users.clear();
    const rows = table.list();
    for (const row of rows) this.users.set(row.id, row);
    for (const [id, session] of this.sessions) if (!this.users.has(session.userId)) this.sessions.delete(id);
    return { imported: added.length, total: rows.length };
  }
  /** Close the database connection, if a store is attached. */
  closeStore(): void { this.table?.close(); this.table = undefined; this.scimTable?.close(); this.scimTable = undefined; }
  /** SCIM tokens and groups. Undefined until the accounts are in the database. */
  get scim(): ScimTable | undefined { return this.scimTable; }
  /** Trusted server configuration only; never serialize this through a browser API. */
  snapshotConfig(): TeamConfig {
    if (!this.config) throw new TeamAuthError("Team sign-in is not configured", 404);
    return structuredClone(this.config);
  }
  configurationDigest(): string { return createHash("sha256").update(JSON.stringify(this.snapshotConfig())).digest("hex"); }
  members(): TeamMember[] {
    return [...this.users.values()].filter(user => !user.deleted).map(user => {
      const scope = user.scopeJson ? parseScope(JSON.parse(user.scopeJson)) : undefined;
      return { userId: user.id, displayName: user.name, role: user.role, ...(scope ? { scope } : {}), ...(user.active ? {} : { disabled: true }) };
    });
  }
  /** Names and permissions of every role the server knows, for the roles page. */
  roleList(): Array<{ name: string; builtIn: boolean; assignable: boolean; permissions: Permission[]; scope: RoleScope | null }> {
    return [...this.roles].map(([name, def]) => ({ name, builtIn: name in BUILT_IN_ROLES, assignable: FREE_ROLES.has(name) || hasFeature("rbac"), permissions: [...def.permissions], scope: def.scope ?? null }));
  }
  /**
   * Change the role or the scope of one account. The caller has checked the license and the permission.
   * Returns what changed, for the audit log. Never leaves the workspace without an account that can manage users.
   */
  setAccess(userId: string, change: { role?: string; scope?: unknown }): { before: { role: string; scope: RoleScope | null }; after: { role: string; scope: RoleScope | null } } {
    const user = this.users.get(userId);
    if (!user) throw new TeamAuthError("No such account", 404);
    if (change.role !== undefined && !this.roles.has(change.role)) throw new TeamAuthError("Unknown role", 400);
    let scopeJson: string | null | undefined;
    if (change.scope !== undefined) {
      if (change.scope === null) scopeJson = null;
      else {
        try {
          const scope = parseScope(change.scope);
          for (const unit of scope?.businessUnits ?? []) if (!this.config?.businessUnits?.[unit]) throw new Error(`Unknown business unit "${unit}"`);
          scopeJson = scope && (scope.repos?.length || scope.businessUnits?.length) ? JSON.stringify(scope) : null;
        } catch (error) { throw new TeamAuthError(error instanceof Error ? error.message : "Invalid scope", 400); }
      }
    }
    const nextRole = change.role ?? user.role;
    if (nextRole !== user.role && this.roles.get(user.role)?.permissions.includes("users.manage") && !this.roles.get(nextRole)?.permissions.includes("users.manage")) {
      const others = [...this.users.values()].filter(row => row.id !== user.id && this.roles.get(row.role)?.permissions.includes("users.manage"));
      if (others.length === 0) throw new TeamAuthError("Keep at least one account that can manage users", 409);
    }
    const before = { role: user.role, scope: user.scopeJson ? parseScope(JSON.parse(user.scopeJson)) ?? null : null };
    const next = { ...user, role: nextRole, roleSource: "admin" as const, scopeJson: scopeJson === undefined ? user.scopeJson : scopeJson };
    this.table?.updateAccess(userId, { role: next.role, roleSource: "admin", scopeJson: next.scopeJson });
    this.users.set(userId, next);
    return { before, after: { role: next.role, scope: next.scopeJson ? parseScope(JSON.parse(next.scopeJson)) ?? null : null } };
  }
  memberCount(): number { return [...this.users.values()].filter(user => !user.deleted).length; }
  /** The free tier stops at FREE_MEMBER_LIMIT accounts; the rbac license feature lifts that. */
  atMemberLimit(): boolean { return this.memberCount() >= FREE_MEMBER_LIMIT && !hasFeature("rbac"); }
  private store(input: TeamUserRow): TeamUserRow {
    const stamp = new Date(this.now()).toISOString();
    const row = { ...input, createdAt: input.createdAt || stamp, updatedAt: input.updatedAt || stamp };
    try { this.table?.insert(row); }
    catch (error) { if (error instanceof TeamUserConflictError) throw new TeamAuthError(error.message, 409); throw error; }
    this.users.set(row.id, row); return row;
  }
  /** End every session of an account. Returns how many ended. */
  revokeSessions(userId: string): number {
    let count = 0;
    for (const [id, session] of this.sessions) if (session.userId === userId) { this.sessions.delete(id); count++; }
    return count;
  }
  /** The accounts SCIM manages: the ones it created. Accounts from the team file or created by an owner are never listed. */
  scimAccounts(): TeamUserRow[] { return [...this.users.values()].filter(user => user.source === "scim" && !user.deleted); }
  scimAccount(id: string): TeamUserRow | undefined { const user = this.users.get(id); return user && user.source === "scim" && !user.deleted ? user : undefined; }
  /** Create an account for a person the identity provider assigned. It has no password. */
  scimCreate(input: { userName: string; name: string; externalId: string | null; email: string | null; active: boolean }): TeamUserRow {
    if (this.atMemberLimit()) throw new TeamAuthError("Workspace member limit reached", 409);
    const taken = [...this.users.values()].some(user => !user.deleted && user.source === "scim" && user.userName?.toLowerCase() === input.userName.toLowerCase());
    if (taken) throw new TeamAuthError("userName is already in use", 409);
    return this.store({ id: `scim-${randomBytes(10).toString("hex")}`, name: input.name, role: this.config?.scim?.defaultRole ?? "viewer", roleSource: "group", scopeJson: null, active: input.active, deleted: false, userName: input.userName, externalId: input.externalId, email: input.email, oidcIssuer: null, passwordHash: null, oidcSub: null, source: "scim", createdAt: "", updatedAt: "" });
  }
  /** Change the profile of a SCIM account. Ending the sessions of a disabled account is the caller's step. */
  scimUpdate(id: string, change: { name?: string; active?: boolean; deleted?: boolean; userName?: string; externalId?: string | null; email?: string | null }): TeamUserRow {
    const user = this.users.get(id);
    if (!user) throw new TeamAuthError("No such account", 404);
    if (change.userName !== undefined && [...this.users.values()].some(row => row.id !== id && !row.deleted && row.source === "scim" && row.userName?.toLowerCase() === change.userName!.toLowerCase())) throw new TeamAuthError("userName is already in use", 409);
    const next = this.table?.updateProfile(id, change) ?? { ...user, ...change, name: change.name ?? user.name, active: change.active ?? user.active, deleted: change.deleted ?? user.deleted, userName: change.userName ?? user.userName, externalId: change.externalId === undefined ? user.externalId : change.externalId, email: change.email === undefined ? user.email : change.email };
    this.users.set(id, next);
    return next;
  }
  /** True when taking this account away would leave nobody able to manage users. */
  isLastManager(id: string): boolean {
    const manages = (user: TeamUserRow) => user.active && !user.deleted && Boolean(this.roles.get(user.role)?.permissions.includes("users.manage"));
    const user = this.users.get(id);
    return Boolean(user && manages(user) && ![...this.users.values()].some(other => other.id !== id && manages(other)));
  }
  /**
   * Set the role of SCIM accounts from their SCIM groups: the first group in scim.groupRoles that holds the account, or
   * scim.defaultRole (viewer). Accounts an owner set by hand keep their role. Returns the changes, for the audit log.
   */
  applyScimGroupRoles(): TeamRoleChange[] {
    const groups = this.scimTable?.listGroups() ?? [];
    const mapping = Object.entries(this.config?.scim?.groupRoles ?? {});
    const planned: Array<{ user: TeamUserRow; wanted: string }> = [];
    for (const user of this.scimAccounts()) {
      if (user.roleSource !== "group") continue;
      const wanted = mapping.find(([name]) => groups.some(group => group.displayName === name && group.memberIds.includes(user.id)))?.[1] ?? this.config?.scim?.defaultRole ?? "viewer";
      if (wanted !== user.role) planned.push({ user, wanted });
    }
    // A group change may never leave the workspace without an account that can manage users.
    const manages = (user: TeamUserRow, role: string) => user.active && !user.deleted && Boolean(this.roles.get(role)?.permissions.includes("users.manage"));
    const demoted = new Map(planned.map(({ user, wanted }) => [user.id, wanted]));
    const hadManager = [...this.users.values()].some(user => manages(user, user.role));
    const keepsManager = [...this.users.values()].some(user => manages(user, demoted.get(user.id) ?? user.role));
    if (hadManager && !keepsManager) throw new TeamAuthError("This change would leave nobody able to manage users, so it was refused", 409);
    const changes: TeamRoleChange[] = [];
    for (const { user, wanted } of planned) {
      this.table?.updateAccess(user.id, { role: wanted });
      this.users.set(user.id, { ...user, role: wanted });
      changes.push({ userId: user.id, old: user.role, new: wanted, source: "scim-group" });
    }
    return changes;
  }
  /** Throws unless a new account may get this role: it exists, is not owner, and is licensed when it is not one of the three free roles. */
  assertAssignableRole(role: string): void {
    if (!this.roles.has(role) || role === "owner") throw new TeamAuthError("Unknown role", 400);
    if (!FREE_ROLES.has(role) && !hasFeature("rbac")) throw new TeamAuthError(NEEDS_LICENSE, 403);
  }
  /** Called only after an owner-authorized member has been durably persisted. */
  addMember(input: { id: string; name: string; role: string; passwordHash: string }): TeamIdentity {
    if (!this.config) throw new TeamAuthError("Team sign-in is not configured", 404);
    const member = userSchema.extend({ passwordHash: z.string() }).parse(input);
    this.assertAssignableRole(member.role);
    if (!validHash(member.passwordHash)) throw new TeamAuthError("Invalid password hash", 400);
    if (this.users.has(member.id)) throw new TeamAuthError("That account ID already exists", 409);
    if (this.atMemberLimit()) throw new TeamAuthError("Workspace member limit reached", 409);
    // The file snapshot follows the file (it backs the compare-and-swap digest); the database holds the account.
    this.store({ ...fileRow(member), source: "local" });
    this.config.users.push(member);
    return this.lookupUser(member.id)!;
  }
  resolveSessionId(id: string | undefined): TeamIdentity | null {
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session || session.expires <= this.now()) { this.sessions.delete(id); return null; }
    return this.lookupUser(session.userId, session.role);
  }
  resolveSession(req: Pick<IncomingMessage, "headers">): TeamIdentity | null { return this.resolveSessionId(getSessionId(req)); }
  status(req: Pick<IncomingMessage, "headers">) {
    return { enabled: this.enabled, ...(this.config ? { workspace: this.config.workspace } : {}), user: this.resolveSession(req), sso: !!this.config?.oidc, ...(this.saml ? { saml: true } : {}) };
  }
  private issueSession(userId: string, role?: string) {
    for (const [id, session] of this.sessions) if (session.expires <= this.now()) this.sessions.delete(id);
    if (this.sessions.size >= 10000) throw new TeamAuthError("Session capacity reached", 503);
    const sessionId = opaque(); this.sessions.set(sessionId, { userId, expires: this.now() + SESSION_MS, ...(role ? { role } : {}) });
    return { sessionId, user: this.lookupUser(userId, role)!, setCookie: this.cookie(COOKIE, sessionId, SESSION_MS / 1000) };
  }
  async login(input: unknown, rateKey = "local") {
    if (!this.config) throw new TeamAuthError("Team sign-in is not configured", 404);
    const parsed = z.object({ userId: z.string().min(1).max(160), password: z.string().min(1).max(1024) }).strict().safeParse(input);
    if (!parsed.success) throw new TeamAuthError("User ID and password are required", 400);
    // Rate key must come from the server socket, never a request identity or forwarding header.
    const key = rateKey;
    for (const [id, row] of this.attempts) if (row.expires <= this.now()) this.attempts.delete(id);
    const attempt = this.attempts.get(key) ?? { count: 0, expires: this.now() + 60_000 };
    if (attempt.count >= 10 || this.attempts.size >= 10000) throw new TeamAuthError("Too many sign-in attempts; try again shortly", 429);
    attempt.count++; this.attempts.set(key, attempt);
    const user = this.users.get(parsed.data.userId);
    const matches = await passwordMatches(parsed.data.password, user?.passwordHash ?? await this.dummyHash);
    if (!user?.passwordHash || !user.active || user.deleted || !matches) throw new TeamAuthError("Invalid user ID or password");
    return this.issueSession(user.id);
  }
  logout(req: Pick<IncomingMessage, "headers">): { setCookie: string } {
    const id = getSessionId(req); if (id) this.sessions.delete(id);
    return { setCookie: this.cookie(COOKIE, "", 0) };
  }
  private requireProviderURL(value: string): URL {
    const url = new URL(value);
    if (url.username || url.password || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) throw new Error("OIDC endpoints require HTTPS (HTTP is allowed only on loopback)");
    return url;
  }
  private async getDiscovery(): Promise<Discovery> {
    if (this.discovery) return this.discovery;
    const oidc = this.config?.oidc; if (!oidc) throw new TeamAuthError("SSO is not configured", 404);
    const response = await fetch(`${oidc.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000), redirect: "error" });
    if (!response.ok) throw new TeamAuthError("SSO provider is unavailable", 502);
    const data = z.object({ issuer: z.string(), authorization_endpoint: z.string().url(), token_endpoint: z.string().url(), jwks_uri: z.string().url() }).parse(await response.json());
    if (data.issuer !== oidc.issuer) throw new TeamAuthError("SSO provider issuer does not match", 502);
    for (const endpoint of [data.authorization_endpoint, data.token_endpoint, data.jwks_uri]) this.requireProviderURL(endpoint);
    this.discovery = data; this.keys = createRemoteJWKSet(new URL(data.jwks_uri)); return data;
  }
  async beginSSO(): Promise<{ url: string; setCookie: string }> {
    const discovery = await this.getDiscovery(); const oidc = this.config!.oidc!;
    for (const [id, pending] of this.pending) if (pending.expires <= this.now()) this.pending.delete(id);
    if (this.pending.size >= 1000) throw new TeamAuthError("Too many pending sign-ins", 429);
    const state = opaque(), nonce = opaque(), verifier = opaque(), browser = opaque();
    this.pending.set(state, { nonce, verifier, browser, expires: this.now() + SSO_MS });
    const url = new URL(discovery.authorization_endpoint);
    for (const [key, value] of Object.entries({ response_type: "code", scope: "openid profile", client_id: oidc.clientId, redirect_uri: oidc.redirectUri, state, nonce, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" })) url.searchParams.set(key, value);
    return { url: url.href, setCookie: this.cookie(SSO_COOKIE, browser, SSO_MS / 1000) };
  }
  /**
   * An account SCIM created has no OIDC subject yet. The first sign-in links it, but only on proof: the ID token must say the
   * email is verified (email_verified is exactly true), the email must match the account's userName or email, and exactly
   * one unlinked account may match. Nothing else links: not an unverified email, not preferred_username, and never an
   * account that already belongs to another subject. After the link, only the subject and issuer match.
   */
  private linkScimAccount(issuer: string, claims: Record<string, unknown>): TeamUserRow | undefined {
    if (claims.email_verified !== true || typeof claims.email !== "string" || claims.email.trim() === "" || typeof claims.sub !== "string" || claims.sub === "") return undefined;
    const email = claims.email.trim().toLowerCase();
    const candidates = [...this.users.values()].filter(row => row.source === "scim" && row.active && !row.deleted && !row.oidcSub && [row.userName, row.email].some(value => value?.toLowerCase() === email));
    if (candidates.length !== 1) return undefined;
    const found = candidates[0]!;
    try {
      const next = this.table?.updateProfile(found.id, { oidcSub: claims.sub, oidcIssuer: issuer }) ?? { ...found, oidcSub: claims.sub, oidcIssuer: issuer };
      this.users.set(found.id, next);
      return next;
    } catch { return undefined; } // the subject already belongs to another account
  }
  /** Create the account for a verified OIDC subject. The ID is derived from the subject, so it cannot collide with a local account ID. */
  private provisionOidcUser(issuer: string, claims: { sub?: string; name?: unknown; preferred_username?: unknown; email?: unknown }, role: string, roleSource: "admin" | "group"): TeamUserRow {
    const sub = claims.sub!;
    const id = sub.length <= 120 ? `oidc:${sub}` : `oidc:${createHash("sha256").update(sub).digest("hex").slice(0, 48)}`;
    const label = [claims.name, claims.preferred_username, claims.email].find((value): value is string => typeof value === "string" && value.trim() !== "");
    const name = (label ?? sub).replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 160) || "SSO user";
    return this.store({ id, name, role, roleSource, scopeJson: null, active: true, deleted: false, userName: null, externalId: null, email: null, oidcIssuer: issuer, passwordHash: null, oidcSub: sub, source: "oidc", createdAt: "", updatedAt: "" });
  }
  async callback(params: URLSearchParams, req: Pick<IncomingMessage, "headers">) {
    const state = params.get("state") ?? ""; const pending = this.pending.get(state);
    const browser = parseCookies(req.headers.cookie)[SSO_COOKIE];
    if (!pending || pending.expires <= this.now() || browser !== pending.browser) throw new TeamAuthError("Invalid or expired SSO sign-in");
    this.pending.delete(state); // Consume even if exchange or verification fails; never permit replay.
    const code = params.get("code"); if (!code || params.has("error")) throw new TeamAuthError("SSO sign-in was not completed");
    const discovery = await this.getDiscovery(); const oidc = this.config!.oidc!;
    const body = new URLSearchParams({ grant_type: "authorization_code", code, client_id: oidc.clientId, redirect_uri: oidc.redirectUri, code_verifier: pending.verifier });
    if (oidc.clientSecretEnv) body.set("client_secret", process.env[oidc.clientSecretEnv]!);
    const response = await fetch(discovery.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body, signal: AbortSignal.timeout(10_000), redirect: "error" });
    if (!response.ok) throw new TeamAuthError("SSO code exchange failed");
    const tokens = z.object({ id_token: z.string().max(32_000) }).passthrough().parse(await response.json());
    let payload;
    try { ({ payload } = await jwtVerify(tokens.id_token, this.keys!, { issuer: oidc.issuer, audience: oidc.clientId, algorithms: ["RS256", "ES256"], requiredClaims: ["exp", "iat", "sub", "nonce"], currentDate: new Date(this.now()), maxTokenAge: "10 minutes" })); }
    catch { throw new TeamAuthError("SSO identity verification failed"); }
    if (payload.nonce !== pending.nonce || (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== oidc.clientId)) throw new TeamAuthError("SSO identity verification failed");
    let user = [...this.users.values()].find(row => row.oidcSub === payload.sub && (!row.oidcIssuer || row.oidcIssuer === oidc.issuer));
    // An account SCIM created has no OIDC subject yet. The first sign-in links it when the verified email or username matches.
    if (!user && hasFeature("scim")) user = this.linkScimAccount(oidc.issuer, payload as Record<string, unknown>);
    if (user && (!user.active || user.deleted)) throw new TeamAuthError("This account has been disabled by your administrator", 403);
    let provisioned = false;
    // Group mapping is a paid feature. The role comes from the first mapped group the user is in.
    const groupRoles = hasFeature("rbac") ? oidc.groupRoles : undefined;
    const mappedRole = roleFromGroups((payload as Record<string, unknown>)[oidc.groupsClaim ?? "groups"], groupRoles);
    let roleChange: TeamRoleChange | undefined;
    if (!user && oidc.jit) {
      // Account creation on first sign-in is a paid feature. Without the license the sign-in stays "not a member".
      if (!hasFeature("rbac")) throw new TeamAuthError(`This SSO account is not a workspace member. Automatic account creation is set up, but ${NEEDS_LICENSE}`, 403);
      if (this.atMemberLimit()) throw new TeamAuthError("Workspace member limit reached", 409);
      user = this.provisionOidcUser(oidc.issuer, payload, mappedRole ?? oidc.jit.role, groupRoles ? "group" : "admin"); provisioned = true;
    }
    // An account whose role came from the groups follows the groups at every sign-in. An account an administrator set stays as set.
    if (user && !provisioned && groupRoles && user.roleSource === "group") {
      const wanted = mappedRole ?? oidc.jit?.role ?? "viewer";
      if (wanted !== user.role) {
        roleChange = { userId: user.id, old: user.role, new: wanted, source: "oidc-group" };
        this.table?.updateAccess(user.id, { role: wanted });
        user = { ...user, role: wanted }; this.users.set(user.id, user);
      }
    }
    if (!user) throw new TeamAuthError("This SSO account is not a workspace member", 403);
    const session = this.issueSession(user.id);
    return { ...session, provisioned, ...(roleChange ? { roleChange } : {}), setCookies: [session.setCookie, this.cookie(SSO_COOKIE, "", 0)], redirect: "/" };
  }
  // SAML sign-in (enterprise license). The checks live in team-saml.ts and the enterprise package.
  private requireSaml(): TeamSaml { if (!this.saml) throw new TeamAuthError("SAML sign-in is not configured", 404); return this.saml; }
  beginSAML(client = "") { return this.requireSaml().begin(client); }
  samlAcs(form: { SAMLResponse?: unknown; RelayState?: unknown }) { return this.requireSaml().acs(form); }
  samlMetadata() { return this.requireSaml().metadata(); }
  samlComplete(ticket: string | null, req: Pick<IncomingMessage, "headers">) {
    const done = this.requireSaml().complete(ticket, req);
    const session = this.issueSession(done.userId, done.role);
    return { ...session, setCookies: [session.setCookie, done.clearCookie], redirect: "/" };
  }
}
