import { randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { z } from "zod";
import { SamlError, SamlServiceProvider, parseIdpMetadata, samlLicenseDenial, type SamlIdentity } from "../enterprise-bridge.js";
import { readIdpMetadataXml } from "./saml-metadata.js";
import { TeamAuthError } from "./team-auth-error.js";
import { SAML_ACS_PATH } from "./team-sso-routes.js";

export const SAML_COOKIE = "zero_team_saml";
const COOKIE_MS = 10 * 60 * 1000;
const TICKET_MS = 60 * 1000;
const METADATA_REFRESH_MS = 12 * 60 * 60 * 1000;
/** A role name: owner, editor, viewer, or any role the workspace defines. */
type Role = string;
const RANK: Record<string, number> = { viewer: 0, editor: 1, owner: 2 };

export const samlConfigSchema = z.object({
  entityId: z.string().min(1).max(512),
  acsUrl: z.string().url(),
  metadataUrl: z.string().url().optional(),
  metadataFile: z.string().min(1).max(1024).optional(),
  groupAttribute: z.string().min(1).max(512).optional(),
  groupRoles: z.record(z.string().min(1).max(512), z.string().min(1).max(64)).optional(),
  requireSignature: z.enum(["assertion", "either"]).optional(),
  clockSkewSeconds: z.number().int().min(0).max(300).optional(),
}).strict().refine(c => Number(!!c.metadataUrl) + Number(!!c.metadataFile) === 1, { message: "Set exactly one of metadataUrl and metadataFile" })
  .refine(c => Boolean(c.groupAttribute) === Boolean(c.groupRoles && Object.keys(c.groupRoles).length > 0), { message: "groupAttribute and groupRoles go together" });
export type SamlConfig = z.infer<typeof samlConfigSchema>;

/** Checks that need no license and no network, run when the team config loads. */
export function validateSamlConfig(config: SamlConfig, origin: string): void {
  const acs = new URL(config.acsUrl);
  if (acs.origin !== origin) throw new Error("SAML acsUrl must use this engine origin");
  if (acs.pathname !== SAML_ACS_PATH || acs.search || acs.hash) throw new Error(`SAML acsUrl must be ${SAML_ACS_PATH}`);
  if (config.metadataUrl) {
    const url = new URL(config.metadataUrl);
    if (url.username || url.password || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) {
      throw new Error("SAML metadataUrl requires HTTPS (HTTP is allowed only on loopback)");
    }
  }
  if (config.metadataFile && !/^(?:\/|[A-Za-z]:[\\/])/.test(config.metadataFile)) throw new Error("SAML metadataFile must be an absolute path");
}

export interface TeamSamlDeps {
  now: () => number;
  cookie: (name: string, value: string, seconds: number) => string;
  /** The workspace member whose configured `samlNameId` equals this NameID. */
  findMember: (nameId: string) => { id: string; role: Role } | undefined;
  /** How much a role can do, to pick the highest one among a person's groups. Defaults to viewer < editor < owner. */
  roleRank?: (role: Role) => number;
  /** Test seam for the provider; production builds it from the metadata. */
  createProvider?: (config: SamlConfig) => Promise<SamlServiceProvider>;
}

function parseCookie(header: string | undefined, name: string): string | undefined {
  let found: string | undefined; let seen = 0;
  for (const part of (header ?? "").split(";")) {
    const at = part.indexOf("="); if (at < 0 || part.slice(0, at).trim() !== name) continue;
    seen++; found = part.slice(at + 1).trim();
  }
  return seen === 1 ? found : undefined; // a duplicated cookie is never trusted
}

/** Highest role among the groups the identity provider asserted, or undefined when none is mapped. */
export function roleFromGroups(groups: readonly string[], map: Readonly<Record<string, Role>>, rank: (role: Role) => number = role => RANK[role] ?? 0): Role | undefined {
  let best: Role | undefined;
  for (const group of groups) {
    if (!Object.hasOwn(map, group)) continue;
    const role = map[group]!;
    if (best === undefined || rank(role) > rank(best)) best = role;
  }
  return best;
}

/**
 * Glue between the team sign-in and the licensed SAML service provider.
 * Flow: begin (redirect to the identity provider, browser cookie set) -> the identity provider posts to the ACS
 * (cross-site, so no session cookie travels) -> the response is checked and a one-use ticket is issued ->
 * redirect to complete (a top-level GET, so the Lax browser cookie travels) -> the cookie must match the
 * one set at begin -> session. A response posted by an attacker's browser cannot sign a victim in.
 */
export class TeamSaml {
  private provider?: { value: Promise<SamlServiceProvider>; loaded: number };
  private readonly tickets = new Map<string, { userId: string; role: Role; binding: string; expires: number }>();

  constructor(readonly config: SamlConfig, private readonly deps: TeamSamlDeps) {}

  private requireLicense(): void {
    const denial = samlLicenseDenial();
    if (denial) throw new TeamAuthError(denial, 403, "not_licensed");
  }

  private service(): Promise<SamlServiceProvider> {
    this.requireLicense();
    const t = this.deps.now();
    if (!this.provider || (this.config.metadataUrl && t - this.provider.loaded > METADATA_REFRESH_MS)) {
      const value = (this.deps.createProvider ?? (async (config: SamlConfig) => new SamlServiceProvider({
        entityId: config.entityId, acsUrl: config.acsUrl, idp: parseIdpMetadata(await readIdpMetadataXml(config)),
        requireSignature: config.requireSignature, ...(config.clockSkewSeconds !== undefined ? { clockSkewMs: config.clockSkewSeconds * 1000 } : {}),
      })))(this.config);
      this.provider = { value, loaded: t };
      value.catch(() => { if (this.provider?.value === value) this.provider = undefined; }); // retry after a failed load
    }
    return this.provider.value;
  }

  private wrap(error: unknown): never {
    if (error instanceof TeamAuthError) throw error;
    if (error instanceof SamlError) {
      if (error.reason === "metadata" || error.reason === "config") throw new TeamAuthError("SAML sign-in is misconfigured", 500, error.reason);
      throw new TeamAuthError(error.statusCode === 429 ? error.message : "SAML sign-in failed", error.statusCode, error.reason);
    }
    throw error;
  }

  async begin(client = ""): Promise<{ url: string; setCookie: string }> {
    try {
      const sp = await this.service();
      const binding = randomBytes(32).toString("base64url");
      const { url } = await sp.begin(binding, client);
      return { url, setCookie: this.deps.cookie(SAML_COOKIE, binding, COOKIE_MS / 1000) };
    } catch (error) { return this.wrap(error); }
  }

  /** Check the posted response. Returns where to send the browser next; the session is issued there. */
  async acs(form: { SAMLResponse?: unknown; RelayState?: unknown }): Promise<{ redirect: string }> {
    let identity: SamlIdentity; let binding: string;
    try { ({ identity, binding } = await (await this.service()).consume(form)); } catch (error) { return this.wrap(error); }
    const member = this.deps.findMember(identity.nameId);
    if (!member) throw new TeamAuthError("This SSO account is not a workspace member", 403, "not_a_member");
    let role = member.role;
    if (this.config.groupAttribute && this.config.groupRoles) {
      const mapped = roleFromGroups(identity.attributes[this.config.groupAttribute] ?? [], this.config.groupRoles, this.deps.roleRank);
      if (!mapped) throw new TeamAuthError("This SSO account has no role in this workspace", 403, "no_mapped_group");
      role = mapped;
    }
    const t = this.deps.now();
    for (const [id, ticket] of this.tickets) if (ticket.expires <= t) this.tickets.delete(id);
    if (this.tickets.size >= 1000) throw new TeamAuthError("Too many pending sign-ins", 429, "pending_full");
    const ticket = randomBytes(32).toString("base64url");
    this.tickets.set(ticket, { userId: member.id, role, binding, expires: t + TICKET_MS });
    return { redirect: `${new URL(this.config.acsUrl).pathname.replace(/acs$/, "complete")}?ticket=${ticket}` };
  }

  /** Spend the ticket. The browser must be the one that began the sign-in. */
  complete(ticket: string | null, req: Pick<IncomingMessage, "headers">): { userId: string; role: Role; clearCookie: string } {
    const entry = ticket ? this.tickets.get(ticket) : undefined;
    if (ticket) this.tickets.delete(ticket);
    const cookie = parseCookie(req.headers.cookie, SAML_COOKIE);
    if (!entry || entry.expires <= this.deps.now() || cookie !== entry.binding) throw new TeamAuthError("Invalid or expired SSO sign-in", 401, "browser_mismatch");
    return { userId: entry.userId, role: entry.role, clearCookie: this.deps.cookie(SAML_COOKIE, "", 0) };
  }

  async metadata(): Promise<string> {
    try { return (await this.service()).metadataXml(); } catch (error) { return this.wrap(error); }
  }
}
