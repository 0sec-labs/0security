// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Roles are named sets of permissions. The five built-in roles are fixed. A server can add custom roles
// in its team configuration. Pure functions: no I/O, no network, no license check (the call site checks).

/** What a role can be granted. Every API route needs exactly one of these (see routes.ts). */
export const PERMISSIONS = [
  "workspace.read", // read threads, automations, skills, settings views and the rest of the workspace
  "findings.read", // read findings, scans and the findings dashboard
  "findings.triage", // change the triage status, assignee or impact notes of a finding
  "threads.run", // start and continue threads, run automations, add skills, create reports
  "settings.write", // change engine settings, connections, extensions, mounts and API keys
  "audit.read", // read the audit log
  "users.manage", // add accounts, change roles and scope
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/** Limits findings to some repositories. Business units name groups of repositories in the team configuration. */
export interface RoleScope {
  repos?: string[];
  businessUnits?: string[];
}

export interface RoleDefinition {
  permissions: Permission[];
  scope?: RoleScope;
}

/**
 * The three roles that exist without a license keep their exact meaning: owner can do everything,
 * editor can work, viewer can read. `triager` and `auditor` are new.
 */
export const BUILT_IN_ROLES: Readonly<Record<string, RoleDefinition>> = Object.freeze({
  owner: { permissions: [...PERMISSIONS] },
  editor: { permissions: ["workspace.read", "findings.read", "findings.triage", "threads.run"] },
  viewer: { permissions: ["workspace.read", "findings.read"] },
  triager: { permissions: ["workspace.read", "findings.read", "findings.triage"] },
  auditor: { permissions: ["findings.read", "audit.read"] },
});

export const ROLE_NAME = /^[a-z][a-z0-9_-]{0,63}$/;
const PATTERN = /^[A-Za-z0-9._*-]+(?:\/[A-Za-z0-9._*-]+)?$/;

function isPermission(value: unknown): value is Permission {
  return typeof value === "string" && (PERMISSIONS as readonly string[]).includes(value);
}

function validScope(value: unknown, where: string): RoleScope | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${where}: scope must be an object`);
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) if (key !== "repos" && key !== "businessUnits") throw new Error(`${where}: unknown scope field "${key}"`);
  const out: RoleScope = {};
  for (const key of ["repos", "businessUnits"] as const) {
    const list = raw[key];
    if (list === undefined) continue;
    if (!Array.isArray(list) || list.length > 200 || !list.every((item) => typeof item === "string" && PATTERN.test(item) && item.length <= 200)) {
      throw new Error(`${where}: scope.${key} must be a list of repository patterns like "org/repo" or "org/*"`);
    }
    out[key] = [...list] as string[];
  }
  return out;
}

/** Check a scope value from a role or an account. Throws a plain message on bad input. */
export function parseScope(value: unknown, where = "scope"): RoleScope | undefined {
  return validScope(value, where);
}

/** Built-in roles plus the custom roles of the team configuration. A custom role cannot reuse a built-in name. */
export function resolveRoles(custom?: unknown): Map<string, RoleDefinition> {
  const roles = new Map<string, RoleDefinition>(Object.entries(BUILT_IN_ROLES).map(([name, role]) => [name, { ...role, permissions: [...role.permissions] }]));
  if (custom === undefined) return roles;
  if (custom === null || typeof custom !== "object" || Array.isArray(custom)) throw new Error("roles must be an object");
  const entries = Object.entries(custom as Record<string, unknown>);
  if (entries.length > 100) throw new Error("roles: at most 100 custom roles");
  for (const [name, raw] of entries) {
    if (!ROLE_NAME.test(name)) throw new Error(`roles: "${name}" is not a valid role name (lowercase letters, digits, - and _)`);
    if (Object.prototype.hasOwnProperty.call(BUILT_IN_ROLES, name)) throw new Error(`roles: "${name}" is a built-in role and cannot be redefined`);
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`roles.${name}: must be an object`);
    const def = raw as Record<string, unknown>;
    for (const key of Object.keys(def)) if (key !== "permissions" && key !== "scope") throw new Error(`roles.${name}: unknown field "${key}"`);
    if (!Array.isArray(def.permissions) || !def.permissions.every(isPermission)) throw new Error(`roles.${name}.permissions must be a list of: ${PERMISSIONS.join(", ")}`);
    const scope = validScope(def.scope, `roles.${name}`);
    roles.set(name, { permissions: [...new Set(def.permissions as Permission[])], ...(scope ? { scope } : {}) });
  }
  return roles;
}

/** The nearest of the three free roles. Code that only knows owner, editor and viewer uses this. */
export function nearestBuiltInRole(permissions: readonly Permission[]): "owner" | "editor" | "viewer" {
  if (permissions.includes("settings.write")) return "owner";
  if (permissions.includes("threads.run")) return "editor";
  return "viewer";
}

/**
 * Business units name groups of repositories: `{ "payments": ["acme/pay-*"] }`. Returns the patterns a scope
 * allows, or null when there is no scope (everything). A business unit that is not defined allows nothing.
 */
export function scopePatterns(scope: RoleScope | undefined, businessUnits: Readonly<Record<string, readonly string[]>> | undefined): string[] | null {
  if (!scope || (!scope.repos && !scope.businessUnits)) return null;
  const patterns = [...(scope.repos ?? [])];
  for (const unit of scope.businessUnits ?? []) patterns.push(...(businessUnits?.[unit] ?? []));
  return patterns;
}
