// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// The permission every API route needs. First matching rule wins. A route with no rule is refused for
// every role, so a new route has to be added here before anyone can call it on a licensed server.
// The rules describe the same decisions as the three-role regex table in team-web.ts: owner can do
// everything, editor can work and triage, viewer can read.
import type { Permission } from "./permissions.js";

/** `session`: needs only a signed-in account. The route checks the rest itself. */
export type RoutePermission = Permission | "session";

interface Rule { methods: "read" | "write" | "any"; pattern: RegExp; permission: RoutePermission }

const rule = (methods: Rule["methods"], pattern: RegExp, permission: RoutePermission): Rule => ({ methods, pattern, permission });

// Console areas (the part after /api/console/). Reading any of them is workspace.read unless a rule says otherwise.
const CONSOLE_READ_AREAS = [
  "sessions", "saved", "search", "workflows", "workflow-definitions", "workflow-executions", "workflow-triggers", "sentinels", "sentinel-presets",
  "extensions", "skills", "github", "connections", "providers", "models", "settings", "doctor", "update-status", "tools", "project",
  "checks", "execution", "instructions", "self-edit", "diagnostics", "remote-sessions", "provider-relays", "repositories", "events",
  "update", "feedback", "credentials", "auth", "plugins", "mcp", "services", "processes", "environment", "learning",
];
// Console areas whose writes are work: start and continue threads, run and edit automations.
const CONSOLE_WORK_AREAS = ["sessions", "workflows", "workflow-definitions", "workflow-executions", "workflow-triggers"];
// Console areas whose writes change the engine, its credentials or the host. Owner only.
const CONSOLE_ADMIN_AREAS = CONSOLE_READ_AREAS.filter((area) => !CONSOLE_WORK_AREAS.includes(area));

const alt = (names: readonly string[]) => names.map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");

export const ROUTE_RULES: readonly Rule[] = [
  // Team routes check the signed-in account and their own permission inside the handler.
  rule("any", /^\/api\/team\//, "session"),

  // Reading the audit log.
  rule("read", /^\/api\/console\/audit-log$/, "audit.read"),
  rule("write", /^\/api\/console\/audit-log$/, "settings.write"),

  // Cost and host-receipt administration remain owner-only; handlers also enforce the signed-in role.
  rule("read", /^\/api\/console\/run-metrics$/, "settings.write"),
  rule("write", /^\/api\/console\/run-metrics\/refresh-host$/, "settings.write"),

  // Findings.
  rule("read", /^\/api\/(?:dashboard|scans|findings|finding-family|findings-server|events)(?:\/|$)/, "findings.read"),
  rule("write", /^\/api\/(?:findings|finding-family)(?:\/|$)/, "findings.triage"),

  // Settings that belong to the owner, before the general work rules below.
  rule("write", /^\/api\/skills\/mounts(?:\/|$)/, "settings.write"),
  rule("write", /^\/api\/console\/saved\/[^/]+\/resume$/, "threads.run"),

  // Work: skills, engagements, threads and automations.
  rule("write", /^\/api\/(?:skills|engagements)(?:\/|$)/, "threads.run"),
  rule("write", new RegExp(`^/api/console/(?:${alt(CONSOLE_WORK_AREAS)})(?:/|$)`), "threads.run"),

  // Engine, host and credential administration.
  rule("write", /^\/api\/(?:control|workflow-engine|workers|work|backends|backend|findings-access|v1)(?:\/|$)/, "settings.write"),
  rule("write", new RegExp(`^/api/console/(?:${alt(CONSOLE_ADMIN_AREAS)})(?:/|$)`), "settings.write"),

  // The app shell asks which engine it is talking to before it shows anything, so every signed-in role needs these.
  rule("read", /^\/api\/(?:backends|backends\/local\/handshake|backend\/handshake)$/, "session"),

  // Everything else that can be read.
  rule("read", /^\/api\/(?:work|skills|engagements|backends|backend|findings-access|workers|workflow-engine|control|v1)(?:\/|$)/, "workspace.read"),
  rule("read", new RegExp(`^/api/console/(?:${alt(CONSOLE_READ_AREAS)})(?:/|$)`), "workspace.read"),
];

/** The permission a request needs, or null when no rule covers it (the request is then refused). */
export function routePermission(method: string, pathname: string): RoutePermission | null {
  const kind: "read" | "write" = method === "GET" || method === "HEAD" ? "read" : "write";
  for (const entry of ROUTE_RULES) {
    if ((entry.methods === "any" || entry.methods === kind) && entry.pattern.test(pathname)) return entry.permission;
  }
  return null;
}

export type RouteDecision =
  | { allowed: true }
  | { allowed: false; code: "forbidden"; permission: RoutePermission }
  | { allowed: false; code: "no_permission_defined" };

export function decideRoute(permissions: readonly string[], method: string, pathname: string): RouteDecision {
  const needed = routePermission(method, pathname);
  if (needed === null) return { allowed: false, code: "no_permission_defined" };
  if (needed === "session" || permissions.includes(needed)) return { allowed: true };
  return { allowed: false, code: "forbidden", permission: needed };
}
