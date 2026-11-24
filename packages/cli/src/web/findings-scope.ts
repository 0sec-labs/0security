import { targetFilter } from "../enterprise-bridge.js";
import type { TeamIdentity } from "./team-auth.js";

/** Tells whether a scan target is inside an account's repository scope. */
export type TargetFilter = (target: string) => boolean;

/** The filter for a signed-in account, or undefined when the account has no scope. Applies with or without a license. */
export function scopeFilterFor(member: Pick<TeamIdentity, "scope"> | null | undefined): TargetFilter | undefined {
  return member?.scope ? targetFilter(member.scope) : undefined;
}

// Routes that return findings data this change does not filter. A scoped account is refused on them.
const UNFILTERED_FINDINGS_ROUTES: readonly RegExp[] = [
  /^\/api\/work(?:\/|$)/,
  /^\/api\/findings-server(?:\/|$)/,
  /^\/api\/engagements(?:\/|$)/,
  /^\/api\/findings\/export$/,
  /^\/api\/scans\/[^/]+\/export$/,
  /^\/api\/findings\/[^/]+\/impact-assessment$/,
  /^\/api\/v1\/presentation\/events$/,
];

export function scopedRouteDenied(pathname: string): boolean {
  return UNFILTERED_FINDINGS_ROUTES.some(pattern => pattern.test(pathname));
}

/** Keep only the parts of the dashboard summary that belong to in-scope scans. Anything not tied to a scan is dropped. */
export function scopeDashboardBody<T extends { scans: Array<{ id: string; target: string }>; cases: Array<{ target: string }>; groups: Array<{ latest: { scanId?: string }; sourceScanIds?: string[] }>; workers: unknown[] }>(body: T, scope: TargetFilter): T {
  const scans = body.scans.filter(scan => scope(scan.target));
  const allowed = new Set(scans.map(scan => scan.id));
  return {
    ...body, scans,
    cases: body.cases.filter(item => scope(item.target)),
    // A family is shown only when every scan that holds it is in scope, as on the detail route. Its counts and scan ids
    // span all its scans, so a family that also occurs elsewhere would reveal that other place.
    groups: body.groups.filter(group => group.latest.scanId !== undefined && allowed.has(group.latest.scanId) && (group.sourceScanIds ?? []).every(id => allowed.has(id))),
    workers: [],
  };
}
