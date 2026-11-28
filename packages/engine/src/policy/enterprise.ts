/**
 * Enterprise no-egress mode.
 *
 * `ZERO_NO_EGRESS=1` (alias: `ZERO_ENTERPRISE=1`; it is a no-egress switch, not a license) keeps every automatic third-party network call off,
 * including anonymous telemetry, lifecycle events and crash reports. The only
 * outbound traffic left is to hosts the operator
 * configured themselves: the model endpoint, a team sign-in issuer, a scan or
 * probe target they named, a remote MCP server they added.
 *
 * The switch is read from the process environment only. Project files
 * (`.0/tui-settings.json`, `.0/config`) have no path to the environment, so a
 * checked-out repository cannot turn it off.
 *
 * This module is a leaf on purpose: it imports nothing, so any directory may
 * import it without adding an edge to the engine import-cycle baseline.
 * See docs/src/content/docs/data-flow.md and `egress-inventory.json`.
 */

/** The preferred name of the no-egress switch. */
export const NO_EGRESS_ENV = "ZERO_NO_EGRESS";
/** The original name. Still honoured, identically, as an alias of {@link NO_EGRESS_ENV}. */
export const ENTERPRISE_ENV = "ZERO_ENTERPRISE";
/** Both names, preferred first. */
export const NO_EGRESS_ENV_NAMES = [NO_EGRESS_ENV, ENTERPRISE_ENV] as const;

function switchedOn(raw: string | undefined): boolean {
  const value = raw?.trim().toLowerCase();
  return value !== undefined && value !== "" && value !== "0" && value !== "false" && value !== "no";
}

/** Set and not explicitly falsy ("", "0", "false", "no") counts as on. Fail closed. */
export function enterpriseMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return NO_EGRESS_ENV_NAMES.some(name => switchedOn(env[name]));
}

export class EnterpriseEgressError extends Error {
  readonly destination: string;
  constructor(destination: string) {
    super(`Blocked by ${NO_EGRESS_ENV} (or its alias ${ENTERPRISE_ENV}): this would contact ${destination}. Unset ${NO_EGRESS_ENV} and ${ENTERPRISE_ENV} to allow it.`);
    this.name = "EnterpriseEgressError";
    this.destination = destination;
  }
}

/** Throw when enterprise mode forbids contacting `destination` (a host or short description). */
export function assertEgressAllowed(destination: string, env: NodeJS.ProcessEnv = process.env): void {
  if (enterpriseMode(env)) throw new EnterpriseEgressError(destination);
}
