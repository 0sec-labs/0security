// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Map the groups an identity provider reports to a role.

/**
 * The role for the first entry of `mapping` (in the order the operator wrote it) whose group the user is in.
 * `groups` is the value of the groups claim: a list of names, or a single name. Null when nothing matches.
 */
export function roleFromGroups(groups: unknown, mapping: Readonly<Record<string, string>> | undefined): string | null {
  if (!mapping) return null;
  const present = new Set<string>();
  if (typeof groups === "string") present.add(groups);
  else if (Array.isArray(groups)) for (const group of groups.slice(0, 1000)) if (typeof group === "string") present.add(group);
  for (const [group, role] of Object.entries(mapping)) if (present.has(group)) return role;
  return null;
}
