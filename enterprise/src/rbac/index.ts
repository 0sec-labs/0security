// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
export { BUILT_IN_ROLES, PERMISSIONS, ROLE_NAME, nearestBuiltInRole, parseScope, resolveRoles, scopePatterns } from "./permissions.js";
export type { Permission, RoleDefinition, RoleScope } from "./permissions.js";
export { ROUTE_RULES, decideRoute, routePermission } from "./routes.js";
export type { RouteDecision, RoutePermission } from "./routes.js";
export { repoMatches, repoOfTarget, targetFilter } from "./scope.js";
export { roleFromGroups } from "./groups.js";
