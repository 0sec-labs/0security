// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { describe, expect, it } from "vitest";
import { BUILT_IN_ROLES, PERMISSIONS, decideRoute, nearestBuiltInRole, repoMatches, repoOfTarget, resolveRoles, roleFromGroups, routePermission, scopePatterns, targetFilter } from "./index.js";

describe("roles", () => {
  it("has the three free roles and two new ones", () => {
    expect(Object.keys(BUILT_IN_ROLES)).toEqual(["owner", "editor", "viewer", "triager", "auditor"]);
    expect(BUILT_IN_ROLES.owner!.permissions).toEqual([...PERMISSIONS]);
    expect(BUILT_IN_ROLES.auditor!.permissions).toEqual(["findings.read", "audit.read"]);
    expect(BUILT_IN_ROLES.triager!.permissions).toContain("findings.triage");
    expect(BUILT_IN_ROLES.triager!.permissions).not.toContain("threads.run");
  });

  it("adds custom roles and refuses bad ones", () => {
    const roles = resolveRoles({ "payments-lead": { permissions: ["findings.read", "findings.triage"], scope: { repos: ["acme/pay-*"] } } });
    expect(roles.get("payments-lead")).toEqual({ permissions: ["findings.read", "findings.triage"], scope: { repos: ["acme/pay-*"] } });
    expect(() => resolveRoles({ owner: { permissions: [] } })).toThrow("built-in");
    expect(() => resolveRoles({ Bad: { permissions: [] } })).toThrow("valid role name");
    expect(() => resolveRoles({ ok: { permissions: ["root"] } })).toThrow("permissions must be");
    expect(() => resolveRoles({ ok: { permissions: [], extra: 1 } })).toThrow("unknown field");
    expect(() => resolveRoles({ ok: { permissions: [], scope: { repos: ["a b"] } } })).toThrow("repository patterns");
    expect(() => resolveRoles({ ok: { permissions: [], scope: { teams: [] } } })).toThrow("unknown scope field");
  });

  it("maps any permission set to the nearest free role without raising it", () => {
    expect(nearestBuiltInRole(BUILT_IN_ROLES.owner!.permissions)).toBe("owner");
    expect(nearestBuiltInRole(BUILT_IN_ROLES.editor!.permissions)).toBe("editor");
    expect(nearestBuiltInRole(BUILT_IN_ROLES.triager!.permissions)).toBe("viewer");
    expect(nearestBuiltInRole(BUILT_IN_ROLES.auditor!.permissions)).toBe("viewer");
    expect(nearestBuiltInRole(["users.manage", "audit.read"])).toBe("viewer");
  });
});

describe("scope", () => {
  it("finds the repository of a target", () => {
    expect(repoOfTarget("https://github.com/Acme/Pay-API.git")).toBe("acme/pay-api");
    expect(repoOfTarget("git@github.com:acme/web.git")).toBe("acme/web");
    expect(repoOfTarget("acme/web")).toBe("acme/web");
    expect(repoOfTarget("/home/me/web")).toBeNull();
    expect(repoOfTarget("./acme/web")).toBeNull();
    expect(repoOfTarget("https://example.com/acme/web")).toBeNull();
  });

  it("matches patterns within one path part", () => {
    expect(repoMatches("acme/pay-api", ["acme/pay-*"])).toBe(true);
    expect(repoMatches("acme/web", ["acme/pay-*"])).toBe(false);
    expect(repoMatches("acme/web", ["acme"])).toBe(true);
    expect(repoMatches("acme/web", ["other/*"])).toBe(false);
    expect(repoMatches("acme/a/b", ["acme/*"])).toBe(false);
  });

  it("expands business units and treats a missing scope as unrestricted", () => {
    expect(scopePatterns(undefined, {})).toBeNull();
    expect(scopePatterns({}, {})).toBeNull();
    expect(scopePatterns({ repos: ["a/b"], businessUnits: ["pay", "none"] }, { pay: ["acme/pay-*"] })).toEqual(["a/b", "acme/pay-*"]);
    expect(scopePatterns({ businessUnits: ["none"] }, {})).toEqual([]);
    expect(targetFilter(null)).toBeUndefined();
    const only = targetFilter(["acme/pay-*"])!;
    expect(only("https://github.com/acme/pay-api")).toBe(true);
    expect(only("https://github.com/acme/web")).toBe(false);
    expect(only("/local/path")).toBe(false);
    expect(targetFilter([])!("acme/web")).toBe(false);
  });
});

describe("groups", () => {
  it("picks the first mapping entry the user is in", () => {
    const mapping = { admins: "owner", triage: "triager", everyone: "viewer" };
    expect(roleFromGroups(["everyone", "triage"], mapping)).toBe("triager");
    expect(roleFromGroups("admins", mapping)).toBe("owner");
    expect(roleFromGroups(["nobody"], mapping)).toBeNull();
    expect(roleFromGroups(undefined, mapping)).toBeNull();
    expect(roleFromGroups(["admins"], undefined)).toBeNull();
    expect(roleFromGroups([1, { admins: true }], mapping)).toBeNull();
  });
});

describe("routes", () => {
  it("names a permission for known routes and refuses unknown ones", () => {
    expect(routePermission("GET", "/api/console/audit-log")).toBe("audit.read");
    expect(routePermission("GET", "/api/dashboard")).toBe("findings.read");
    expect(routePermission("POST", "/api/finding-family/abc/triage")).toBe("findings.triage");
    expect(routePermission("POST", "/api/console/sessions")).toBe("threads.run");
    expect(routePermission("PATCH", "/api/console/settings")).toBe("settings.write");
    expect(routePermission("GET", "/api/console/settings")).toBe("workspace.read");
    expect(routePermission("GET", "/api/brand-new")).toBeNull();
    expect(routePermission("DELETE", "/api/console/brand-new")).toBeNull();
    expect(decideRoute(["workspace.read"], "GET", "/api/brand-new")).toEqual({ allowed: false, code: "no_permission_defined" });
    expect(decideRoute(["workspace.read"], "POST", "/api/console/sessions")).toEqual({ allowed: false, code: "forbidden", permission: "threads.run" });
    expect(decideRoute([], "GET", "/api/team/session")).toEqual({ allowed: true });
  });

  it("gives the auditor findings and the audit log and nothing else", () => {
    const auditor = BUILT_IN_ROLES.auditor!.permissions;
    expect(decideRoute(auditor, "GET", "/api/console/audit-log").allowed).toBe(true);
    expect(decideRoute(auditor, "GET", "/api/dashboard").allowed).toBe(true);
    expect(decideRoute(auditor, "GET", "/api/console/sessions").allowed).toBe(false);
    expect(decideRoute(auditor, "POST", "/api/finding-family/x/triage").allowed).toBe(false);
  });
});
