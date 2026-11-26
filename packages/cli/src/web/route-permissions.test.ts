// Fails when a server route has no permission rule. A route with no rule is refused on a licensed server,
// so this test keeps a new route from shipping unusable (or, worse, unreviewed). The rules are in enterprise/src/rbac/routes.ts.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ROUTE_RULES, routePermission } from "../enterprise-bridge.js";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..");
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

// Files that answer /api requests. Client code that only calls other servers is not listed.
const SERVER_FILES = [
  "commands/dashboard.ts",
  ...readdirSync(here).filter(name => name.endsWith(".ts") && !/\.(?:test|integration\.test)\.ts$/.test(name) && !/-client\.ts$|^(?:team-rbac|route-permissions)/.test(name)).map(name => `web/${name}`),
];

// Words that start a regular expression in these files but are not API areas.
const NOT_ROUTES = new Set(["assets", "builtin", "openai", "packages", "repos", "scripts", "conversations", "rooms", "extensions\\", "skills\\"]);
// /api paths that are named in server code but answered before the team permission check, by their own credential.
const OWN_CREDENTIAL = new Set(["webhooks"]);
// /api paths that appear in server files as the address of another server (outbound calls), not as a route here.
const OUTBOUND = new Set(["paas"]);

function read(file: string): string { return readFileSync(join(src, file), "utf8"); }
function code(file: string): string {
  // Comments and line-comment text name routes in prose. Drop them.
  return read(file).replace(/\/\*[\s\S]*?\*\//g, "").split("\n").filter(line => !/^\s*\/\//.test(line)).join("\n");
}

/** First path part after /api/ in string and regular-expression literals. */
function apiAreas(): Map<string, string> {
  const found = new Map<string, string>();
  for (const file of SERVER_FILES) {
    const text = code(file);
    for (const m of text.matchAll(/[/\\]{1,2}api[/\\]{1,2}([a-z][a-z0-9-]*)/g)) if (!found.has(m[1]!)) found.set(m[1]!, file);
  }
  return found;
}

/** First path part after /api/console/ for literals that spell the full path. */
function consoleAreasFromFullPaths(): Map<string, string> {
  const found = new Map<string, string>();
  for (const file of SERVER_FILES) {
    for (const m of code(file).matchAll(/[/\\]{1,2}api[/\\]{1,2}console[/\\]{1,2}([a-z][a-z0-9-]*)/g)) if (!found.has(m[1]!)) found.set(m[1]!, file);
  }
  return found;
}

/** First path part of routes that handlers match on the path after /api/console/. */
function consoleAreasFromRelativePaths(): Map<string, string> {
  const found = new Map<string, string>();
  const add = (name: string | undefined, file: string) => { if (name && !NOT_ROUTES.has(name) && !found.has(name)) found.set(name, file); };
  // Team routes (/api/team/...) use their own relative paths and are covered by the "session" rule.
  for (const file of SERVER_FILES.filter(name => name !== "commands/dashboard.ts" && !name.startsWith("web/team-"))) {
    const text = code(file);
    for (const m of text.matchAll(/\bpath\s*(?:===|!==)\s*"([a-z][a-z0-9-]*)(?:\/[^"]*)?"/g)) add(m[1], file);
    for (const m of text.matchAll(/\bpath\.startsWith\("([a-z][a-z0-9-]*)\//g)) add(m[1], file);
    for (const m of text.matchAll(/\bcase\s+"([a-z][a-z0-9-]*)(?:\/[^"]*)?":/g)) add(m[1], file);
    // Regular expressions tested against the relative path: /^area/, /^area(?:/, /^(a|b(?:...)|c)$/.
    for (const line of text.split("\n")) {
      if (!/\b(?:path|rel)\b/.test(line)) continue;
      for (const m of line.matchAll(/\/\^([a-z][a-z0-9-]*)(?=\\\/|\(|\$|\/)/g)) add(m[1], file);
      const group = /\/\^\(((?:[a-z][a-z0-9-]*(?:\([^)]*\))?(?:\\\/[^|)]*)?\|?)+)\)\$?\//.exec(line);
      if (group) for (const part of group[1]!.split("|")) add(/^[a-z][a-z0-9-]*/.exec(part)?.[0], file);
    }
  }
  return found;
}

describe("every API route has a permission rule", () => {
  it("covers each /api area the server answers", () => {
    const missing: string[] = [];
    for (const [area, file] of apiAreas()) {
      if (area === "console" || OWN_CREDENTIAL.has(area) || OUTBOUND.has(area)) continue;
      if (METHODS.every(method => routePermission(method, `/api/${area}/x`) === null && routePermission(method, `/api/${area}`) === null)) missing.push(`/api/${area} (named in ${file})`);
    }
    expect(missing, "add a rule for each area to ROUTE_RULES in enterprise/src/rbac/routes.ts").toEqual([]);
  });

  it("covers each /api/console area, for reads and for writes", () => {
    const areas = new Map([...consoleAreasFromFullPaths(), ...consoleAreasFromRelativePaths()]);
    expect(areas.size, "the scan found too few console areas; fix the scan").toBeGreaterThan(20);
    const missing: string[] = [];
    for (const [area, file] of areas) {
      for (const [label, method] of [["read", "GET"], ["write", "POST"]] as const) {
        // Metrics has a read-only collection; its one explicit write route refreshes host receipts.
        const representativePath = area === "run-metrics" && method === "POST" ? "/api/console/run-metrics/refresh-host" : `/api/console/${area}/x`;
        if (routePermission(method, representativePath) === null && routePermission(method, `/api/console/${area}`) === null) missing.push(`${label} /api/console/${area} (named in ${file})`);
      }
    }
    expect(missing, "add a rule for each area to ROUTE_RULES in enterprise/src/rbac/routes.ts").toEqual([]);
  });

  it("keeps metrics reads and the explicit host refresh owner-managed without allowing collection writes", () => {
    expect(routePermission("GET", "/api/console/run-metrics")).toBe("settings.write");
    expect(routePermission("POST", "/api/console/run-metrics/refresh-host")).toBe("settings.write");
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect(routePermission(method, "/api/console/run-metrics")).toBeNull();
    expect(routePermission("POST", "/api/console/run-metrics/other")).toBeNull();
  });

  it("names a permission, never nothing, for the sensitive routes", () => {
    const sensitive: Array<[string, string]> = [["POST", "/api/team/users"], ["GET", "/api/console/audit-log"], ["POST", "/api/control/reset-database"], ["POST", "/api/workers/deploy"], ["PUT", "/api/console/instructions/global"], ["POST", "/api/console/update/apply"]];
    for (const [method, path] of sensitive) expect(routePermission(method, path), `${method} ${path}`).not.toBeNull();
  });

  it("has no rule that names a permission outside the list", () => {
    const known = new Set(["session", "workspace.read", "findings.read", "findings.triage", "threads.run", "settings.write", "audit.read", "users.manage"]);
    for (const rule of ROUTE_RULES) expect(known.has(rule.permission)).toBe(true);
  });
});
