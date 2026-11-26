/**
 * End to end: the in-repo Foxguard binary (`foxguard graph`) indexes a Java Spring fixture and the real
 * code-index tools answer from it. The fixture is crates/foxguard/tests/fixtures/java_graph_app: three
 * routes, one of which (`GET /api/notes/{id}/export`) has no authorization or ownership check.
 *
 * The binary is found through ZERO_FOXGUARD_TEST_BIN, then target/release and target/debug of this repo,
 * then PATH. Without one the suite is skipped locally; in CI (the setup action puts the freshly built
 * binary on PATH) a missing binary fails the run instead of skipping it.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { accessSync, appendFileSync, constants, cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { clearIndexCache, getIndex } from "./build.js";
import { clearFoxguardProbe } from "./foxguard.js";
import { ToolExecutor } from "../agent/tools.js";
import type { ToolContext } from "../agent/types.js";

const REPO = fileURLToPath(new URL("../../../../", import.meta.url));
const FIXTURE = join(REPO, "crates/foxguard/tests/fixtures/java_graph_app");
const SECURITY_FIXTURE = join(REPO, "crates/foxguard/tests/fixtures/java_graph_security_app");

function supportsGraph(bin: string): boolean {
  try {
    accessSync(bin, constants.X_OK);
    return /schema version 1/i.test(execFileSync(bin, ["graph", "--help"], { encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "ignore"] }));
  } catch { return false; }
}

function findBinary(): string | undefined {
  const candidates = [
    process.env["ZERO_FOXGUARD_TEST_BIN"],
    join(REPO, "target/release/foxguard"),
    join(REPO, "target/debug/foxguard"),
    ...(process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "foxguard")),
  ].filter((c): c is string => Boolean(c));
  return candidates.find(supportsGraph);
}

const binary = findBinary();
const inCi = Boolean(process.env["CI"]);

describe("Java code index through the real foxguard binary", () => {
  if (!binary && inCi) {
    it("has a foxguard binary with `graph` in CI", () => { throw new Error("no foxguard binary with `graph` (schema version 1) found on PATH or in target/"); });
    return;
  }
  const run = binary ? describe : describe.skip;
  run("fixture project", () => {
    let root: string;
    let saved: string | undefined;
    beforeAll(() => { saved = process.env["ZERO_FOXGUARD_PATH"]; });
    afterAll(() => { if (saved === undefined) delete process.env["ZERO_FOXGUARD_PATH"]; else process.env["ZERO_FOXGUARD_PATH"] = saved; });
    beforeEach(() => {
      root = mkdtempSync(join(tmpdir(), "java-index-"));
      cpSync(FIXTURE, root, { recursive: true });
      clearIndexCache(); clearFoxguardProbe();
      process.env["ZERO_FOXGUARD_PATH"] = binary!;
    });
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    const ctx = (): ToolContext => ({ target: "https://example.com", scanId: "java-index", findings: [], attackResults: [], targetInfo: {}, role: "review", scopePath: root });
    const call = async (name: string, args: Record<string, unknown>): Promise<Record<string, any>> => {
      const result = await new ToolExecutor(ctx(), null).execute({ name, arguments: args });
      expect(result.success, result.error).toBe(true);
      return result.output as Record<string, any>;
    };

    it("builds a foxguard index with the Java symbols, three routes and sink calls", async () => {
      const { index } = await getIndex(root);
      expect(index.engine).toBe("foxguard");
      expect(index.unsupported).toEqual({});
      expect(index.routes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(["GET /api/notes/{id}", "GET /api/notes/{id}/export", "PUT /api/notes/{id}"]);
      expect(index.symbols.filter((s) => s.language === "java").map((s) => s.qualified)).toEqual(expect.arrayContaining(["NoteController.export", "NoteService.load", "OwnershipChecker.assertOwner"]));
      expect(index.calls.some((c) => c.text === "jdbcTemplate.queryForObject" && c.sink?.category === "sql")).toBe(true);
      expect(index.calls.some((c) => c.text === "Files.readString" && c.sink?.category === "file")).toBe(true);
    });

    it("routes with without_auth_signal lists only the route with no check", async () => {
      const all = await call("routes", {});
      expect(all["routes"]).toHaveLength(3);
      const out = await call("routes", { without_auth_signal: true });
      expect(out["routes"].map((r: { path: string }) => r.path)).toEqual(["/api/notes/{id}/export"]);
      expect(out["routes"][0].sinks_reachable.sort()).toEqual(["file", "sql"]);
      expect(out["index"].engine).toBe("foxguard");
      expect(out["index"].languages).toEqual(["java"]);
      const guarded = all["routes"].filter((r: { auth_signal_missing: boolean }) => !r.auth_signal_missing);
      const byPath = Object.fromEntries(guarded.map((r: { method: string; auth_signals: Array<{ name: string }> }) => [r.method, r.auth_signals.map((s) => s.name)]));
      expect(byPath["GET"]).toContain("PreAuthorize");
      expect(byPath["PUT"]).toContain("ownership.assertOwner");
    });

    it("callers_of follows the ownership check and the service method up to the routes", async () => {
      const owner = await call("callers_of", { symbol: "OwnershipChecker.assertOwner", depth: 2 });
      expect(owner["entryRoutes"].map((r: { route: string }) => r.route)).toEqual(["PUT /api/notes/{id}"]);
      const load = await call("callers_of", { symbol: "NoteService.load", depth: 3 });
      // PUT is reached twice (directly and through save), so compare the distinct routes.
      expect([...new Set(load["entryRoutes"].map((r: { route: string }) => r.route))].sort()).toEqual(["GET /api/notes/{id}", "GET /api/notes/{id}/export", "PUT /api/notes/{id}"]);
    });

    it("trace_to_sink reaches the SQL and file sinks, with and without an auth signal on the path", async () => {
      const exportTrace = await call("trace_to_sink", { from: "GET /api/notes/{id}/export" });
      const categories = exportTrace["paths"].map((p: { sink: { category: string } }) => p.sink.category).sort();
      expect(categories).toEqual(["file", "sql"]);
      for (const p of exportTrace["paths"]) expect(p.auth_signals_on_path).toEqual([]);
      const put = await call("trace_to_sink", { from: "PUT /api/notes/{id}", sink: "sql" });
      expect(put["paths"].length).toBeGreaterThan(0);
      expect(put["paths"][0].auth_signals_on_path).toContain("ownership.assertOwner");
    });

    it("callees_of marks the sink calls", async () => {
      const out = await call("callees_of", { symbol: "NoteService.exportRaw", depth: 2 });
      const sinks = out["callees"].filter((c: { sink?: { category: string } }) => c.sink).map((c: { sink: { category: string } }) => c.sink.category).sort();
      expect(sinks).toEqual(["file", "sql"]);
    });

    it("a Java edit gives a new index, so a stale one is never served", async () => {
      const first = await getIndex(root);
      expect((await getIndex(root)).cached).toBe(true);
      appendFileSync(join(root, "src/main/java/com/example/notes/Note.java"), "// edited\n");
      const second = await getIndex(root);
      expect(second.cached).toBe(false);
      expect(second.index.fingerprint).not.toBe(first.index.fingerprint);
    });
  });

  run("security configuration outside annotations, interfaces and Kotlin", () => {
    let root: string;
    let saved: string | undefined;
    beforeAll(() => { saved = process.env["ZERO_FOXGUARD_PATH"]; });
    afterAll(() => { if (saved === undefined) delete process.env["ZERO_FOXGUARD_PATH"]; else process.env["ZERO_FOXGUARD_PATH"] = saved; });
    beforeEach(() => {
      root = mkdtempSync(join(tmpdir(), "java-security-index-"));
      cpSync(SECURITY_FIXTURE, root, { recursive: true });
      clearIndexCache(); clearFoxguardProbe();
      process.env["ZERO_FOXGUARD_PATH"] = binary!;
    });
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    const ctx = (): ToolContext => ({ target: "https://example.com", scanId: "java-security-index", findings: [], attackResults: [], targetInfo: {}, role: "review", scopePath: root });
    const call = async (name: string, args: Record<string, unknown>): Promise<Record<string, any>> => {
      const result = await new ToolExecutor(ctx(), null).execute({ name, arguments: args });
      expect(result.success, result.error).toBe(true);
      return result.output as Record<string, any>;
    };

    it("indexes Java, Kotlin and web.xml routes and reports coverage", async () => {
      const { index } = await getIndex(root);
      expect(index.engine).toBe("foxguard");
      expect(index.unsupported).toEqual({});
      expect(index.droppedCalls).toBe(0);
      expect(new Set(index.symbols.map((s) => s.language))).toEqual(new Set(["java", "kotlin"]));
      expect(index.routes.map((r) => `${r.method} ${r.path}`).sort()).toEqual([
        "DELETE /shop/orders/{id}", "GET /admin/export", "GET /kt/health", "GET /kt/me", "GET /legacy/report", "GET /public/search", "GET /shop/orders/{id}",
      ]);
    });

    it("URL rules count as auth signals with their source, so only open routes lack one", async () => {
      const out = await call("routes", {});
      const byRoute = Object.fromEntries(out["routes"].map((r: { method: string; path: string }) => [`${r.method} ${r.path}`, r]));
      const order = byRoute["GET /shop/orders/{id}"];
      expect(order.auth_signal_missing).toBe(false);
      expect(order.auth_signals.map((s: { name: string }) => s.name)).toContain("url-rule:authenticated");
      expect(order.auth_signals.find((s: { name: string }) => s.name === "url-rule:authenticated").source).toMatch(/SecurityConfig\.java:\d+/);
      expect(byRoute["GET /admin/export"].auth_signals.map((s: { name: string }) => s.name)).toContain("url-rule:hasAuthority(ADMIN)");
      expect(byRoute["GET /legacy/report"].auth_signals.map((s: { name: string }) => s.name)).toContain("web.xml:auth-constraint(auditor)");
      expect(byRoute["GET /kt/me"].auth_signals.map((s: { name: string }) => s.name)).toContain("authenticate(jwt)");
      const open = await call("routes", { without_auth_signal: true });
      expect(open["routes"].map((r: { path: string }) => r.path).sort()).toEqual(["/kt/health", "/public/search"]);
      const search = open["routes"].find((r: { path: string }) => r.path === "/public/search");
      expect(search.public).toBe(true);
      expect(search.public_source).toMatch(/requestMatchers/);
      expect(search.sinks_reachable).toEqual(["sql"]);
    });

    it("an interface-typed field reaches the single implementor, so the trace crosses it", async () => {
      const trace = await call("trace_to_sink", { from: "GET /public/search", sink: "sql" });
      expect(trace["paths"].length).toBeGreaterThan(0);
      const hops = trace["paths"][0].hops.map((h: { symbol: string }) => h.symbol);
      expect(hops).toContain("OrderServiceImpl.search");
      const callers = await call("callers_of", { symbol: "OrderServiceImpl.load", depth: 2 });
      expect([...new Set(callers["entryRoutes"].map((r: { route: string }) => r.route))]).toEqual(["GET /shop/orders/{id}"]);
    });

    it("an edit to web.xml gives a new index", async () => {
      const first = await getIndex(root);
      appendFileSync(join(root, "src/main/webapp/WEB-INF/web.xml"), "<!-- edited -->\n");
      const second = await getIndex(root);
      expect(second.cached).toBe(false);
      expect(second.index.fingerprint).not.toBe(first.index.fingerprint);
    });
  });
});
