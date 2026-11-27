import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { clearIndexCache, getIndex } from "./build.js";
import { clearFoxguardProbe } from "./foxguard.js";
import { callersOf, calleesOf, routesOf, traceToSink } from "./query.js";
import { ToolExecutor } from "../agent/tools.js";
import { DeferredToolRegistry } from "../agent/deferred-tools.js";
import { TOOL_DEFINITIONS } from "../agent/tools.js";
import { TOOL_PACKS } from "../agent/toolset.js";
import { clearSkillRegistry, getSkillById, loadSkillRegistry } from "../agent/skills/index.js";
import type { ToolContext } from "../agent/types.js";

/** Three routes on one router; the export route has no authentication and no ownership check. */
const NOTES_APP: Record<string, string> = {
  "src/auth.ts": `
export function requireAuth(req: any, res: any, next: any) { if (!req.user) return res.status(401).end(); next(); }
export function assertOwner(user: any, note: any) { if (note.ownerId !== user.id) throw new Error("forbidden"); }
`,
  "src/notes.ts": `
import { db } from "./db";
// db.query("never indexed: this is a comment")
export async function loadNote(id: string) {
  return db.query("SELECT * FROM notes WHERE id = '" + id + "'");
}
export async function saveNote(id: string, body: string) {
  return db.query("UPDATE notes SET body = ? WHERE id = ?", [body, id]);
}
`,
  "src/handlers.ts": `
import { loadNote } from "./notes";
export async function exportHandler(req: any, res: any) {
  const note = await loadNote(req.params.id);
  res.send(note);
}
`,
  "src/routes.ts": `
import express from "express";
import { requireAuth, assertOwner } from "./auth";
import { loadNote, saveNote } from "./notes";
import { exportHandler } from "./handlers";

const router = express.Router();

router.get("/notes/:id", requireAuth, async (req, res) => {
  const note = await loadNote(req.params.id);
  assertOwner(req.user, note);
  res.json(note);
});

router.put("/notes/:id", requireAuth, async (req, res) => {
  const note = await loadNote(req.params.id);
  assertOwner(req.user, note);
  await saveNote(req.params.id, req.body.body);
  res.json({ ok: true });
});

router.get("/notes/:id/export", exportHandler);

export default router;
`,
};

const PY_APP: Record<string, string> = {
  "app.py": `
import os
from flask import Flask
from auth import login_required, check_owner

app = Flask(__name__)

@app.route("/files/<name>", methods=["DELETE"])
@login_required
def delete_file(name):
    check_owner(name)
    os.remove(name)

@app.route("/ping")
def ping():
    """os.system("never indexed")"""
    return run_ping(request.args["host"])

def run_ping(host):
    os.system("ping " + host)
`,
  "auth.py": `
def login_required(fn):
    return fn

def check_owner(name):
    pass
`,
};

function write(root: string, files: Record<string, string>): void {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
}

let root: string;
let savedFoxguard: string | undefined;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "code-index-"));
  clearIndexCache(); clearFoxguardProbe();
  savedFoxguard = process.env["ZERO_FOXGUARD_PATH"];
  process.env["ZERO_FOXGUARD_PATH"] = join(root, "no-such-foxguard"); // the built-in extractor, whatever is installed
});
afterEach(() => {
  if (savedFoxguard === undefined) delete process.env["ZERO_FOXGUARD_PATH"]; else process.env["ZERO_FOXGUARD_PATH"] = savedFoxguard;
  rmSync(root, { recursive: true, force: true });
});

describe("code index: TypeScript fixture with one unguarded route of three", () => {
  beforeEach(() => write(root, NOTES_APP));

  it("indexes symbols, calls and the three routes", async () => {
    const { index } = await getIndex(root);
    expect(index.routes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(["GET /notes/:id", "GET /notes/:id/export", "PUT /notes/:id"]);
    expect(index.symbols.map((s) => s.name)).toEqual(expect.arrayContaining(["requireAuth", "assertOwner", "loadNote", "exportHandler"]));
    // Comments and strings are not code.
    expect(index.calls.some((c) => c.text === "db.query" && c.file === "src/notes.ts")).toBe(true);
    expect(index.calls.filter((c) => c.file === "src/notes.ts" && c.name === "query")).toHaveLength(2);
  });

  it("finds the missing check through routes and callers_of", async () => {
    const { index } = await getIndex(root);
    const view = routesOf(index, {}, 50);
    const unguarded = view.routes.filter((r) => r.auth_signal_missing);
    expect(unguarded.map((r) => `${r.method} ${r.path}`)).toEqual(["GET /notes/:id/export"]);
    expect(unguarded[0]!.handler).toContain("exportHandler");
    expect(unguarded[0]!.sinks_reachable).toContain("sql");
    expect(routesOf(index, { withoutAuthSignal: true }, 50).routes).toHaveLength(1);

    const callers = callersOf(index, "assertOwner", 2, 50);
    if ("error" in callers) throw new Error(callers.error);
    const guarded = callers.entryRoutes.map((r) => r.route).sort();
    expect(guarded).toEqual(["GET /notes/:id", "PUT /notes/:id"]);
    expect(guarded).not.toContain("GET /notes/:id/export");
  });

  it("traces the unguarded route to the sql sink with no auth signal on the path", async () => {
    const { index } = await getIndex(root);
    const trace = traceToSink(index, "GET /notes/:id/export", "sql", 5, 5);
    if ("error" in trace) throw new Error(trace.error);
    expect(trace.paths).toHaveLength(1);
    expect(trace.paths[0]!.hops.map((h) => h.symbol)).toEqual(["exportHandler", "loadNote"]);
    expect(trace.paths[0]!.sink.call).toBe("db.query");
    expect(trace.paths[0]!.auth_signals_on_path).toEqual([]);
    const guarded = traceToSink(index, "PUT /notes/:id", "sql", 5, 5);
    if ("error" in guarded) throw new Error(guarded.error);
    expect(guarded.paths.every((p) => p.auth_signals_on_path.includes("requireAuth"))).toBe(true);
  });

  it("lists callees with sink marks and reports unknown names softly", async () => {
    const { index } = await getIndex(root);
    const callees = calleesOf(index, "loadNote", 1, 10);
    if ("error" in callees) throw new Error(callees.error);
    expect(callees.callees[0]).toMatchObject({ call: "db.query", sink: { category: "sql" } });
    expect(callersOf(index, "doesNotExist", 1, 5)).toHaveProperty("error");
  });

  it("caches per commit and working-tree state", async () => {
    execFileSync("git", ["init", "-q"], { cwd: root });
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "add", "-A"], { cwd: root });
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init"], { cwd: root });
    const first = await getIndex(root);
    expect(first.cached).toBe(false);
    expect(first.index.commit).toMatch(/^[0-9a-f]{40}$/);
    expect((await getIndex(root)).cached).toBe(true);
    writeFileSync(join(root, "src/extra.ts"), "export function extra() { return 1; }\n");
    utimesSync(join(root, "src/extra.ts"), new Date(), new Date());
    const third = await getIndex(root);
    expect(third.cached).toBe(false);
    expect(third.index.symbols.some((s) => s.name === "extra")).toBe(true);
  });
});

describe("code index: Python fixture", () => {
  beforeEach(() => write(root, PY_APP));

  it("finds routes, decorators as middleware and the command sink", async () => {
    const { index } = await getIndex(root);
    const routes = routesOf(index, {}, 10).routes;
    expect(routes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(["DELETE /files/<name>", "GET /ping"]);
    expect(routes.find((r) => r.path === "/ping")!.auth_signal_missing).toBe(true);
    expect(routes.find((r) => r.path.startsWith("/files"))!.auth_signal_missing).toBe(false);
    const trace = traceToSink(index, "GET /ping", "command", 4, 3);
    if ("error" in trace) throw new Error(trace.error);
    expect(trace.paths[0]!.hops.map((h) => h.symbol)).toEqual(["ping", "run_ping"]);
    expect(trace.paths[0]!.sink.call).toBe("os.system");
  });
});

describe("code index: other frameworks", () => {
  it("indexes NestJS decorators, class methods, FastAPI Depends and Django URLConf", async () => {
    write(root, {
      "svc/notes.controller.ts": `
@Controller("notes")
@UseGuards(AuthGuard)
export class NotesController {
  constructor(private readonly svc: NotesService) {}
  @Get(":id")
  async find(id: string) { return this.svc.findOne(id); }
  @Public()
  @Post("open")
  open(body: any) { return this.svc.create(body); }
}
export class NotesService {
  findOne(id: string) { return exec("cat " + id); }
  create(b: any) { return b; }
}
`,
      "api/main.py": `
from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/me")
async def me(user=Depends(current_user)):
    return user
`,
      "api/urls.py": `
from django.urls import path
urlpatterns = [path("reports/", views.report_list), path("admin/", admin_view)]
`,
      "api/views.py": "def report_list(request):\n    return render(request)\n",
    });
    const { index } = await getIndex(root);
    const byPath = Object.fromEntries(index.routes.map((r) => [`${r.method} ${r.path}`, r]));
    expect(byPath["GET /notes/:id"]!.middleware).toContain("AuthGuard");
    expect(byPath["POST /notes/open"]!.middleware).toEqual(expect.arrayContaining(["Public", "AuthGuard"]));
    expect(byPath["GET /me"]!.middleware).toEqual(["current_user"]);
    expect(byPath["ANY /reports/"]!.handler).toContain("views.py#report_list");
    const trace = traceToSink(index, "GET /notes/:id", "command", 4, 3);
    if ("error" in trace) throw new Error(trace.error);
    expect(trace.paths[0]!.sink.call).toBe("exec");
  });
});

describe("code index: Foxguard graph backend", () => {
  const graph = {
    version: 1, producer: "foxguard", files: 1, unsupported: {}, truncated: false, taintSummaries: [],
    symbols: [{ id: "a.py#h@1", name: "h", qualified: "h", kind: "function", file: "a.py", line: 1, endLine: 2, language: "python" }],
    calls: [{ from: "a.py#h@1", name: "system", text: "os.system", file: "a.py", line: 2, sink: { category: "command", text: "os.system" } }],
    routes: [{ method: "GET", path: "/x", file: "a.py", line: 1, handler: "a.py#h@1", middleware: [], framework: "flask-fastapi" }],
  };
  const fake = (help: string, out: string): string => {
    const bin = join(root, "fake-foxguard");
    writeFileSync(bin, `#!/bin/sh\nif [ "$2" = "--help" ]; then printf '%s' '${help}'; else printf '%s' '${out}'; fi\n`);
    chmodSync(bin, 0o755);
    return bin;
  };

  it("uses a graph from a Foxguard binary that supports it", async () => {
    write(root, NOTES_APP);
    process.env["ZERO_FOXGUARD_PATH"] = fake("Export ... (schema version 1) --file-timeout <N>", JSON.stringify(graph));
    const { index } = await getIndex(root);
    expect(index.engine).toBe("foxguard");
    expect(index.routes.map((r) => r.path)).toEqual(["/x"]);
  });

  it("falls back to the built-in index for an older binary or invalid output", async () => {
    write(root, NOTES_APP);
    process.env["ZERO_FOXGUARD_PATH"] = fake("scan help", "not json");
    expect((await getIndex(root)).index.engine).toBe("builtin");
    clearIndexCache(); clearFoxguardProbe();
    process.env["ZERO_FOXGUARD_PATH"] = fake("(schema version 1) --file-timeout <N>", JSON.stringify({ ...graph, version: 2 }));
    expect((await getIndex(root)).index.engine).toBe("builtin");
  });
});

describe("code index tools through the real tool dispatch", () => {
  const ctx = (): ToolContext => ({ target: "https://example.com", scanId: "ci-test", findings: [], attackResults: [], targetInfo: {}, role: "review", scopePath: root });

  it("has the four tools registered, in the code-index pack and not in the core list", async () => {
    for (const name of TOOL_PACKS["code-index"]!) expect(TOOL_DEFINITIONS[name]).toBeDefined();
  });

  it("answers routes, callers_of, callees_of and trace_to_sink", async () => {
    write(root, NOTES_APP);
    const executor = new ToolExecutor(ctx(), null);
    const routes = await executor.execute({ name: "routes", arguments: { without_auth_signal: true } });
    expect(routes.success).toBe(true);
    const out = routes.output as { routes: Array<{ path: string }>; index: { cached: boolean } };
    expect(out.routes.map((r) => r.path)).toEqual(["/notes/:id/export"]);
    const callers = await executor.execute({ name: "callers_of", arguments: { symbol: "assertOwner", depth: 2 } });
    expect((callers.output as { entryRoutes: Array<{ route: string }> }).entryRoutes.map((r) => r.route).sort()).toEqual(["GET /notes/:id", "PUT /notes/:id"]);
    const callees = await executor.execute({ name: "callees_of", arguments: { symbol: "exportHandler" } });
    expect((callees.output as { callees: Array<{ call: string }> }).callees.map((c) => c.call)).toContain("loadNote");
    const trace = await executor.execute({ name: "trace_to_sink", arguments: { from: "GET /notes/:id/export", sink: "sql" } });
    expect((trace.output as { paths: unknown[] }).paths).toHaveLength(1);
    expect((trace.output as { index: { cached: boolean } }).index.cached).toBe(true);
  });

  it("rejects out-of-bounds or malformed arguments before touching the folder, and strips unknown keys", async () => {
    write(root, NOTES_APP);
    const executor = new ToolExecutor(ctx(), null);
    const deep = await executor.execute({ name: "callers_of", arguments: { symbol: "assertOwner", depth: 99 } });
    expect(deep.success).toBe(false);
    expect(deep.error).toContain("depth");
    const bad = await executor.execute({ name: "trace_to_sink", arguments: { from: "x; rm -rf /", max_paths: 1000 } });
    expect(bad.success).toBe(false);
    const missing = await executor.execute({ name: "routes", arguments: { limit: 0 } });
    expect(missing.success).toBe(false);
    const stripped = await executor.execute({ name: "routes", arguments: { cwd: "/etc", argv: ["x"] } });
    expect(stripped.success).toBe(true);
  });

  it("fails soft to search for unsupported languages and unknown symbols", async () => {
    write(root, { "main.go": "package main\nfunc main() {}\n" });
    const executor = new ToolExecutor(ctx(), null);
    const result = await executor.execute({ name: "routes", arguments: {} });
    expect(result.success).toBe(true);
    expect(result.output).toMatchObject({ supported: false, unsupported_files_by_extension: { go: 1 } });
    expect(JSON.stringify(result.output)).toContain("rg");
    write(root, NOTES_APP);
    const unknown = await executor.execute({ name: "callers_of", arguments: { symbol: "nope" } });
    expect(unknown.success).toBe(true);
    expect(unknown.output).toMatchObject({ found: false });
    const noFolder = await new ToolExecutor({ ...ctx(), scopePath: undefined }, null).execute({ name: "routes", arguments: {} });
    expect(noFolder.success).toBe(false);
  });

  describe("skills", () => {
    beforeEach(() => { clearSkillRegistry(); loadSkillRegistry(); });
    afterEach(() => clearSkillRegistry());
    it("the scan skill points at the code-index skill without declaring the pack itself", async () => {
      const scan = getSkillById("scan")!;
      expect(scan.tools ?? []).toEqual([]);
      expect(scan.content).toContain("`code-index`");
      expect(scan.content).toContain("without_auth_signal");
      expect(scan.content).toMatch(/poc_steps[^\n]*no network|poc_steps[^\n]*uses no network/);
    });
    it.each(["seedless-depth-review", "verify-finding", "code-index"])("%s loads the code-index pack", async (skill) => {
      const registry = new DeferredToolRegistry();
      registry.seed(Object.values(TOOL_DEFINITIONS).filter((d) => TOOL_PACKS["code-index"]!.includes(d.name)));
      const executor = new ToolExecutor({ ...ctx(), packTools: registry } as ToolContext, null);
      const loaded = await executor.execute({ name: "load_skill", arguments: { skill_id: skill } });
      expect(loaded.success).toBe(true);
      const out = loaded.output as { tools_available_next_turn: string[]; content: string };
      expect(out.tools_available_next_turn.sort()).toEqual(["callees_of", "callers_of", "routes", "trace_to_sink"]);
      expect(out.content).toContain("callers_of");
    });
  });
});
