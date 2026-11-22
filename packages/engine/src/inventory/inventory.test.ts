import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildInventory, inventorySummaryText, isIgnored, parseGitignore, planBatches } from "./index.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function tree(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "inventory-test-"));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}
const kinds = (units: Array<{ kind: string; path: string; name?: string }>) => units.map(unit => `${unit.kind} ${unit.path} ${unit.name ?? ""}`.trim());

describe("buildInventory", () => {
  it("finds routes, handlers, webhooks, consumers, mains and dangerous sinks across frameworks", () => {
    const root = tree({
      "src/api.js": "const app = require('express')();\napp.get('/users/:id', h);\nrouter.post('/stripe/webhook', w);\n",
      "app.py": "@app.route('/items')\ndef items():\n  pass\n@router.post('/upload')\ndef up(): pass\nif __name__ == '__main__':\n  pass\n",
      "main.go": "package main\nfunc main() {}\nfunc serve(w http.ResponseWriter, r *http.Request) {}\nfunc init() { mux.HandleFunc(\"/ping\", serve) }\n",
      "Ctl.java": "@RestController\nclass C {\n  @GetMapping(\"/a\")\n  String a() { return \"\"; }\n}\n",
      "config/routes.rb": "Rails.application.routes.draw do\n  get '/health', to: 'h#show'\n  resources :posts\nend\n",
      "app/controllers/posts_controller.rb": "class PostsController\n  def index; end\n  private\n  def helper; end\nend\n",
      "web.php": "<?php\nRoute::get('/home', fn() => 1);\n$x = $_GET['a'];\n$y = $_POST['b'];\n",
      "jobs.ts": "cron.schedule('* * * * *', run);\nnew Worker('q', proc);\n",
      "load.py": "import pickle\nx = pickle.loads(data)\nimport subprocess\nsubprocess.run(cmd, shell=True)\n",
    });
    const { units } = buildInventory(root);
    const list = kinds(units);
    expect(list).toContain("http-route src/api.js GET /users/:id");
    expect(list).toContain("webhook src/api.js POST /stripe/webhook");
    expect(list).toContain("http-route app.py GET /items".replace("GET", "route"));
    expect(list).toContain("http-route app.py post /upload");
    expect(list).toContain("cli-main app.py main");
    expect(list).toContain("cli-main main.go main");
    expect(list).toContain("http-route main.go serve");
    expect(list).toContain("http-route main.go handle /ping");
    expect(list).toContain("http-route Ctl.java GET /a");
    expect(list).toContain("http-route config/routes.rb get /health");
    expect(list).toContain("http-route config/routes.rb resources posts");
    expect(list).toContain("http-route app/controllers/posts_controller.rb action index");
    expect(list).not.toContain("http-route app/controllers/posts_controller.rb action helper");
    expect(list).toContain("http-route web.php GET /home");
    expect(units.filter(unit => unit.path === "web.php" && unit.name === "reads $_GET")).toHaveLength(1);
    expect(list).toContain("cron jobs.ts job");
    expect(list).toContain("queue-consumer jobs.ts consumer");
    expect(list).toContain("deserialization load.py deserialization");
    expect(list).toContain("exec load.py command or code execution");
  });

  it("gives every source file a unit: files no matcher hits are grouped by directory after the entry points", () => {
    const root = tree({
      "server.js": "app.get('/a', h);\n",
      "lib/a.js": "export const a = 1;\n",
      "lib/b.js": "export const b = 2;\n",
      "lib/deep/c.py": "x = 1\n",
      "README.md": "not source\n",
    });
    const { units, summary } = buildInventory(root);
    expect(units.map(unit => unit.kind)).toEqual(["http-route", "other", "other"]);
    const others = units.filter(unit => unit.kind === "other");
    expect(others.map(unit => [unit.path, unit.files])).toEqual([["lib", ["lib/a.js", "lib/b.js"]], ["lib/deep", ["lib/deep/c.py"]]]);
    const covered = new Set(units.flatMap(unit => (unit.files ?? [unit.path])));
    expect([...covered].sort()).toEqual(["lib/a.js", "lib/b.js", "lib/deep/c.py", "server.js"]);
    expect(summary.sourceFiles).toBe(4);
    expect(summary.entryPoints).toBe(1);
  });

  it("splits a big directory into chunks and keeps ids stable and unique", () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 7; i++) files[`util/f${i}.js`] = `export const v${i} = ${i};\n`;
    const root = tree(files);
    const first = buildInventory(root, { otherChunk: 3 });
    const second = buildInventory(root, { otherChunk: 3 });
    expect(first.units).toHaveLength(3);
    expect(first.units).toEqual(second.units);
    expect(new Set(first.units.map(unit => unit.id)).size).toBe(3);
  });

  it("skips ignored files, vendored and build directories, links, minified and oversized files, and executes nothing", () => {
    const root = tree({
      ".gitignore": "secret/\n*.gen.js\n!keep.gen.js\n/only-root.js\n",
      "secret/a.js": "app.get('/s', h);\n",
      "x.gen.js": "app.get('/g', h);\n",
      "keep.gen.js": "app.get('/k', h);\n",
      "only-root.js": "app.get('/r', h);\n",
      "sub/only-root.js": "app.get('/nested', h);\n",
      "node_modules/m/index.js": "app.get('/m', h);\n",
      "vendor/v.go": "func main() {}\n",
      "dist/out.js": "app.get('/d', h);\n",
      "web/app.min.js": "app.get('/min', h);\n",
      "big.js": `app.get('/big', h);\n${"x".repeat(2000)}\n`,
      "ok.js": "app.get('/ok', h);\n",
    });
    symlinkSync("/etc", join(root, "link"));
    const { units, summary } = buildInventory(root, { maxFileBytes: 1000 });
    const paths = new Set(units.flatMap(unit => (unit.files ?? [unit.path])));
    expect([...paths].sort()).toEqual(["big.js", "keep.gen.js", "ok.js", "sub/only-root.js"]);
    expect(summary.skipped.tooLarge).toEqual(["big.js"]);
    expect(units.find(unit => unit.files?.includes("big.js"))?.kind).toBe("other");
  });

  it("is bounded: a file cap and an entry-point cap, with the overflow still covered", () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 12; i++) files[`r${String(i).padStart(2, "0")}.js`] = "app.get('/x', h);\n";
    const root = tree(files);
    const capped = buildInventory(root, { maxEntryUnits: 5 });
    expect(capped.summary.entryPoints).toBe(5);
    expect(capped.summary.skipped.unitLimit).toBe(true);
    expect(new Set(capped.units.flatMap(unit => (unit.files ?? [unit.path]))).size).toBe(12);
    const walked = buildInventory(root, { maxFiles: 4 });
    expect(walked.summary.skipped.walkLimit).toBe(true);
    expect(walked.summary.sourceFiles).toBe(4);
  });

  it("limits the units one matcher gives a file", () => {
    const root = tree({ "pg.php": `<?php\n${Array.from({ length: 40 }, (_, i) => `Route::get('/r${i}', f);`).join("\n")}\n` });
    expect(buildInventory(root).summary.entryPoints).toBe(25);
  });

  it("restricts to a set of files for a review of a change", () => {
    const root = tree({ "a.js": "app.get('/a', h);\n", "b.js": "app.get('/b', h);\n" });
    expect(buildInventory(root, { only: new Set(["b.js"]) }).units.map(unit => unit.path)).toEqual(["b.js"]);
  });
});

describe("gitignore", () => {
  it("handles anchors, directory-only rules, globstars and negation", () => {
    const rules = parseGitignore("# c\n*.log\nbuild/\n/top.txt\ndocs/**/*.tmp\n!keep.log\n");
    expect(isIgnored(rules, "a/b.log", false)).toBe(true);
    expect(isIgnored(rules, "keep.log", false)).toBe(false);
    expect(isIgnored(rules, "build", true)).toBe(true);
    expect(isIgnored(rules, "build", false)).toBe(false);
    expect(isIgnored(rules, "top.txt", false)).toBe(true);
    expect(isIgnored(rules, "x/top.txt", false)).toBe(false);
    expect(isIgnored(rules, "docs/a/b/c.tmp", false)).toBe(true);
  });
});

describe("planBatches", () => {
  const unit = (i: number, path = `f${i}.js`) => ({ id: `u${i}`, kind: "http-route" as const, path, startLine: 1 });
  it("puts at most the batch size of entry points in a batch, entry points before other groups", () => {
    const units = [...Array.from({ length: 19 }, (_, i) => unit(i)), { id: "o1", kind: "other" as const, path: "lib", files: ["lib/a.js"] }, { id: "o2", kind: "other" as const, path: "lib2", files: ["lib2/a.js"] }];
    const batches = planBatches(units, 8);
    expect(batches.map(batch => batch.units.length)).toEqual([8, 8, 3, 2]);
    expect(batches[2]!.units.every(item => item.kind === "http-route")).toBe(true);
    expect(batches[3]!.units.every(item => item.kind === "other")).toBe(true);
    expect(batches.flatMap(batch => batch.units.map(item => item.id)).sort()).toEqual(units.map(item => item.id).sort());
  });
  it("keeps one file's units together while they fit", () => {
    const units = [...Array.from({ length: 6 }, (_, i) => unit(i)), ...Array.from({ length: 4 }, (_, i) => unit(10 + i, "same.js"))];
    expect(planBatches(units, 8).map(batch => batch.units.length)).toEqual([10]);
  });
  it("describes the inventory briefly", () => {
    const { summary } = buildInventory(tree({ "a.js": "app.get('/a', h);\n", "lib/b.js": "export {}\n" }));
    expect(inventorySummaryText(summary)).toMatch(/2 source files; 1 entry points/);
  });
});
