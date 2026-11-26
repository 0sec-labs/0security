import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { checkInventory, scanHosts, scanOutbound } from "./check-egress-inventory.mjs";

function fixture({ files, entries, knownHosts = [], docs = "" }) {
  const root = mkdtempSync(join(tmpdir(), "egress-inventory-"));
  const write = (path, text) => { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), text); };
  for (const [path, text] of Object.entries(files)) write(path, text);
  write("scripts/egress-inventory.json", JSON.stringify({ entries, knownHosts }));
  write("docs/src/content/docs/data-flow.md", docs);
  return root;
}
const entry = (id, file, destinations = []) => ({ id, class: "feature", enterprise: "blocked", destinations, files: [file], when: "", sent: "", disable: "" });

test("the real repository is registered and documented", () => {
  assert.deepEqual(checkInventory(), []);
});

test("a new outbound call that is not in the inventory fails", () => {
  const root = fixture({ files: { "packages/cli/src/new-thing.ts": "export const go = () => fetch('https://x.example.test');\n" }, entries: [] });
  const problems = checkInventory(root);
  assert.equal(problems.length >= 1, true);
  assert.match(problems[0], /new-thing\.ts makes an outbound call/);
});

test("a registered, documented call passes, and a stale entry fails", () => {
  const files = { "packages/engine/src/ok.ts": "export const go = () => fetch(url);\n", "packages/engine/src/quiet.ts": "export const x = 1;\n" };
  const docs = "`ok-call` reaches api.thing.dev";
  const ok = fixture({ files, entries: [entry("ok-call", "packages/engine/src/ok.ts", ["api.thing.dev"])], docs });
  assert.deepEqual(checkInventory(ok), []);
  const stale = fixture({ files, entries: [entry("ok-call", "packages/engine/src/ok.ts", ["api.thing.dev"]), entry("quiet-call", "packages/engine/src/quiet.ts")], docs: `${docs} \`quiet-call\`` });
  assert.match(checkInventory(stale).join("\n"), /quiet\.ts, but it no longer matches/);
});

test("a destination missing from the docs page fails", () => {
  const files = { "packages/engine/src/ok.ts": "export const go = () => fetch(url);\n" };
  const root = fixture({ files, entries: [entry("ok-call", "packages/engine/src/ok.ts", ["api.thing.dev"])], docs: "`ok-call`" });
  assert.match(checkInventory(root).join("\n"), /does not list api\.thing\.dev/);
});

test("an unreviewed host literal in code fails; comments and test fixtures do not", () => {
  const files = {
    "packages/cli/src/a.ts": "// see https://commented.example.org/docs\nconst u = 'https://new-host.dev/v1';\nconst f = 'https://x.example.test';\n",
    "packages/cli/src/a.test.ts": "const u = 'https://test-only.dev';\n",
  };
  const root = fixture({ files, entries: [] });
  assert.deepEqual([...scanHosts(root).keys()], ["new-host.dev"]);
  assert.equal(scanOutbound(root).size, 0);
});

test("an HTTP client in a Rust crate must be registered; rule text that only names reqwest is not a call", () => {
  const files = {
    "crates/tool/src/net.rs": "fn go() { let c = reqwest::blocking::Client::builder().build(); }\n",
    "crates/tool/src/rules/ssrf.rs": "// matches reqwest::get(url)\nconst NAME: &str = \"reqwest\";\n",
  };
  const missing = fixture({ files, entries: [] });
  assert.match(checkInventory(missing).join("\n"), /crates\/tool\/src\/net\.rs makes an outbound call \(rustHttp\)/);
  assert.doesNotMatch(checkInventory(missing).join("\n"), /ssrf\.rs/);
  const ok = fixture({ files, entries: [entry("rust-call", "crates/tool/src/net.rs", ["api.thing.dev"])], docs: "`rust-call` reaches api.thing.dev" });
  assert.deepEqual(checkInventory(ok), []);
});
