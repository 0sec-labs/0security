// Real-run check of the Linux bubblewrap sandbox. Run it INSIDE a Linux container that has bubblewrap and node.
// After `pnpm --filter @0/engine build`, from the repository root:
//   docker run --rm --privileged -v "$PWD":/w:ro node:24-alpine sh -c "apk add --no-cache bubblewrap && node /w/packages/engine/scripts/sandbox-linux-check.mjs"
// --privileged lets bubblewrap create namespaces and mount /proc; without it the script reports the sandbox as unavailable.
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { detectSandbox, planSandbox } from "../dist/plugins/extensions/sandbox/index.js";

const status = detectSandbox();
console.log("detect:", JSON.stringify({ backend: status.backend, bwrap: status.bwrap.detail }));
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "lx-")));
const ext = path.join(tmp, "ext"); fs.mkdirSync(path.join(ext, "data"), { recursive: true }); fs.mkdirSync(path.join(ext, "scripts"));
fs.writeFileSync(path.join(ext, "data", "in.txt"), "own-data");
const home = os.homedir(); fs.mkdirSync(path.join(home, ".ssh"), { recursive: true });
const homeFile = path.join(home, ".ssh", "id_test"); fs.writeFileSync(homeFile, "home-secret");
const other = path.join(tmp, "other-repo"); fs.mkdirSync(other); fs.writeFileSync(path.join(other, "secret.txt"), "x");
const script = (n, body) => { const p = path.join(ext, "scripts", n); fs.writeFileSync(p, body, { mode: 0o755 }); return p; };
const server = http.createServer((_q, r) => r.end("pong")); await new Promise(r => server.listen(0, "127.0.0.1", r));
const port = server.address().port;

const exec = async (file, decl, argv = ["/bin/sh"]) => {
  const plan = planSandbox({ decl, extensionDir: ext, workspace: null, argv: [...argv, file], interpreters: ["sh", "bash", "node"], env: { PATH: process.env.PATH }, cwd: tmp, label: "linux check" }, { env: {}, status });
  if (plan.kind !== "sandboxed") return `NOT SANDBOXED ${JSON.stringify(plan)}`;
  const r = await new Promise(res => execFile(plan.file, plan.args, { cwd: plan.cwd, env: { ...process.env, ...plan.env }, timeout: 20000 }, (e, stdout, stderr) => res({ stdout, stderr, status: e ? (e.code ?? 1) : 0 })));
  plan.cleanup();
  return `${(r.stdout || "").trim().replace(/\n/g, " | ")}${r.stderr ? ` [stderr: ${r.stderr.trim().split("\n")[0]}]` : ""} (exit ${r.status})`;
};
const D = (o = {}) => ({ network: false, process: false, readPaths: [], writePaths: [], ...o });
const run = async (name, out) => console.log(`${name}: ${await out}`);

await run("own dir + scratch", exec(script("a.sh", `read -r a < "${ext}/data/in.txt"; echo own:$a; echo w > "$TMPDIR/o" && echo scratch-write-ok; read -r b < "$TMPDIR/o"; echo scratch-read:$b`), D()));
await run("home ssh + other repo", exec(script("b.sh", `if [ -e "${homeFile}" ]; then echo HOME-FILE-VISIBLE; else echo home-file-absent; fi; if [ -e "${other}/secret.txt" ]; then echo OTHER-VISIBLE; else echo other-repo-absent; fi`), D()));
await run("writes outside scratch", exec(script("c.sh", `mkdir -p "${tmp}/new" 2>/dev/null && echo LEAK-MKDIR || echo mkdir-outside-denied; if echo x > "${ext}/data/n"; then echo LEAK-OWN; else echo own-dir-write-denied; fi; if echo x > /etc/x 2>/dev/null; then echo LEAK-ETC; else echo etc-write-denied; fi`), D()));
await run("exec ls without process", exec(script("d.sh", `/bin/ls / >/dev/null 2>&1 && echo LEAK-EXEC || echo exec-denied`), D()));
await run("exec ls with process", exec(script("e.sh", `/bin/ls / >/dev/null 2>&1 && echo exec-ok || echo exec-denied`), D({ process: true })));
const net = script("f.sh", `/usr/bin/wget -q -T 3 -O - http://127.0.0.1:${port}/ && echo NET-OK || echo net-blocked`);
await run("loopback server, network off", exec(net, D({ process: true })));
await run("loopback server, network declared", exec(net, D({ process: true, network: true })));
const js = path.join(ext, "scripts", "n.js"); fs.writeFileSync(js, `const fs=require("fs");console.log("own="+fs.readFileSync("${ext}/data/in.txt","utf8"));try{fs.readFileSync("${homeFile}");console.log("LEAK")}catch(e){console.log("node-home-denied "+e.code)}`);
await run("node under sandbox", exec(js, D(), [process.execPath]));
server.close();
