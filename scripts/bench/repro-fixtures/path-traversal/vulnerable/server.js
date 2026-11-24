// INTENTIONALLY VULNERABLE TEST FIXTURE. Not product code. Never deploy it.
// MIT licensed, written for this repository. Used only by the reproduction tests (`findings reproduce`).
//
// Planted flaw: the download route joins the requested name to the public folder without checking that the result
// stays inside it, so `../` reads files outside the public folder. That is the point of this fixture.
//
// Blast radius, kept small on purpose:
// - It serves only inside the folder that holds its own copy (the harness-created temp folder, or / inside a
//   container). Anything above that is refused, so `../` cannot reach the real file system of a host.
// - It refuses to run with / as that limit unless it is inside a container.
// - It binds to 127.0.0.1 only and refuses any peer that is not loopback.
// - It has no package.json and no script that starts it, no CI job runs it, and it exits unless the caller sets
//   REPRO_FIXTURE_ACK=intentionally-vulnerable.
// It uses only Node built-ins so it starts in a container with no network and no installed packages.
const http = require("http");
const fs = require("fs");
const path = require("path");

if (process.env.REPRO_FIXTURE_ACK !== "intentionally-vulnerable") {
  console.error("This is an intentionally vulnerable test fixture. Set REPRO_FIXTURE_ACK=intentionally-vulnerable to start it.");
  process.exit(2);
}

const ROOT = path.join(__dirname, "public");
const LIMIT = path.dirname(__dirname);
if (LIMIT === path.parse(LIMIT).root && !fs.existsSync("/.dockerenv") && !fs.existsSync("/run/.containerenv")) {
  console.error("Refusing to serve the file system root outside a container.");
  process.exit(2);
}
const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

http.createServer((req, res) => {
  if (!LOOPBACK.has(req.socket.remoteAddress)) { res.writeHead(403); res.end("loopback only"); return; }
  const url = new URL(req.url, "http://localhost");
  if (url.pathname !== "/download") { res.writeHead(404); res.end("not found"); return; }
  const file = path.join(ROOT, url.searchParams.get("name") || ""); // planted flaw: not kept inside ROOT
  const rel = path.relative(LIMIT, file);
  if (rel.startsWith("..") || path.isAbsolute(rel)) { res.writeHead(403); res.end("outside the fixture"); return; }
  fs.readFile(file, (error, data) => {
    if (error) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(data);
  });
}).listen(Number(process.env.PORT || 3000), "127.0.0.1");
