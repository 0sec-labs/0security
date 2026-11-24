// INTENTIONALLY VULNERABLE TEST FIXTURE. Not product code. Never deploy it.
// MIT licensed, written for this repository. Used only by the reproduction tests (`findings reproduce`).
//
// Planted flaw: the download route joins the requested name to the public folder without checking where it lands,
// so `../` reads files outside the public folder. That is the point of this fixture.
//
// Safeguards: it binds to 127.0.0.1 only, it has no package.json and no script that starts it, no CI job runs it, and
// it refuses to start unless the caller sets REPRO_FIXTURE_ACK=intentionally-vulnerable.
// It uses only Node built-ins so it starts in a container with no network and no installed packages.
const http = require("http");
const fs = require("fs");
const path = require("path");

if (process.env.REPRO_FIXTURE_ACK !== "intentionally-vulnerable") {
  console.error("This is an intentionally vulnerable test fixture. Set REPRO_FIXTURE_ACK=intentionally-vulnerable to start it.");
  process.exit(2);
}

const ROOT = path.join(__dirname, "public");

http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname !== "/download") { res.writeHead(404); res.end("not found"); return; }
  const file = path.join(ROOT, url.searchParams.get("name") || ""); // planted flaw: no containment check
  fs.readFile(file, (error, data) => {
    if (error) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(data);
  });
}).listen(Number(process.env.PORT || 3000), "127.0.0.1");
