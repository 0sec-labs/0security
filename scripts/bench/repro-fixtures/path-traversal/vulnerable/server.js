// Planted-bug fixture for reproduction tests. MIT licensed, written for this repository.
// Flaw: the download route joins the requested name to the public folder without checking where it lands.
// It uses only Node built-ins so it starts in a container with no network and no installed packages.
const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "public");

http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname !== "/download") { res.writeHead(404); res.end("not found"); return; }
  const file = path.join(ROOT, url.searchParams.get("name") || "");
  fs.readFile(file, (error, data) => {
    if (error) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(data);
  });
}).listen(Number(process.env.PORT || 3000), "127.0.0.1");
