// The same app with the flaw fixed: the resolved path must stay inside the public folder.
// MIT licensed, written for this repository.
const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "public");

http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname !== "/download") { res.writeHead(404); res.end("not found"); return; }
  const file = path.resolve(ROOT, url.searchParams.get("name") || "");
  if (!file.startsWith(ROOT + path.sep)) { res.writeHead(400); res.end("bad name"); return; }
  fs.readFile(file, (error, data) => {
    if (error) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(data);
  });
}).listen(Number(process.env.PORT || 3000), "127.0.0.1");
