// TEST FIXTURE: the same app as ../vulnerable with the flaw fixed. The resolved path must stay inside the public folder.
// MIT licensed, written for this repository. Binds to 127.0.0.1 only. Has no package.json and no start script.
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
