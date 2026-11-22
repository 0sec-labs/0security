const https = require("https");
const http = require("http");

function postJson(url, payload) {
  const target = new URL(url);
  const client = target.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = client.request(target, { method: "POST", headers: { "content-type": "application/json" }, timeout: 5000 }, res => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.end(JSON.stringify(payload));
  });
}

module.exports = { postJson };
