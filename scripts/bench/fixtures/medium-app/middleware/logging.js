function requestLog(req, res, next) {
  const started = Date.now();
  res.on("finish", () => {
    console.log(JSON.stringify({ method: req.method, url: req.originalUrl, status: res.statusCode, ms: Date.now() - started }));
  });
  next();
}

module.exports = { requestLog };
