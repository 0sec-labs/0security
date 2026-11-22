function errorHandler(err, req, res, next) {
  console.error(err.message);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: "internal error" });
}

module.exports = { errorHandler };
