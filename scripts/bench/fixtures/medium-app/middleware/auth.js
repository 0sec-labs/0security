const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");

function requireUser(req, res, next) {
  const header = req.get("authorization") || "";
  try {
    req.user = jwt.verify(header.replace(/^Bearer /, ""), JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.sendStatus(403);
  next();
}

module.exports = { requireUser, requireAdmin };
