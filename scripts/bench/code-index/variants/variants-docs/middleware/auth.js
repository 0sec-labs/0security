const { docs } = require("../db");

function loadUser(req, _res, next) {
  req.user = req.get("x-user-id") ? { id: req.get("x-user-id") } : undefined;
  next();
}

function requireUser(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  next();
}

// Throws unless the signed-in user owns the document.
function assertDocOwner(req, doc) {
  if (!doc || doc.ownerId !== req.user.id) {
    const err = new Error("not found");
    err.status = 404;
    throw err;
  }
}

function requireDocOwner(req, res, next) {
  const doc = docs.get(req.params.id);
  if (!doc || doc.ownerId !== req.user.id) return res.sendStatus(404);
  req.doc = doc;
  next();
}

module.exports = { loadUser, requireUser, assertDocOwner, requireDocOwner };
