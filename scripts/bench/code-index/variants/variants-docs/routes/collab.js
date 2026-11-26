const router = require("express").Router();
const { docs, comments } = require("../db");
const { requireUser } = require("../middleware/auth");

router.post("/docs/:id/share", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  if (!doc) return res.sendStatus(404);
  doc.shared.push(String(req.body.userId));
  res.json({ shared: doc.shared });
});

// Comments: the owner or a user the document is shared with may read.
router.get("/docs/:id/comments", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  if (!doc || (doc.ownerId !== req.user.id && !doc.shared.includes(req.user.id))) return res.sendStatus(404);
  res.json(comments.filter((c) => c.docId === doc.id));
});

router.post("/docs/:id/comments", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  if (!doc || (doc.ownerId !== req.user.id && !doc.shared.includes(req.user.id))) return res.sendStatus(404);
  comments.push({ docId: doc.id, authorId: req.user.id, text: String(req.body.text) });
  res.sendStatus(201);
});

module.exports = router;
