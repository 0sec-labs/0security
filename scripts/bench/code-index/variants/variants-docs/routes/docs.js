const router = require("express").Router();
const { docs } = require("../db");
const { requireUser, assertDocOwner, requireDocOwner } = require("../middleware/auth");

router.get("/docs", requireUser, (req, res) => {
  res.json([...docs.values()].filter((d) => d.ownerId === req.user.id));
});

router.post("/docs", requireUser, (req, res) => {
  const doc = { id: String(docs.size + 1), ownerId: req.user.id, title: req.body.title, body: req.body.body, versions: [], shared: [] };
  docs.set(doc.id, doc);
  res.status(201).json(doc);
});

// Ownership check added here after the first report (read of someone else's document).
router.get("/docs/:id", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  assertDocOwner(req, doc);
  res.json(doc);
});

router.put("/docs/:id", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  if (!doc) return res.sendStatus(404);
  doc.versions.push(doc.body);
  doc.body = req.body.body;
  res.json(doc);
});

router.delete("/docs/:id", requireUser, (req, res) => {
  docs.delete(req.params.id);
  res.sendStatus(204);
});

router.get("/docs/:id/export", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  if (!doc) return res.sendStatus(404);
  res.type("text/markdown").send(`# ${doc.title}\n\n${doc.body}`);
});

router.get("/docs/:id/versions", requireUser, (req, res) => {
  const doc = docs.get(req.params.id);
  if (!doc) return res.sendStatus(404);
  res.json(doc.versions);
});

router.patch("/docs/:id/title", requireUser, requireDocOwner, (req, res) => {
  req.doc.title = req.body.title;
  res.json(req.doc);
});

router.post("/docs/bulk-delete", requireUser, (req, res) => {
  for (const id of req.body.ids) docs.delete(String(id));
  res.sendStatus(204);
});

module.exports = router;
