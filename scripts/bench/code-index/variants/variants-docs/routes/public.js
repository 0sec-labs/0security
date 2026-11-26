const router = require("express").Router();
const { docs } = require("../db");

// Published documents are public on purpose: only the ones the owner published, by slug.
router.get("/public/:slug", (req, res) => {
  const doc = [...docs.values()].find((d) => d.published && d.slug === req.params.slug);
  if (!doc) return res.sendStatus(404);
  res.json({ title: doc.title, body: doc.body });
});

module.exports = router;
