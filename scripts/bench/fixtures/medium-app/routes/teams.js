const express = require("express");
const { all, get, run } = require("../db");
const { requireUser } = require("../middleware/auth");
const { positiveInt, requireFields } = require("../middleware/validate");

const router = express.Router();
router.use(requireUser);

router.get("/", async (req, res) => {
  res.json(await all("SELECT t.id, t.name FROM teams t JOIN memberships m ON m.team_id = t.id WHERE m.user_id = ?", [req.user.id]));
});

router.post("/", requireFields("name"), async (req, res) => {
  const result = await run("INSERT INTO teams(name, owner_id) VALUES(?, ?)", [req.body.name, req.user.id]);
  res.status(201).json({ id: result.lastID });
});

router.post("/:id/members", requireFields("userId"), async (req, res) => {
  const id = positiveInt(req.params.id);
  const team = await get("SELECT * FROM teams WHERE id = ? AND owner_id = ?", [id, req.user.id]);
  if (!team) return res.sendStatus(403);
  await run("INSERT INTO memberships(team_id, user_id) VALUES(?, ?)", [id, positiveInt(req.body.userId)]);
  res.sendStatus(204);
});

module.exports = router;
