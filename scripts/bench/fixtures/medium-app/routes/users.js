const express = require("express");
const { requireUser } = require("../middleware/auth");
const { get, run } = require("../db");

const router = express.Router();
router.use(requireUser);

router.get("/me", async (req, res) => {
  res.json(await get("SELECT id, email, role FROM users WHERE id = ?", [req.user.id]));
});

router.put("/me", async (req, res) => {
  await run("UPDATE users SET display_name = ? WHERE id = ?", [String(req.body.displayName || "").slice(0, 80), req.user.id]);
  res.sendStatus(204);
});

router.get("/:id/card", async (req, res) => {
  const user = await get("SELECT display_name FROM users WHERE id = ?", [req.params.id]);
  if (!user) return res.status(404).send(`<p>No user named ${req.query.name}</p>`);
  res.send(`<h1>${user.display_name}</h1>`);
});

router.delete("/me", async (req, res) => {
  await run("DELETE FROM users WHERE id = ?", [req.user.id]);
  res.sendStatus(204);
});

module.exports = router;
