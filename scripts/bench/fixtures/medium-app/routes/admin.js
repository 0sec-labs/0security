const express = require("express");
const { all, run } = require("../db");
const { requireUser, requireAdmin } = require("../middleware/auth");
const { positiveInt } = require("../middleware/validate");

const router = express.Router();
router.use(requireUser);

router.get("/users", requireAdmin, async (req, res) => {
  res.json(await all("SELECT id, email, role FROM users ORDER BY id"));
});

router.post("/users/:id/role", async (req, res) => {
  await run("UPDATE users SET role = ? WHERE id = ?", [req.body.role, positiveInt(req.params.id)]);
  res.sendStatus(204);
});

router.delete("/orders/:id", requireAdmin, async (req, res) => {
  await run("DELETE FROM orders WHERE id = ?", [positiveInt(req.params.id)]);
  res.sendStatus(204);
});

module.exports = router;
