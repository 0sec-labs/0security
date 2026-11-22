const express = require("express");
const { all, run } = require("../db");
const { requireUser } = require("../middleware/auth");
const { requireFields } = require("../middleware/validate");
const { postJson } = require("../lib/http");

const router = express.Router();
router.use(requireUser);

router.get("/", async (req, res) => {
  res.json(await all("SELECT id, text, read FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50", [req.user.id]));
});

router.post("/read", async (req, res) => {
  await run("UPDATE notifications SET read = 1 WHERE user_id = ?", [req.user.id]);
  res.sendStatus(204);
});

router.post("/hook", requireFields("url"), async (req, res) => {
  const status = await postJson(req.body.url, { text: "Test notification from the shop" });
  res.json({ delivered: status < 400 });
});

module.exports = router;
