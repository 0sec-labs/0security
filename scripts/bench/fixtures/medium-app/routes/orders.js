const express = require("express");
const { all, get, run } = require("../db");
const { requireUser } = require("../middleware/auth");
const { positiveInt, requireFields } = require("../middleware/validate");
const orders = require("../services/orderService");

const router = express.Router();
router.use(requireUser);

router.get("/", async (req, res) => {
  res.json(await all("SELECT id, status, total_cents FROM orders WHERE user_id = ? ORDER BY id DESC", [req.user.id]));
});

router.post("/", requireFields("items"), async (req, res) => {
  const order = await orders.place(req.user.id, req.body.items);
  res.status(201).json(order);
});

router.get("/:id", async (req, res) => {
  const id = positiveInt(req.params.id);
  if (!id) return res.sendStatus(400);
  const order = await get("SELECT * FROM orders WHERE id = ?", [id]);
  order ? res.json(order) : res.sendStatus(404);
});

router.post("/:id/cancel", async (req, res) => {
  const id = positiveInt(req.params.id);
  const order = await get("SELECT * FROM orders WHERE id = ? AND user_id = ?", [id, req.user.id]);
  if (!order) return res.sendStatus(404);
  await run("UPDATE orders SET status = 'cancelled' WHERE id = ?", [id]);
  res.sendStatus(204);
});

module.exports = router;
