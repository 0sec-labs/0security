const express = require("express");
const { get } = require("../db");
const { requireUser } = require("../middleware/auth");
const { positiveInt } = require("../middleware/validate");
const pdf = require("../services/pdf");

const router = express.Router();
router.use(requireUser);

router.get("/:orderId", async (req, res) => {
  const orderId = positiveInt(req.params.orderId);
  const order = await get("SELECT * FROM orders WHERE id = ? AND user_id = ?", [orderId, req.user.id]);
  if (!order) return res.sendStatus(404);
  res.type("application/pdf").send(await pdf.render(order));
});

router.get("/:orderId/summary", async (req, res) => {
  const orderId = positiveInt(req.params.orderId);
  const order = await get("SELECT id, status, total_cents FROM orders WHERE id = ? AND user_id = ?", [orderId, req.user.id]);
  order ? res.json(order) : res.sendStatus(404);
});

module.exports = router;
