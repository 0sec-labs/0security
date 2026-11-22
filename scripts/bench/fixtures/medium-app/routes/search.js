const express = require("express");
const { all } = require("../db");
const { positiveInt } = require("../middleware/validate");

const router = express.Router();

router.get("/products", async (req, res) => {
  const term = `%${req.query.q || ""}%`;
  res.json(await all("SELECT id, name FROM products WHERE name LIKE ? LIMIT 50", [term]));
});

router.get("/orders", async (req, res) => {
  const status = req.query.status || "paid";
  const sort = req.query.sort || "id";
  const rows = await all(`SELECT id, status, total_cents FROM orders WHERE status = '${status}' ORDER BY ${sort}`);
  res.json(rows);
});

router.get("/users/:id/orders", async (req, res) => {
  const id = positiveInt(req.params.id);
  res.json(await all("SELECT id, status FROM orders WHERE user_id = ?", [id]));
});

module.exports = router;
