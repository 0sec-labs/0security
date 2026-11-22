const express = require("express");
const { all, get, run } = require("../db");
const { requireUser, requireAdmin } = require("../middleware/auth");
const { positiveInt } = require("../middleware/validate");
const { PAGE_SIZE } = require("../config");

const router = express.Router();

router.get("/", async (req, res) => {
  const page = positiveInt(req.query.page) || 1;
  res.json(await all("SELECT id, name, price_cents FROM products ORDER BY id LIMIT ? OFFSET ?", [PAGE_SIZE, (page - 1) * PAGE_SIZE]));
});

router.get("/:id", async (req, res) => {
  const id = positiveInt(req.params.id);
  if (!id) return res.sendStatus(400);
  const product = await get("SELECT * FROM products WHERE id = ?", [id]);
  product ? res.json(product) : res.sendStatus(404);
});

router.post("/", requireUser, requireAdmin, async (req, res) => {
  const result = await run("INSERT INTO products(name, price_cents) VALUES(?, ?)", [req.body.name, req.body.priceCents]);
  res.status(201).json({ id: result.lastID });
});

router.delete("/:id", requireUser, requireAdmin, async (req, res) => {
  await run("DELETE FROM products WHERE id = ?", [positiveInt(req.params.id)]);
  res.sendStatus(204);
});

module.exports = router;
