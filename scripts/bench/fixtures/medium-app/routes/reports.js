const express = require("express");
const { requireUser, requireAdmin } = require("../middleware/auth");
const exporter = require("../services/exporter");

const router = express.Router();
router.use(requireUser, requireAdmin);

router.get("/sales", async (req, res) => {
  res.json(await exporter.salesTotals(req.query.from, req.query.to));
});

router.post("/sales/export", async (req, res) => {
  const file = await exporter.exportSales(req.body.name, req.body.format || "csv");
  res.json({ file });
});

router.get("/inventory", async (req, res) => {
  res.json(await exporter.inventoryTotals());
});

module.exports = router;
