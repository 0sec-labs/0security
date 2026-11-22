const crypto = require("crypto");
const express = require("express");
const { run } = require("../db");

const router = express.Router();
const SIGNING_KEY = process.env.PAYMENT_WEBHOOK_KEY || "";

function validSignature(raw, header) {
  const expected = crypto.createHmac("sha256", SIGNING_KEY).update(raw).digest("hex");
  const given = Buffer.from(String(header || ""), "hex");
  const want = Buffer.from(expected, "hex");
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}

router.post("/payments", express.raw({ type: "application/json" }), async (req, res) => {
  if (!SIGNING_KEY || !validSignature(req.body, req.get("x-signature"))) return res.sendStatus(401);
  const event = JSON.parse(req.body.toString("utf8"));
  if (event.type === "payment.succeeded") await run("UPDATE orders SET status = 'paid' WHERE id = ?", [event.orderId]);
  res.sendStatus(204);
});

router.post("/shipping", express.raw({ type: "application/json" }), async (req, res) => {
  if (!SIGNING_KEY || !validSignature(req.body, req.get("x-signature"))) return res.sendStatus(401);
  const event = JSON.parse(req.body.toString("utf8"));
  await run("UPDATE orders SET status = 'shipped' WHERE id = ? AND status = 'paid'", [event.orderId]);
  res.sendStatus(204);
});

module.exports = router;
