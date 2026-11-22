const express = require("express");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");
const { requireFields } = require("../middleware/validate");
const users = require("../services/userService");

const router = express.Router();

router.post("/register", requireFields("email", "password"), async (req, res) => {
  const user = await users.create(req.body.email, req.body.password);
  res.status(201).json({ id: user.id });
});

router.post("/login", requireFields("email", "password"), async (req, res) => {
  const user = await users.verify(req.body.email, req.body.password);
  if (!user) return res.sendStatus(401);
  res.json({ token: jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "8h" }) });
});

router.post("/logout", (req, res) => res.sendStatus(204));

module.exports = router;
