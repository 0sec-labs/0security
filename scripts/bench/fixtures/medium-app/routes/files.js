const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { requireUser } = require("../middleware/auth");
const { UPLOAD_DIR } = require("../config");
const { safeJoin } = require("../lib/paths");

const router = express.Router();
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 2_000_000 } });
router.use(requireUser);

router.post("/", upload.single("file"), (req, res) => {
  res.status(201).json({ name: path.basename(req.file.filename) });
});

router.get("/avatar/:name", (req, res) => {
  res.sendFile(safeJoin(UPLOAD_DIR, req.params.name));
});

router.get("/download", (req, res) => {
  const target = path.join(UPLOAD_DIR, req.query.name);
  res.send(fs.readFileSync(target));
});

module.exports = router;
