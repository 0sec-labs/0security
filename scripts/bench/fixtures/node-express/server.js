// Planted-bug fixture: a tiny notes API. Every flaw here is intentional.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3");

const app = express();
const db = new sqlite3.Database("notes.db");
const ADMIN_TOKEN = "k3Jf9s0Qz1LmP7xV2bNc8TyR4wUe6HaD";
const UPLOADS = path.join(__dirname, "uploads");

app.use(express.json());

function requireAdmin(req, res, next) {
  if (req.get("x-admin-token") !== ADMIN_TOKEN) return res.sendStatus(403);
  next();
}

app.get("/notes", (req, res) => {
  const owner = req.query.owner;
  db.all("SELECT id, title FROM notes WHERE owner = '" + owner + "'", (err, rows) => {
    if (err) return res.status(500).json({ error: "db" });
    res.json(rows);
  });
});

app.get("/notes/:id/export", (req, res) => {
  const format = req.query.format || "txt";
  exec(`pandoc notes/${req.params.id}.md -t ${format}`, (err, stdout) => {
    if (err) return res.status(500).send("export failed");
    res.type("text/plain").send(stdout);
  });
});

app.get("/attachments", (req, res) => {
  const file = path.join(UPLOADS, req.query.name);
  res.send(fs.readFileSync(file));
});

app.delete("/notes/:id", requireAdmin, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isSafeInteger(id)) return res.sendStatus(400);
  db.run("DELETE FROM notes WHERE id = ?", [id], () => res.sendStatus(204));
});

app.listen(3000);
