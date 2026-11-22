// Clean fixture: looks like the node-express fixture but every pattern is the safe form.
const express = require("express");
const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");

const app = express();
const db = new sqlite3.Database("notes.db");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const UPLOADS = path.resolve(__dirname, "uploads");
const FORMATS = new Set(["txt", "html", "docx"]);

app.use(express.json());

function requireAdmin(req, res, next) {
  const given = Buffer.from(req.get("x-admin-token") || "");
  const want = Buffer.from(ADMIN_TOKEN || "");
  if (!want.length || given.length !== want.length || !crypto.timingSafeEqual(given, want)) return res.sendStatus(403);
  next();
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

app.get("/notes", (req, res) => {
  db.all("SELECT id, title FROM notes WHERE owner = ?", [String(req.query.owner)], (err, rows) => {
    if (err) return res.status(500).json({ error: "db" });
    res.json(rows);
  });
});

app.get("/notes/:id/page", (req, res) => {
  db.get("SELECT title FROM notes WHERE id = ?", [Number(req.params.id)], (err, row) => {
    if (err || !row) return res.sendStatus(404);
    res.send(`<h1>${escapeHtml(row.title)}</h1>`);
  });
});

app.get("/notes/:id/export", (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  const format = String(req.query.format || "txt");
  if (!Number.isSafeInteger(id) || !FORMATS.has(format)) return res.sendStatus(400);
  execFile("pandoc", [`notes/${id}.md`, "-t", format], (err, stdout) => {
    if (err) return res.status(500).send("export failed");
    res.type("text/plain").send(stdout);
  });
});

app.get("/attachments", (req, res) => {
  const file = path.resolve(UPLOADS, String(req.query.name));
  if (!file.startsWith(UPLOADS + path.sep)) return res.sendStatus(400);
  res.send(fs.readFileSync(file));
});

app.delete("/notes/:id", requireAdmin, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isSafeInteger(id)) return res.sendStatus(400);
  db.run("DELETE FROM notes WHERE id = ?", [id], () => res.sendStatus(204));
});

app.listen(3000);
