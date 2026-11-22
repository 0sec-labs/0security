"""Clean fixture: a small bookmark service. Every risky-looking pattern here is the safe form."""
import hashlib
import hmac
import json
import os
import sqlite3
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, jsonify, render_template_string, request

app = Flask(__name__)
API_TOKEN = os.environ["API_TOKEN"]
ALLOWED_HOSTS = {"example.org", "docs.example.org"}
PAGE = "<h1>{{ title }}</h1><p>{{ note }}</p>"


def db():
    return sqlite3.connect("bookmarks.db")


def require_token():
    given = request.headers.get("X-Token", "")
    if not hmac.compare_digest(given.encode(), API_TOKEN.encode()):
        abort(403)


@app.route("/bookmarks")
def bookmarks():
    rows = db().execute("SELECT id, title FROM bookmarks WHERE owner = ?", (request.args.get("owner", ""),))
    return jsonify([{"id": r[0], "title": r[1]} for r in rows])


@app.route("/bookmarks/<int:bookmark_id>/page")
def page(bookmark_id):
    row = db().execute("SELECT title, note FROM bookmarks WHERE id = ?", (bookmark_id,)).fetchone()
    if row is None:
        abort(404)
    return render_template_string(PAGE, title=row[0], note=row[1])


@app.route("/preview")
def preview():
    host = urlparse(request.args["url"]).hostname
    if host not in ALLOWED_HOSTS:
        abort(400)
    resp = requests.get(f"https://{host}/", timeout=5, allow_redirects=False)
    return jsonify({"status": resp.status_code})


@app.route("/import", methods=["POST"])
def import_bookmarks():
    require_token()
    data = yaml.safe_load(request.data)
    return jsonify({"count": len(data or [])})


@app.route("/register", methods=["POST"])
def register():
    salt = os.urandom(16)
    digest = hashlib.scrypt(request.form["password"].encode(), salt=salt, n=2**14, r=8, p=1)
    db().execute("INSERT INTO users (name, salt, hash) VALUES (?, ?, ?)", (request.form["name"], salt, digest))
    return "", 201


@app.route("/etag")
def etag():
    body = json.dumps(sorted(os.listdir("static")))
    return jsonify({"etag": hashlib.sha1(body.encode()).hexdigest()})
