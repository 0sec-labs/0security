"""Planted-bug fixture: a small link-preview service. Every flaw here is intentional."""
import hashlib
import pickle
import base64

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/preview")
def preview():
    url = request.args["url"]
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "title": resp.text[:80]})


@app.route("/session/restore", methods=["POST"])
def restore_session():
    blob = base64.b64decode(request.form["session"])
    session = pickle.loads(blob)
    return jsonify({"user": session.get("user")})


@app.route("/config/import", methods=["POST"])
def import_config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({"keys": sorted(cfg)})


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    stored = hash_password(request.form["password"])
    return jsonify({"hash": stored})


@app.route("/health")
def health():
    # Fixed internal URL; no user input reaches it.
    return jsonify({"upstream": requests.get("http://localhost:9000/ping", timeout=2).status_code})


if __name__ == "__main__":
    app.run()
