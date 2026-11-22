"""Small reporting service that the shop backend calls for cached summaries."""
import pickle

from flask import Flask, jsonify, request

import store
from config import SNAPSHOT_LIMIT

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify(ok=True)


@app.route("/summary/<int:year>")
def summary(year):
    return jsonify(store.yearly_summary(year))


@app.route("/snapshot", methods=["POST"])
def snapshot():
    data = request.get_data()
    if len(data) > SNAPSHOT_LIMIT:
        return jsonify(error="too large"), 413
    state = pickle.loads(data)
    store.save_snapshot(state)
    return jsonify(saved=len(state))


@app.route("/snapshot/latest")
def latest_snapshot():
    return jsonify(store.latest_snapshot())


if __name__ == "__main__":
    app.run(port=5001)
