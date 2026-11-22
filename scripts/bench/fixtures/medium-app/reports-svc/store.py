import json
import sqlite3

from config import DB_PATH


def _conn():
    return sqlite3.connect(DB_PATH)


def yearly_summary(year):
    with _conn() as conn:
        rows = conn.execute(
            "SELECT strftime('%m', created_at) AS month, SUM(total_cents) FROM orders WHERE strftime('%Y', created_at) = ? GROUP BY month",
            (str(year),),
        ).fetchall()
    return {month: cents for month, cents in rows}


def save_snapshot(state):
    with _conn() as conn:
        conn.execute("INSERT INTO snapshots(body) VALUES (?)", (json.dumps(state, default=str),))


def latest_snapshot():
    with _conn() as conn:
        row = conn.execute("SELECT body FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else {}
