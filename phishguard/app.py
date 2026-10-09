"""ThreatGuard / PhishGuard backend: Flask + SQLite.

Run:   python app.py
Env:   PHISHGUARD_TOKEN  shared secret for the API (strongly recommended)
       PHISHGUARD_DB     path to the SQLite file (default: phishguard.db)
       PORT              default 5000
"""
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory

from detector import analyze, status_for, threat_type

BASE = Path(__file__).parent
DB_PATH = os.environ.get("PHISHGUARD_DB", str(BASE / "phishguard.db"))
TOKEN = os.environ.get("PHISHGUARD_TOKEN", "")
MAX_BODY = 5000
MAX_SENDER = 80

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript((BASE / "schema.sql").read_text())


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def access_allowed():
    row = get_db().execute("SELECT value FROM settings WHERE key = 'access'").fetchone()
    return bool(row and row["value"] == "1")


def row_to_dict(row):
    result = analyze(row["body"])
    return {
        "id": row["id"],
        "sender": row["sender"],
        "channel": row["channel"],
        "body": row["body"],
        "time": row["received_at"],
        "score": row["score"],
        "level": row["level"],
        "threat_type": row["threat_type"],
        "status": row["status"],
        "hits": json.loads(row["signals"]),
        "ranges": result["ranges"],
        "archived": bool(row["archived"]),
    }


def store_message(sender, channel, body):
    result = analyze(body)
    db = get_db()
    cur = db.execute(
        """INSERT INTO messages
           (sender, channel, body, received_at, score, level, threat_type, status, signals)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            sender,
            channel,
            body,
            now_iso(),
            result["score"],
            result["level"],
            threat_type(result["level"], channel),
            status_for(result["level"]),
            json.dumps(result["hits"]),
        ),
    )
    db.commit()
    row = db.execute("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,)).fetchone()
    return row_to_dict(row)


def read_payload():
    data = request.get_json(silent=True) or {}
    body = str(data.get("body", "")).strip()[:MAX_BODY]
    sender = str(data.get("sender", "")).strip()[:MAX_SENDER]
    channel = str(data.get("channel", "")).strip()[:20]
    return sender, channel, body


# -------------------------------------------------------------------- auth
@app.before_request
def require_token():
    if not request.path.startswith("/api/") or not TOKEN:
        return None
    supplied = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(supplied.encode(), TOKEN.encode()):
        return jsonify(error="unauthorized"), 401
    return None


# --------------------------------------------------------------------- API
@app.get("/api/state")
def state():
    return jsonify(access=access_allowed(), auth_required=bool(TOKEN))


@app.post("/api/access")
def set_access():
    allowed = bool((request.get_json(silent=True) or {}).get("allowed"))
    db = get_db()
    db.execute("UPDATE settings SET value = ? WHERE key = 'access'", ("1" if allowed else "0",))
    if not allowed:
        db.execute("UPDATE messages SET archived = 1 WHERE channel != 'Manual'")
    db.commit()
    return jsonify(access=allowed)


@app.get("/api/messages")
def list_messages():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    rows = get_db().execute(
        "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify(messages=[row_to_dict(r) for r in rows])


@app.post("/api/messages")
def ingest():
    """Receive a message (from the app, a share, or a phone automation)."""
    if not access_allowed():
        return jsonify(error="access is turned off"), 403
    sender, channel, body = read_payload()
    if not body:
        return jsonify(error="body is required"), 400
    return jsonify(store_message(sender or "Unknown", channel or "SMS", body)), 201


@app.post("/api/scan")
def scan():
    """Manual scan from the Scan page. Always allowed."""
    sender, _channel, body = read_payload()
    if not body:
        return jsonify(error="body is required"), 400
    return jsonify(store_message(sender or "Manual scan", "Manual", body)), 201


@app.post("/api/inbox/clear")
def clear_inbox():
    db = get_db()
    db.execute("UPDATE messages SET archived = 1 WHERE channel != 'Manual'")
    db.commit()
    return jsonify(ok=True)


@app.get("/api/stats")
def stats():
    row = get_db().execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(level = 'high'), 0) AS high,
                  COALESCE(SUM(level = 'low'), 0)  AS clean
           FROM messages"""
    ).fetchone()
    return jsonify(total=row["total"], high=row["high"], clean=row["clean"])


# ------------------------------------------------------------------- pages
@app.get("/")
@app.get("/share")
def index():
    return send_from_directory(app.static_folder, "index.html")


init_db()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=int(os.environ.get("PORT", 5000)), debug=False)
