"""
Web dashboard — Flask app for viewing scan results.
"""

import os
from datetime import datetime

from flask import Flask, jsonify, render_template, request

from ..storage import Storage

app = Flask(__name__)
app.secret_key = os.getenv("DASHBOARD_SECRET_KEY", "change-me-in-production")

_storage = None


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(get_storage().get_stats())


@app.route("/api/hits")
def api_hits():
    limit = int(request.args.get("limit", 50))
    keyword = request.args.get("keyword")
    storage = get_storage()
    if keyword:
        records = storage.get_hits_by_keyword(keyword, limit=limit)
    else:
        records = storage.get_recent_hits(limit=limit)

    return jsonify([
        {
            "id": r.id,
            "url": r.url,
            "keyword": r.keyword,
            "category": r.category,
            "context": r.context,
            "depth": r.depth,
            "found_at": r.found_at.isoformat() if r.found_at else None,
            "alerted": r.alerted,
        }
        for r in records
    ])


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


def create_app():
    return app


if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
