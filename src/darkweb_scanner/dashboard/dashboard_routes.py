"""
Dashboard blueprint — all protected routes.
"""

from datetime import datetime
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from ..auth import require_login
from .app import get_storage

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@require_login
def index():
    return render_template("index.html", username=session.get("username"))


@dashboard_bp.route("/api/stats")
@require_login
def api_stats():
    return jsonify(get_storage().get_stats())


@dashboard_bp.route("/api/hits")
@require_login
def api_hits():
    limit = int(request.args.get("limit", 50))
    keyword = request.args.get("keyword")
    storage = get_storage()
    records = storage.get_hits_by_keyword(keyword, limit=limit) if keyword else storage.get_recent_hits(limit=limit)
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


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})
