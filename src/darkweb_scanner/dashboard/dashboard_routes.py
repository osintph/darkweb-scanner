"""
Dashboard blueprint — all protected routes.
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from ..auth import hash_password, require_login, validate_password_strength
from .storage_helper import get_storage

dashboard_bp = Blueprint("dashboard", __name__)

CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "/app/config"))
KEYWORDS_FILE = CONFIG_DIR / "keywords.yaml"
SEEDS_FILE = CONFIG_DIR / "seeds.txt"


# ── Pages ──────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/dashboard")
@require_login
def index():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    return render_template("index.html", username=session.get("username"), is_admin=user.is_admin)


# ── Stats & Hits API ───────────────────────────────────────────────────────────


@dashboard_bp.route("/api/stats")
@require_login
def api_stats():
    return jsonify(get_storage().get_stats())


@dashboard_bp.route("/api/hits")
@require_login
def api_hits():
    limit = int(request.args.get("limit", 100))
    keyword = request.args.get("keyword")
    storage = get_storage()
    records = (
        storage.get_hits_by_keyword(keyword, limit=limit)
        if keyword
        else storage.get_recent_hits(limit=limit)
    )
    return jsonify(
        [
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
        ]
    )


# ── Keywords API ───────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords", methods=["GET"])
@require_login
def api_keywords_get():
    try:
        import yaml

        if not KEYWORDS_FILE.exists():
            return jsonify({"categories": {}})
        data = yaml.safe_load(KEYWORDS_FILE.read_text()) or {}
        return jsonify({"categories": data.get("keywords", {})})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/keywords", methods=["POST"])
@require_login
def api_keywords_add():
    try:
        import yaml

        body = request.get_json()
        keyword = (body.get("keyword") or "").strip()
        category = (body.get("category") or "custom").strip()
        if not keyword:
            return jsonify({"error": "keyword required"}), 400

        data = {}
        if KEYWORDS_FILE.exists():
            data = yaml.safe_load(KEYWORDS_FILE.read_text()) or {}
        data.setdefault("keywords", {}).setdefault(category, [])
        if keyword not in data["keywords"][category]:
            data["keywords"][category].append(keyword)
            KEYWORDS_FILE.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/keywords", methods=["DELETE"])
@require_login
def api_keywords_delete():
    try:
        import yaml

        body = request.get_json()
        keyword = (body.get("keyword") or "").strip()
        category = (body.get("category") or "").strip()
        if not keyword or not category:
            return jsonify({"error": "keyword and category required"}), 400

        if not KEYWORDS_FILE.exists():
            return jsonify({"ok": True})
        data = yaml.safe_load(KEYWORDS_FILE.read_text()) or {}
        kws = data.get("keywords", {}).get(category, [])
        if keyword in kws:
            kws.remove(keyword)
            data["keywords"][category] = kws
            KEYWORDS_FILE.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Seeds API ──────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds", methods=["GET"])
@require_login
def api_seeds_get():
    try:
        if not SEEDS_FILE.exists():
            return jsonify({"seeds": []})
        seeds = [
            line.strip()
            for line in SEEDS_FILE.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return jsonify({"seeds": seeds})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/seeds", methods=["POST"])
@require_login
def api_seeds_add():
    try:
        body = request.get_json()
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        if not url.startswith("http"):
            return jsonify({"error": "URL must start with http"}), 400

        existing = []
        if SEEDS_FILE.exists():
            existing = SEEDS_FILE.read_text().splitlines()
        if url not in existing:
            existing.append(url)
            SEEDS_FILE.write_text("\n".join(existing) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/seeds", methods=["DELETE"])
@require_login
def api_seeds_delete():
    try:
        body = request.get_json()
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400

        if not SEEDS_FILE.exists():
            return jsonify({"ok": True})
        lines = [l for l in SEEDS_FILE.read_text().splitlines() if l.strip() != url]
        SEEDS_FILE.write_text("\n".join(lines) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Crawl control API ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/crawl/start", methods=["POST"])
@require_login
def api_crawl_start():
    try:
        # Check if already running
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=scanner", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        if "scanner" in result.stdout:
            return jsonify({"error": "Crawl already running"}), 409

        subprocess.Popen(
            ["docker", "compose", "--profile", "scan", "run", "--rm", "scanner"],
            cwd="/app",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return jsonify({"ok": True, "message": "Crawl started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/crawl/status", methods=["GET"])
@require_login
def api_crawl_status():
    try:
        storage = get_storage()
        stats = storage.get_stats()
        active = storage.get_active_session()
        return jsonify(
            {
                "active": active is not None,
                "session": (
                    {
                        "id": active.id,
                        "started_at": active.started_at.isoformat() if active else None,
                        "pages_crawled": active.pages_crawled if active else 0,
                        "hits_found": active.hits_found if active else 0,
                    }
                    if active
                    else None
                ),
                "stats": stats,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── User management API (admin only) ──────────────────────────────────────────


def require_admin(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        storage = get_storage()
        user = storage.get_user_by_id(session["user_id"])
        if not user or not user.is_admin:
            return jsonify({"error": "admin required"}), 403
        return f(*args, **kwargs)

    return decorated


@dashboard_bp.route("/api/users", methods=["GET"])
@require_admin
def api_users_list():
    storage = get_storage()
    users = storage.list_users()
    return jsonify(
        [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "is_admin": u.is_admin,
                "totp_enabled": u.totp_enabled,
                "oauth_provider": u.oauth_provider,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ]
    )


@dashboard_bp.route("/api/users", methods=["POST"])
@require_admin
def api_users_create():
    body = request.get_json()
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip() or None
    password = body.get("password") or ""
    is_admin = bool(body.get("is_admin", False))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    err = validate_password_strength(password)
    if err:
        return jsonify({"error": err}), 400

    storage = get_storage()
    if storage.get_user_by_username(username):
        return jsonify({"error": "username already taken"}), 409

    user_id = storage.create_user(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=is_admin,
    )
    return jsonify({"ok": True, "id": user_id})


@dashboard_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_admin
def api_users_delete(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "cannot delete yourself"}), 400
    storage = get_storage()
    storage.delete_user(user_id)
    return jsonify({"ok": True})


# ── User settings API (own account) ───────────────────────────────────────────


@dashboard_bp.route("/api/settings/password", methods=["POST"])
@require_login
def api_change_password():
    from ..auth import check_password

    body = request.get_json()
    current = body.get("current_password", "")
    new_pw = body.get("new_password", "")
    confirm = body.get("confirm_password", "")

    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])

    if user.password_hash and not check_password(current, user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    err = validate_password_strength(new_pw)
    if err:
        return jsonify({"error": err}), 400

    storage.update_user_password(session["user_id"], hash_password(new_pw))
    return jsonify({"ok": True})


@dashboard_bp.route("/api/settings/totp/disable", methods=["POST"])
@require_login
def api_disable_totp():
    from ..auth import check_password, verify_totp

    body = request.get_json()
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])

    # Require either password or valid TOTP code to disable 2FA
    code = body.get("totp_code", "").strip()
    password = body.get("password", "")

    if user.totp_secret and code and verify_totp(user.totp_secret, code):
        storage.disable_totp(session["user_id"])
        return jsonify({"ok": True})
    if user.password_hash and password and check_password(password, user.password_hash):
        storage.disable_totp(session["user_id"])
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid code or password"}), 400


@dashboard_bp.route("/api/settings/profile", methods=["GET"])
@require_login
def api_profile():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "totp_enabled": user.totp_enabled,
            "oauth_provider": user.oauth_provider,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }
    )


# ── Health ─────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})
