"""
Dashboard blueprint — all protected routes.
"""

import json
import os
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from ..auth import hash_password, require_login, validate_password_strength
from .storage_helper import get_storage

dashboard_bp = Blueprint("dashboard", __name__)

# Config is read-only at /app/config — write user edits to /app/data instead
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "/app/config"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))

# Read from config (bundled defaults), write to data (persistent, writable)
KEYWORDS_FILE = DATA_DIR / "keywords.yaml"
KEYWORDS_DEFAULT = CONFIG_DIR / "keywords.yaml"
SEEDS_FILE = DATA_DIR / "seeds.txt"
SEEDS_DEFAULT = CONFIG_DIR / "seeds.txt"
CRAWL_FLAG = DATA_DIR / "crawl.start"


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_seeds() -> list[str]:
    """Load seeds from data dir (user edits), falling back to config default."""
    src = SEEDS_FILE if SEEDS_FILE.exists() else SEEDS_DEFAULT
    if not src.exists():
        return []
    return [
        line.strip()
        for line in src.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _load_keywords() -> dict:
    """Load keywords from data dir (user edits), falling back to config default."""
    import yaml

    src = KEYWORDS_FILE if KEYWORDS_FILE.exists() else KEYWORDS_DEFAULT
    if not src.exists():
        return {}
    data = yaml.safe_load(src.read_text()) or {}
    return data.get("keywords", {})


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
        return jsonify({"categories": _load_keywords()})
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

        _ensure_data_dir()
        cats = _load_keywords()
        cats.setdefault(category, [])
        if keyword not in cats[category]:
            cats[category].append(keyword)
            KEYWORDS_FILE.write_text(
                yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
            )
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

        _ensure_data_dir()
        cats = _load_keywords()
        if keyword in cats.get(category, []):
            cats[category].remove(keyword)
            KEYWORDS_FILE.write_text(
                yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
            )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Seeds API ──────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds", methods=["GET"])
@require_login
def api_seeds_get():
    try:
        return jsonify({"seeds": _load_seeds()})
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

        _ensure_data_dir()
        existing = _load_seeds()
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

        _ensure_data_dir()
        seeds = [s for s in _load_seeds() if s != url]
        SEEDS_FILE.write_text("\n".join(seeds) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Crawl control API ──────────────────────────────────────────────────────────
# The dashboard can't exec docker — instead it writes a flag file that the
# scanner container watches. Run the scanner with: make scan


@dashboard_bp.route("/api/crawl/start", methods=["POST"])
@require_login
def api_crawl_start():
    try:
        _ensure_data_dir()
        if CRAWL_FLAG.exists():
            return jsonify({"error": "Crawl flag already set"}), 409
        CRAWL_FLAG.write_text(datetime.utcnow().isoformat())
        return jsonify({"ok": True, "message": "Crawl flag set. Run: make scan on the server."})
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



# ── Telegram Channels API ──────────────────────────────────────────────────────

TELEGRAM_CHANNELS_FILE = DATA_DIR / "telegram_channels.txt"


def _load_channels() -> list[str]:
    if not TELEGRAM_CHANNELS_FILE.exists():
        # Fall back to env var
        raw = os.getenv("TELEGRAM_CHANNELS", "")
        return [c.strip().lstrip("@") for c in raw.split(",") if c.strip()]
    return [
        line.strip().lstrip("@")
        for line in TELEGRAM_CHANNELS_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@dashboard_bp.route("/api/telegram/channels", methods=["GET"])
@require_login
def api_telegram_channels_get():
    try:
        return jsonify({"channels": _load_channels()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/telegram/channels", methods=["POST"])
@require_login
def api_telegram_channels_add():
    try:
        body = request.get_json()
        channel = (body.get("channel") or "").strip().lstrip("@")
        if not channel:
            return jsonify({"error": "channel required"}), 400
        _ensure_data_dir()
        existing = _load_channels()
        if channel not in existing:
            existing.append(channel)
            TELEGRAM_CHANNELS_FILE.write_text("\n".join(existing) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/telegram/channels", methods=["DELETE"])
@require_login
def api_telegram_channels_delete():
    try:
        body = request.get_json()
        channel = (body.get("channel") or "").strip().lstrip("@")
        if not channel:
            return jsonify({"error": "channel required"}), 400
        _ensure_data_dir()
        channels = [c for c in _load_channels() if c != channel]
        TELEGRAM_CHANNELS_FILE.write_text("\n".join(channels) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Health ─────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})
