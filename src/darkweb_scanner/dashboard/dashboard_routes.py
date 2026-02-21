"""
Dashboard blueprint — all protected routes.
"""

import json
import os
from datetime import datetime
from pathlib import Path

from flask import Blueprint, Response, jsonify, render_template, request, session

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
STOP_FLAG  = DATA_DIR / "crawl.stop"


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




@dashboard_bp.route("/api/crawl/stop", methods=["POST"])
@require_login
def api_crawl_stop():
    try:
        _ensure_data_dir()
        STOP_FLAG.write_text(datetime.utcnow().isoformat())
        return jsonify({"ok": True, "message": "Stop signal sent — crawl will halt after current page."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route("/api/crawl/status", methods=["GET"])
@require_login
def api_crawl_status():
    try:
        storage = get_storage()
        stats = storage.get_stats()
        active = storage.get_active_session()
        session_data = None
        if active:
            live_hits = storage.count_session_hits(active["id"])
            live_pages = storage.count_session_pages(active["id"])
            session_data = {
                "id": active["id"],
                "started_at": active["started_at"],
                "pages_crawled": live_pages,
                "hits_found": live_hits,
            }
        return jsonify({
            "active": active is not None,
            "session": session_data,
            "stats": stats,
        })
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
        must_change_password=True,  # force password change + MFA on first login
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


# ── Sessions API ───────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/sessions", methods=["GET"])
@require_login
def api_sessions():
    storage = get_storage()
    sessions = storage.get_sessions(limit=20)
    for s in sessions:
        try:
            s["seed_urls"] = json.loads(s["seed_urls"])
        except Exception:
            s["seed_urls"] = []
    return jsonify(sessions)


@dashboard_bp.route("/api/sessions/<int:session_id>/hits", methods=["GET"])
@require_login
def api_session_hits(session_id):
    storage = get_storage()
    hits = storage.get_hits_by_session(session_id, limit=200)
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
            }
            for r in hits
        ]
    )


# ── PDF Report API ─────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/report/pdf", methods=["GET"])
@require_login
def api_report_pdf():
    try:
        from io import BytesIO
        from datetime import datetime as dt
        session_id_filter = request.args.get("session_id", type=int)

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        storage = get_storage()
        stats = storage.get_stats()
        if session_id_filter:
            sessions = [s for s in storage.get_sessions(limit=50) if s["id"] == session_id_filter]
            hits = storage.get_hits_by_session(session_id_filter, limit=500)
            report_title = f"Session #{session_id_filter} — Threat Intelligence Report"
        else:
            sessions = storage.get_sessions(limit=50)
            hits = storage.get_hits_for_report(limit=200)
            report_title = "Threat Intelligence Executive Report"

        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        W = A4[0] - 40 * mm

        # Custom styles
        s_title = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontSize=22,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0d1117"),
            spaceAfter=4,
        )
        s_subtitle = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#8b949e"),
            spaceAfter=2,
        )
        s_h2 = ParagraphStyle(
            "H2",
            parent=styles["Normal"],
            fontSize=13,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0d1117"),
            spaceBefore=14,
            spaceAfter=6,
        )

        s_small = ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontSize=7.5,
            textColor=colors.HexColor("#57606a"),
            leading=11,
            wordWrap="CJK",
        )
        s_mono = ParagraphStyle(
            "Mono",
            parent=styles["Normal"],
            fontSize=7,
            fontName="Courier",
            textColor=colors.HexColor("#0550ae"),
            leading=10,
            wordWrap="CJK",
        )

        generated_at = dt.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        story = []

        # ── Cover header ──
        story.append(Paragraph("Dark Web Scanner", s_title))
        story.append(Paragraph(report_title, s_subtitle))
        story.append(Paragraph(f"Generated: {generated_at}", s_subtitle))
        story.append(HRFlowable(width=W, thickness=2, color=colors.HexColor("#f85149"), spaceAfter=14))

        # ── Executive summary stats ──
        story.append(Paragraph("Executive Summary", s_h2))

        stat_data = [
            ["Metric", "Value"],
            ["Total Crawl Sessions", str(stats["total_sessions"])],
            ["Total Pages Crawled", str(stats["total_pages"])],
            ["Total Keyword Hits", str(stats["total_hits"])],
            ["Unique Keywords Triggered", str(len(stats["top_keywords"]))],
        ]
        stat_table = Table(stat_data, colWidths=[W * 0.6, W * 0.4])
        stat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("PADDING", (0, 0), (-1, -1), 7),
                    ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ]
            )
        )
        story.append(stat_table)

        # ── Top keywords ──
        if stats["top_keywords"]:
            story.append(Paragraph("Top Keywords by Hit Count", s_h2))
            kw_data = [["Keyword", "Hits"]] + [
                [k["keyword"], str(k["count"])] for k in stats["top_keywords"]
            ]
            kw_table = Table(kw_data, colWidths=[W * 0.75, W * 0.25])
            kw_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("PADDING", (0, 0), (-1, -1), 7),
                        ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ]
                )
            )
            story.append(kw_table)

        # ── Session history ──
        story.append(Paragraph("Scan Session History", s_h2))
        sess_data = [["Started", "Status", "Pages", "Hits"]]
        for s in sessions[:15]:
            started = s["started_at"][:16].replace("T", " ") if s.get("started_at") else "—"
            sess_data.append([started, s.get("status") or "—", str(s.get("pages_crawled") or 0), str(s.get("hits_found") or 0)])
        sess_table = Table(sess_data, colWidths=[W * 0.38, W * 0.22, W * 0.2, W * 0.2])
        sess_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ]
            )
        )
        story.append(sess_table)

        # ── Keyword hits detail ──
        if hits:
            story.append(Paragraph(f"Keyword Hits Detail (latest {len(hits)})", s_h2))
            hits_data = [["Keyword", "Category", "URL", "Context", "Found At"]]
            for h in hits:
                found = h.found_at.strftime("%m-%d %H:%M") if h.found_at else "—"
                ctx = (h.context or "")[:120] + ("…" if len(h.context or "") > 120 else "")
                hits_data.append([
                    Paragraph(h.keyword or "", s_small),
                    Paragraph(h.category or "", s_small),
                    Paragraph(h.url or "", s_mono),
                    Paragraph(ctx, s_small),
                    Paragraph(found, s_small),
                ])
            hits_table = Table(
                hits_data,
                colWidths=[W * 0.12, W * 0.1, W * 0.25, W * 0.4, W * 0.13],
                repeatRows=1,
            )
            hits_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 8),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("PADDING", (0, 0), (-1, -1), 5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(hits_table)

        # ── Footer ──
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width=W, thickness=0.5, color=colors.HexColor("#d0d7de")))
        story.append(Paragraph(
            "CONFIDENTIAL — This report contains sensitive threat intelligence data. "
            "Do not distribute without authorization.",
            ParagraphStyle("Footer", parent=s_small, textColor=colors.HexColor("#8b949e"), fontSize=7),
        ))

        doc.build(story)
        buf.seek(0)

        filename = f"threat-intel-report-{dt.utcnow().strftime('%Y%m%d-%H%M')}.pdf"
        return Response(
            buf.read(),
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ── Investigations API ─────────────────────────────────────────────────────────


@dashboard_bp.route("/api/investigations", methods=["GET"])
@require_login
def api_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_investigations(limit=50))


@dashboard_bp.route("/api/investigations", methods=["POST"])
@require_login
def api_investigations_create():
    import asyncio
    from ..investigations import run_investigation

    body = request.get_json()
    name = (body.get("name") or "").strip()
    targets = body.get("targets") or []

    if not name:
        return jsonify({"error": "Investigation name required"}), 400
    if not targets:
        return jsonify({"error": "At least one target required"}), 400

    # Validate targets
    valid = []
    for t in targets:
        val = (t.get("value") or "").strip()
        ttype = (t.get("type") or "keyword").strip()
        if val and ttype in ("email", "name", "keyword"):
            valid.append({"value": val, "type": ttype})

    if not valid:
        return jsonify({"error": "No valid targets provided"}), 400

    storage = get_storage()
    api_key = os.getenv("HIBP_API_KEY", "")

    try:
        inv_id = asyncio.run(run_investigation(
            name=name,
            targets=valid,
            storage=storage,
            api_key=api_key,
        ))
        return jsonify({"ok": True, "id": inv_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_investigations_get(inv_id):
    storage = get_storage()
    targets = storage.get_investigation_targets(inv_id)
    investigations = storage.get_investigations(limit=50)
    inv = next((i for i in investigations if i["id"] == inv_id), None)
    if not inv:
        return jsonify({"error": "Not found"}), 404
    return jsonify({**inv, "targets": targets})


@dashboard_bp.route("/api/investigations/<int:inv_id>", methods=["DELETE"])
@require_login
def api_investigations_delete(inv_id):
    storage = get_storage()
    storage.delete_investigation(inv_id)
    return jsonify({"ok": True})


# ── IP Investigation API ───────────────────────────────────────────────────────


@dashboard_bp.route("/api/ip-investigations", methods=["GET"])
@require_login
def api_ip_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_ip_investigations(limit=50))


@dashboard_bp.route("/api/ip-investigations", methods=["POST"])
@require_login
def api_ip_investigations_create():
    import re
    from ..ip_lookup import investigate_ip

    body = request.get_json()
    ip = (body.get("ip") or "").strip()

    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    if not ip or (not ipv4.match(ip) and not ipv6.match(ip)):
        return jsonify({"error": "Invalid IP address"}), 400

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not abuse_key and not vt_key:
        return jsonify({"error": "No API keys configured. Add ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY to .env"}), 400

    storage = get_storage()
    try:
        result = investigate_ip(ip, abuse_key, vt_key)
        inv_id = storage.save_ip_investigation(
            ip=ip,
            abuseipdb_data=result.get("abuseipdb") or {},
            virustotal_data=result.get("virustotal") or {},
        )
        return jsonify({"ok": True, "id": inv_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_ip_investigations_get(inv_id):
    storage = get_storage()
    data = storage.get_ip_investigation(inv_id)
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(data)


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["DELETE"])
@require_login
def api_ip_investigations_delete(inv_id):
    storage = get_storage()
    storage.delete_ip_investigation(inv_id)
    return jsonify({"ok": True})

# ── Ransomware Tracker API ─────────────────────────────────────────────────────


@dashboard_bp.route("/api/ransomware/groups", methods=["GET"])
@require_login
def api_ransomware_groups():
    from ..ransomware_data import RANSOMWARE_GROUPS
    storage = get_storage()
    # Cross-reference each group's keywords against existing hits
    enriched = []
    for group in RANSOMWARE_GROUPS:
        hit_count = 0
        recent_hits = []
        for kw in group.get("keywords", []):
            hits = storage.get_hits_by_keyword(kw, limit=5)
            hit_count += len(hits)
            for h in hits:
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        enriched.append({**group, "hit_count": hit_count, "recent_hits": recent_hits[:5]})
    # Sort: active + SEA targeting + most hits first
    enriched.sort(key=lambda g: (
        g["status"] != "active",
        not g["targeting_sea"],
        -g["hit_count"],
    ))
    return jsonify(enriched)


@dashboard_bp.route("/api/ransomware/add-seeds", methods=["POST"])
@require_admin
def api_ransomware_add_seeds():
    """Add all known ransomware .onion URLs to the seed list."""
    from ..ransomware_data import RANSOMWARE_ONION_SEEDS
    _ensure_data_dir()
    existing = _load_seeds()
    added = 0
    for url in RANSOMWARE_ONION_SEEDS:
        if url not in existing:
            existing.append(url)
            added += 1
    SEEDS_FILE.write_text("\n".join(existing) + "\n")
    return jsonify({"ok": True, "added": added, "total": len(RANSOMWARE_ONION_SEEDS)})


@dashboard_bp.route("/api/ransomware/add-keywords", methods=["POST"])
@require_admin
def api_ransomware_add_keywords():
    """Add all ransomware group names as keywords."""
    import yaml
    from ..ransomware_data import RANSOMWARE_GROUPS
    _ensure_data_dir()
    cats = _load_keywords()
    cats.setdefault("ransomware", [])
    added = 0
    for group in RANSOMWARE_GROUPS:
        for kw in group.get("keywords", []):
            if kw not in cats["ransomware"]:
                cats["ransomware"].append(kw)
                added += 1
    KEYWORDS_FILE.write_text(
        yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
    )
    return jsonify({"ok": True, "added": added})


# ── Threat Actors API ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/threat-actors", methods=["GET"])
@require_login
def api_threat_actors():
    from ..threat_actors import THREAT_ACTORS
    storage = get_storage()
    enriched = []
    for actor in THREAT_ACTORS:
        hit_count = 0
        recent_hits = []
        for kw in actor.get("keywords", []):
            hits = storage.get_hits_by_keyword(kw, limit=3)
            hit_count += len(hits)
            for h in hits:
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        enriched.append({**actor, "hit_count": hit_count, "recent_hits": recent_hits[:3]})
    enriched.sort(key=lambda a: (
        a["risk_level"] not in ("critical", "high"),
        not a["targeting_sea"],
        -a["hit_count"],
    ))
    return jsonify(enriched)


# ── Digest / Mailing List API ──────────────────────────────────────────────────


@dashboard_bp.route("/api/digest/subscribers", methods=["GET"])
@require_admin
def api_digest_subscribers_get():
    from ..digest import load_subscribers
    return jsonify({"subscribers": load_subscribers()})


@dashboard_bp.route("/api/digest/subscribers", methods=["POST"])
@require_admin
def api_digest_subscribers_add():
    from ..digest import add_subscriber
    body = request.get_json()
    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "valid email required"}), 400
    added = add_subscriber(email)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/digest/subscribers", methods=["DELETE"])
@require_admin
def api_digest_subscribers_remove():
    from ..digest import remove_subscriber
    body = request.get_json()
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    remove_subscriber(email)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/digest/send", methods=["POST"])
@require_admin
def api_digest_send():
    from ..digest import send_digest
    body = request.get_json() or {}
    # Optional: send to specific emails instead of subscriber list
    recipients = body.get("recipients") or None
    storage = get_storage()
    result = send_digest(storage, recipients=recipients)
    if result["ok"]:
        return jsonify(result)
    return jsonify(result), 500


@dashboard_bp.route("/api/digest/preview", methods=["GET"])
@require_login
def api_digest_preview():
    """Download a preview of the digest PDF without sending."""
    from ..digest import build_digest_pdf
    from ..feeds import fetch_all_feeds
    storage = get_storage()
    try:
        feed_data = fetch_all_feeds()
        stats = storage.get_stats()
        top_kw = stats.get("top_keywords", [{}])
        scanner_summary = {
            "total_hits": stats.get("total_hits", 0),
            "total_pages": stats.get("total_pages", 0),
            "total_sessions": stats.get("total_sessions", 0),
            "top_keyword": top_kw[0].get("keyword", "—") if top_kw else "—",
        }
        pdf = build_digest_pdf(feed_data, scanner_summary=scanner_summary)
        from datetime import datetime as dt
        filename = f"digest-preview-{dt.utcnow().strftime('%Y%m%d')}.pdf"
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@dashboard_bp.route("/api/digest/feeds", methods=["GET"])
@require_login
def api_digest_feeds():
    """Preview feed data without building PDF."""
    from ..feeds import fetch_all_feeds
    try:
        data = fetch_all_feeds()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/digest/subscribe", methods=["POST"])
def api_public_subscribe():
    """Public endpoint — no auth required. For static website subscribe form."""
    from ..digest import add_subscriber
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    name = (body.get("name") or "").strip()[:100]
    org = (body.get("org") or "").strip()[:200]
    # Honeypot
    if body.get("website"):
        return jsonify({"ok": True})  # silently drop bots
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Valid email required"}), 400
    added = add_subscriber(email, name=name, org=org)
    return jsonify({"ok": True, "new": added})


# ── DNS Crawler API ────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/dns/investigations", methods=["GET"])
@require_login
def api_dns_list():
    storage = get_storage()
    return jsonify(storage.get_dns_investigations(limit=100))


@dashboard_bp.route("/api/dns/investigate", methods=["POST"])
@require_login
def api_dns_start():
    """Start a DNS investigation — runs in background thread."""
    import threading
    from ..dns_crawler import run_dns_recon

    body = request.get_json() or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    # Basic sanity check
    if len(domain) > 253 or " " in domain:
        return jsonify({"error": "invalid domain"}), 400

    storage = get_storage()
    inv_id = storage.create_dns_investigation(domain)

    def run():
        try:
            result = run_dns_recon(domain)
            storage.complete_dns_investigation(inv_id, result)
        except Exception as e:
            import traceback
            storage.fail_dns_investigation(inv_id, str(e))
            print(f"DNS investigation {inv_id} failed: {traceback.format_exc()}", flush=True)

    t = threading.Thread(target=run, daemon=True)
    t.start()

    return jsonify({"ok": True, "id": inv_id, "domain": domain})


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_dns_get(inv_id: int):
    storage = get_storage()
    result = storage.get_dns_investigation(inv_id)
    if not result:
        return jsonify({"error": "not found"}), 404
    return jsonify(result)


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>", methods=["DELETE"])
@require_login
def api_dns_delete(inv_id: int):
    storage = get_storage()
    storage.delete_dns_investigation(inv_id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/pdf", methods=["GET"])
@require_login
def api_dns_pdf(inv_id: int):
    """Export DNS investigation as PDF report."""
    from io import BytesIO
    from datetime import datetime as dt

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "not found"}), 404
    if inv["status"] != "complete":
        return jsonify({"error": "investigation not complete yet"}), 400

    r = inv.get("result", {})
    domain = inv["domain"]
    created = inv.get("created_at", "")[:16].replace("T", " ")
    dns = r.get("dns_records", {})
    zt = r.get("zone_transfer", {})
    email_sec = r.get("email_security", {})
    resolved = r.get("subdomains_resolved", [])
    passive = r.get("subdomains_passive", [])
    ip_geo = r.get("ip_geo", {})
    ptr = r.get("ptr_records", {})
    zt_success = any(v.get("success") for v in zt.values() if isinstance(v, dict))

    buf = BytesIO()
    W, H = A4
    M = 18 * mm
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=M, rightMargin=M,
                            topMargin=M, bottomMargin=M)
    PW = W - 2 * M
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_h1 = S("h1", fontSize=20, fontName="Helvetica-Bold", textColor=colors.HexColor("#0d1117"), spaceAfter=2, leading=24)
    s_tagline = S("tl", fontSize=10, textColor=colors.HexColor("#f85149"), fontName="Helvetica-Bold", spaceAfter=3, leading=14)
    s_meta = S("meta", fontSize=8, textColor=colors.HexColor("#8b949e"), spaceAfter=0, leading=12)
    s_body = S("body", fontSize=8.5, textColor=colors.HexColor("#24292f"), leading=13)
    s_small = S("small", fontSize=7.5, textColor=colors.HexColor("#57606a"), leading=11)
    s_mono = S("mono", fontSize=7, fontName="Courier", textColor=colors.HexColor("#0550ae"), leading=10, wordWrap="CJK")
    s_warn = S("warn", fontSize=8, textColor=colors.HexColor("#f85149"), fontName="Helvetica-Bold", leading=12)
    s_footer = S("footer", fontSize=7, textColor=colors.HexColor("#8b949e"), leading=10)

    no_pad = TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])

    story = []

    # ── Masthead: logo left, stacked text right (prevents overlap) ──
    story.append(HRFlowable(width=PW, thickness=4, color=colors.HexColor("#f85149"), spaceAfter=10))
    logo_tbl = Table([[Paragraph('<font color="#f85149" size="26"><b>⬡</b></font>',
        S("logo_d", fontSize=26, textColor=colors.HexColor("#f85149"), leading=30))]], colWidths=[14 * mm])
    logo_tbl.setStyle(no_pad)
    text_tbl = Table([
        [Paragraph("DNS Reconnaissance Report", s_h1)],
        [Paragraph("powered by OSINT PH  ·  osintph.info", s_tagline)],
        [Paragraph(f"Target: {domain}  ·  Investigated: {created}  ·  Generated: {dt.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", s_meta)],
    ], colWidths=[PW - 16 * mm])
    text_tbl.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    header_tbl = Table([[logo_tbl, text_tbl]], colWidths=[16 * mm, PW - 16 * mm])
    header_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=10))
    s_body = S("body", fontSize=8.5, textColor=colors.HexColor("#24292f"), leading=13)
    s_small = S("small", fontSize=7.5, textColor=colors.HexColor("#57606a"), leading=11)
    s_mono = S("mono", fontSize=7, fontName="Courier", textColor=colors.HexColor("#0550ae"), leading=10, wordWrap="CJK")
    s_warn = S("warn", fontSize=8, textColor=colors.HexColor("#f85149"), fontName="Helvetica-Bold", leading=12)
    s_footer = S("footer", fontSize=7, textColor=colors.HexColor("#8b949e"), leading=10)

    def section(title, color="#0d1117"):
        story.append(Spacer(1, 4))
        story.append(Paragraph(title, S(f"sh{title[:8]}", fontSize=11, fontName="Helvetica-Bold",
            textColor=colors.HexColor(color), spaceBefore=10, spaceAfter=3)))
        story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=3))

    def make_table(headers, rows, col_widths, row_bg=None):
        data = [headers] + rows
        tbl = Table(data, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1117")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), row_bg or [colors.HexColor("#f6f8fa"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return tbl

    # ── Summary ──
    section("Executive Summary")
    main_ips = dns.get("A", []) + dns.get("AAAA", [])
    summary_data = [
        ["Metric", "Value"],
        ["Domain", domain],
        ["Subdomains Discovered", str(inv.get("subdomain_count") or 0)],
        ["Subdomains Resolved", str(inv.get("resolved_count") or 0)],
        ["IP Addresses", str(len(main_ips))],
        ["Zone Transfer", "⚠ VULNERABLE — Transfer Succeeded" if zt_success else "Secure (refused)"],
        ["SPF Record", "✓ Present" if email_sec.get("spf_valid") else "✗ Missing — spoofing risk"],
        ["DMARC Record", "✓ Present" if email_sec.get("dmarc_valid") else "✗ Missing — no enforcement"],
        ["DKIM Selectors", ", ".join(email_sec.get("dkim_selectors_found", [])) or "None found"],
    ]
    tbl = Table(summary_data, colWidths=[PW * 0.45, PW * 0.55])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("PADDING", (0, 0), (-1, -1), 6),
        # Highlight zone transfer row red if vulnerable
        *(
            [("TEXTCOLOR", (1, 5), (1, 5), colors.HexColor("#f85149")),
             ("FONTNAME", (1, 5), (1, 5), "Helvetica-Bold")]
            if zt_success else []
        ),
    ]))
    story.append(tbl)

    # ── Email security issues ──
    issues = email_sec.get("issues", [])
    if issues:
        section("⚠ Email Security Issues", "#f85149")
        for issue in issues:
            story.append(Paragraph(f"• {issue}", s_warn))
            story.append(Spacer(1, 2))

    # ── DNS Records ──
    section("DNS Records")
    rec_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    rec_rows = []
    for rtype in rec_types:
        for val in dns.get(rtype, []):
            geo = ip_geo.get(val, {})
            geo_str = f"{geo.get('city', '')} {geo.get('country', '')} · {geo.get('org', '')}".strip(" ·")
            ptr_str = ptr.get(val, "")
            rec_rows.append([
                Paragraph(rtype, S(f"rt{rtype}", fontSize=7, fontName="Helvetica-Bold",
                    textColor=colors.white, backColor=colors.HexColor("#161b22"),
                    borderPadding=(2, 4, 2, 4))),
                Paragraph(val, s_mono),
                Paragraph(ptr_str, s_small) if ptr_str else Paragraph("", s_small),
                Paragraph(geo_str, s_small),
            ])
    if rec_rows:
        story.append(make_table(
            [Paragraph(h, S(f"rh{h}", fontSize=7.5, textColor=colors.white, fontName="Helvetica-Bold"))
             for h in ["Type", "Value", "PTR / Hostname", "Geolocation"]],
            rec_rows,
            [PW * 0.08, PW * 0.28, PW * 0.28, PW * 0.36],
        ))

    # ── Email security records ──
    if email_sec.get("spf") or email_sec.get("dmarc"):
        section("Email Authentication Records")
        email_rows = []
        if email_sec.get("spf"):
            email_rows.append([Paragraph("SPF", s_body), Paragraph(email_sec["spf"], s_mono)])
        if email_sec.get("dmarc"):
            email_rows.append([Paragraph("DMARC", s_body), Paragraph(email_sec["dmarc"], s_mono)])
        if email_sec.get("dkim_selectors_found"):
            email_rows.append([Paragraph("DKIM", s_body),
                Paragraph("Selectors: " + ", ".join(email_sec["dkim_selectors_found"]), s_body)])
        story.append(make_table(
            [Paragraph(h, S(f"eh{h}", fontSize=7.5, textColor=colors.white, fontName="Helvetica-Bold"))
             for h in ["Record", "Value"]],
            email_rows, [PW * 0.12, PW * 0.88],
        ))

    # ── Zone transfer ──
    if zt_success:
        section("🚨 Zone Transfer — CRITICAL FINDING", "#f85149")
        story.append(Paragraph(
            "Zone transfer succeeded. The DNS server is leaking its full zone data to unauthorized parties. "
            "This exposes all DNS records and subdomains. Restrict AXFR to authorised secondary nameservers immediately.",
            s_warn))
        story.append(Spacer(1, 6))
        for ns, info in zt.items():
            if not info.get("success"):
                continue
            story.append(Paragraph(f"Nameserver: {ns} — {info['record_count']} records exposed", s_body))
            zt_rows = [
                [Paragraph(rec["name"], s_mono), Paragraph(rec["type"], s_body), Paragraph(rec["value"], s_mono)]
                for rec in (info.get("records") or [])[:100]
            ]
            if zt_rows:
                story.append(Spacer(1, 4))
                story.append(make_table(
                    [Paragraph(h, S(f"zh{h}", fontSize=7.5, textColor=colors.white, fontName="Helvetica-Bold"))
                     for h in ["Name", "Type", "Value"]],
                    zt_rows, [PW * 0.3, PW * 0.1, PW * 0.6],
                    row_bg=[colors.HexColor("#fff8f8"), colors.white],
                ))

    # ── Resolved subdomains ──
    if resolved:
        section(f"Resolved Subdomains ({len(resolved)})")
        sub_rows = []
        for s in resolved[:200]:
            ips = ", ".join(s.get("ips", []))
            geo_parts = [f"{g.get('city','')} {g.get('countryCode','')}".strip()
                         for g in (s.get("geo") or []) if g and g.get("country")]
            geo = " / ".join(geo_parts)
            sub_rows.append([Paragraph(s["subdomain"], s_mono), Paragraph(ips, s_mono), Paragraph(geo, s_small)])
        story.append(make_table(
            [Paragraph(h, S(f"sbh{h}", fontSize=7.5, textColor=colors.white, fontName="Helvetica-Bold"))
             for h in ["Subdomain", "IP Address(es)", "Location"]],
            sub_rows, [PW * 0.42, PW * 0.28, PW * 0.30],
        ))

    # ── Certificate transparency ──
    if passive:
        section(f"Certificate Transparency — crt.sh ({len(passive)} certificates)")
        cert_rows = []
        for c in passive[:150]:
            issuer = (c.get("issuer") or "").split("O=")[-1].split(",")[0][:40]
            cert_rows.append([
                Paragraph(c.get("subdomain", ""), s_mono),
                Paragraph(issuer, s_small),
                Paragraph((c.get("not_after") or "")[:10], s_small),
            ])
        story.append(make_table(
            [Paragraph(h, S(f"ch{h}", fontSize=7.5, textColor=colors.white, fontName="Helvetica-Bold"))
             for h in ["Subdomain / SAN", "Issuer", "Expires"]],
            cert_rows, [PW * 0.5, PW * 0.3, PW * 0.2],
        ))

    # ── Footer ──
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de")))
    story.append(Spacer(1, 5))
    story.append(Paragraph(
        f"CONFIDENTIAL — DNS Reconnaissance Report powered by OSINT PH · osintph.info · "
        f"Target: {domain} · Report ID: OSINTPH-DNS-{inv_id}-{dt.utcnow().strftime('%Y%m%d')}",
        s_footer))

    doc.build(story)
    buf.seek(0)
    filename = f"osintph-dns-{domain}-{dt.utcnow().strftime('%Y%m%d')}.pdf"
    return Response(
        buf.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Health ─────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})
