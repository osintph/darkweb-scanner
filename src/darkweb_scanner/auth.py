"""
Authentication — local accounts with bcrypt + TOTP 2FA + OAuth (Google/GitHub).
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from flask import redirect, request, session, url_for
from io import BytesIO
import base64

logger = logging.getLogger(__name__)

# ── Session helpers ───────────────────────────────────────────────────────────

def login_user(user_id: int, username: str):
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username
    session["logged_in"] = True
    session.pop("totp_pending_user_id", None)

def logout_user():
    session.clear()

def current_user_id() -> Optional[int]:
    return session.get("user_id")

def is_authenticated() -> bool:
    return bool(session.get("logged_in") and session.get("user_id"))

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated

# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def validate_password_strength(password: str) -> Optional[str]:
    """Returns error message or None if valid."""
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    return None

# ── TOTP helpers ──────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="DarkWebScanner"
    )

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)

def generate_totp_qr_base64(secret: str, username: str) -> str:
    """Returns base64-encoded PNG QR code."""
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# ── OAuth config ──────────────────────────────────────────────────────────────

def get_oauth_providers() -> dict:
    providers = {}
    
    if os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
        providers["google"] = {
            "name": "Google",
            "icon": "G",
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "scope": "openid email profile",
        }
    
    if os.getenv("GITHUB_CLIENT_ID") and os.getenv("GITHUB_CLIENT_SECRET"):
        providers["github"] = {
            "name": "GitHub",
            "icon": "GH",
            "client_id": os.getenv("GITHUB_CLIENT_ID"),
            "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scope": "read:user user:email",
        }
    
    return providers
