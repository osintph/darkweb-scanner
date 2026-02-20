"""
Flask application factory — wires up auth + dashboard blueprints.
"""

import os
from datetime import timedelta

from flask import Flask, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app() -> Flask:
    app = Flask(__name__)

    app.secret_key = os.getenv("DASHBOARD_SECRET_KEY", "change-me-in-production")
    app.permanent_session_lifetime = timedelta(hours=12)

    # Trust X-Forwarded-Proto from nginx so url_for generates https:// URLs
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    from .auth_routes import auth_bp
    from .dashboard_routes import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    @app.route("/")
    def root():
        return redirect(url_for("dashboard.index"))

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
