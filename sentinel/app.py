# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/app.py -- Flask application factory and background thread launcher.
"""
import os
import threading

from flask import Flask

from sentinel import auth, config
from sentinel.routes import (
    audit_bp,
    ban_bp,
    history_bp,
    ingest_bp,
    ip_bp,
    main_bp,
    ui_bp,
)

# Absolute paths to templates and static files within the sentinel/ package.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_PKG_DIR, "templates")
_STATIC_DIR = os.path.join(_PKG_DIR, "static")


def create_app():
    app = Flask(
        __name__,
        template_folder=_TEMPLATES_DIR,
        static_folder=_STATIC_DIR,
    )

    # Register auth gate (not decorated in auth.py to avoid needing an app reference there)
    app.before_request(auth._sentinel_auth_gate)

    # Register all blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(ban_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(ip_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(ui_bp)

    return app


def start_background_threads(app):
    from sentinel.geo import geo_worker
    from sentinel.workers import reset, stream, _state_flush_worker
    from sentinel.botnet import botnet_detection_worker
    from sentinel.persistence import _sync_iptables_bans

    _sync_iptables_bans()

    for _ in range(config.GEO_WORKERS):
        threading.Thread(target=geo_worker, daemon=True).start()

    for _log_path in config._effective_log_paths():
        threading.Thread(target=stream, kwargs={"path": _log_path}, daemon=True).start()

    threading.Thread(target=reset, daemon=True).start()
    threading.Thread(target=botnet_detection_worker, daemon=True).start()
    threading.Thread(target=_state_flush_worker, daemon=True).start()
