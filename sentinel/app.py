# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/app.py -- Flask application factory and SOC-grade background orchestration.
"""

import os
import threading
import time
import logging

from flask import Flask

from sentinel import auth, config
from sentinel.routes import (
    audit_bp,
    ban_bp,
    history_bp,
    ingest_bp,
    ip_bp,
    main_bp,
    ssh_bp,
    ui_bp,
    whitelist_bp,
)

# ========================
# PATHS
# ========================
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_PKG_DIR, "templates")
_STATIC_DIR = os.path.join(_PKG_DIR, "static")

# ========================
# LOGGING (IMPORTANT)
# ========================
logging.basicConfig(
    level=logging.INFO,
    format="[sentinel] %(asctime)s %(levelname)s: %(message)s",
)

log = logging.getLogger("sentinel")


# ========================
# SAFE THREAD WRAPPER
# ========================
def safe_thread(target, name, **kwargs):
    def runner():
        while True:
            try:
                log.info(f"[thread:start] {name}")
                target(**kwargs)
            except Exception as e:
                log.exception(f"[thread:crash] {name}: {e}")
                time.sleep(2)  # prevent tight crash loop

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    return t


# ========================
# VALIDATION
# ========================
def validate_config():
    errors = []

    if not config.LOG_PATHS:
        errors.append("LOG_PATH is empty")

    if config.INGEST_RATE_LIMIT <= 0:
        errors.append("INGEST_RATE_LIMIT invalid")

    if errors:
        for e in errors:
            log.error(f"[config] {e}")
        raise RuntimeError("Invalid configuration")

    log.info("[config] validation passed")


# ========================
# APP FACTORY
# ========================
def create_app():
    validate_config()

    app = Flask(
        __name__,
        template_folder=_TEMPLATES_DIR,
        static_folder=_STATIC_DIR,
    )

    # ========================
    # AUTH GATE
    # ========================
    app.before_request(auth._sentinel_auth_gate)

    # ========================
    # BLUEPRINTS
    # ========================
    app.register_blueprint(main_bp)
    app.register_blueprint(ban_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(ip_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(ssh_bp)
    app.register_blueprint(whitelist_bp)
    app.register_blueprint(ui_bp)

    log.info("[app] Flask app initialized")

    return app


# ========================
# BACKGROUND THREADS
# ========================
def start_background_threads(app):
    log.info("[startup] starting background workers")

    from sentinel.geo import geo_worker
    from sentinel.workers import (
        reset,
        stream,
        _state_flush_worker,
        _ingest_worker,
    )
    from sentinel.botnet import botnet_detection_worker
    from sentinel.persistence import _sync_iptables_bans
    from sentinel.reputation import reputation_worker

    # ========================
    # INIT STATE
    # ========================
    try:
        _sync_iptables_bans()
        log.info("[startup] iptables sync complete")
    except Exception as e:
        log.warning(f"[startup] iptables sync failed: {e}")

    # ========================
    # GEO WORKERS
    # ========================
    for i in range(config.GEO_WORKERS):
        safe_thread(geo_worker, f"geo_worker_{i}")

    # ========================
    # LOG STREAMS
    # ========================
    for path in config.LOG_PATHS:
        safe_thread(stream, f"log_stream:{path}", path=path)

    # ========================
    # CORE WORKERS
    # ========================
    safe_thread(reset, "reset_worker")
    safe_thread(botnet_detection_worker, "botnet_worker")
    safe_thread(_state_flush_worker, "state_flush_worker")

    # ========================
    # INGEST PIPELINE (IMPORTANT)
    # ========================
    safe_thread(_ingest_worker, "ingest_worker")

    # ========================
    # REPUTATION WORKERS
    # ========================
    for i in range(config.REPUTATION_WORKERS):
        safe_thread(reputation_worker, f"reputation_worker_{i}")

    log.info("[startup] all workers started")