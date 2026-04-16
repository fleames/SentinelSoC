# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/__init__.py -- Import and re-export all Blueprint objects.
"""
from sentinel.routes.main import bp as main_bp
from sentinel.routes.ban import bp as ban_bp
from sentinel.routes.audit import bp as audit_bp
from sentinel.routes.ip import bp as ip_bp
from sentinel.routes.history import bp as history_bp
from sentinel.routes.ingest import bp as ingest_bp
from sentinel.routes.ui import bp as ui_bp
from sentinel.routes.ssh import bp as ssh_bp
from sentinel.routes.whitelist import bp as whitelist_bp

__all__ = [
    "main_bp",
    "ban_bp",
    "audit_bp",
    "ip_bp",
    "history_bp",
    "ingest_bp",
    "ui_bp",
    "ssh_bp",
    "whitelist_bp",
]
