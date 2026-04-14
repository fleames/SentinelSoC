# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/audit.py -- /api/audit endpoint.
"""
import json
import os

from flask import Blueprint, jsonify, request

from sentinel import config, state
from sentinel.auth import _audit_actor, _audit_write

bp = Blueprint("audit", __name__)


@bp.route("/api/audit", methods=["GET", "DELETE"])
def api_audit():
    if request.method == "DELETE":
        if not config.AUDIT_LOG_PATH:
            return jsonify({"ok": True, "cleared": 0})
        cleared = 0
        try:
            with state.audit_lock:
                try:
                    with open(config.AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                        cleared = sum(1 for ln in f if ln.strip())
                except OSError:
                    pass
                with open(config.AUDIT_LOG_PATH, "w", encoding="utf-8"):
                    pass  # truncate
        except OSError as e:
            return jsonify({"error": str(e)}), 500
        _audit_write("audit_cleared", _audit_actor(), {"entries_removed": cleared})
        return jsonify({"ok": True, "cleared": cleared})

    # GET
    limit = min(int(request.args.get("limit", 100)), 500)
    if not config.AUDIT_LOG_PATH or not os.path.exists(config.AUDIT_LOG_PATH):
        return jsonify({"entries": [], "audit_path": config.AUDIT_LOG_PATH, "audit_enabled": bool(config.AUDIT_LOG_PATH)})
    entries = []
    try:
        with state.audit_lock:
            with open(config.AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    except OSError:
        pass
    return jsonify({"entries": entries[-limit:], "audit_path": config.AUDIT_LOG_PATH, "audit_enabled": True})
