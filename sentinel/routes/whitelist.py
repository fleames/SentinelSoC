# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/whitelist.py -- /api/whitelist endpoints (add / remove / list).
"""
from flask import Blueprint, jsonify, request

from sentinel import state
from sentinel.auth import _audit_actor, _audit_write
from sentinel.persistence import _save_path_whitelist, _save_ip_whitelist

bp = Blueprint("whitelist", __name__)


def _clean_entry(raw):
    """Normalise a whitelist entry: lowercase, strip, ensure leading slash."""
    s = str(raw or "").strip().lower()
    if not s:
        return ""
    if not s.startswith("/"):
        s = "/" + s
    return s[:300]


@bp.route("/api/whitelist", methods=["GET"])
def api_whitelist_get():
    with state.lock:
        entries = sorted(state.whitelisted_paths)
    return jsonify({"ok": True, "whitelisted_paths": entries})


@bp.route("/api/whitelist/add", methods=["POST"])
def api_whitelist_add():
    body = request.get_json(silent=True) or {}
    raw = body.get("path") or request.args.get("path") or ""
    entry = _clean_entry(raw)
    if not entry:
        return jsonify({"error": "missing or invalid path"}), 400
    with state.lock:
        state.whitelisted_paths.add(entry)
        entries = sorted(state.whitelisted_paths)
    _save_path_whitelist()
    _audit_write("whitelist_add", _audit_actor(), {"path": entry})
    return jsonify({"ok": True, "whitelisted_paths": entries})


@bp.route("/api/whitelist/remove", methods=["POST"])
def api_whitelist_remove():
    body = request.get_json(silent=True) or {}
    raw = body.get("path") or request.args.get("path") or ""
    entry = _clean_entry(raw)
    if not entry:
        return jsonify({"error": "missing or invalid path"}), 400
    with state.lock:
        state.whitelisted_paths.discard(entry)
        entries = sorted(state.whitelisted_paths)
    _save_path_whitelist()
    _audit_write("whitelist_remove", _audit_actor(), {"path": entry})
    return jsonify({"ok": True, "whitelisted_paths": entries})


# ── IP whitelist ──────────────────────────────────────────────────────────────

def _clean_ip(raw):
    return str(raw or "").strip()[:64]


@bp.route("/api/ip-whitelist", methods=["GET"])
def api_ip_whitelist_get():
    with state.lock:
        entries = sorted(state.whitelisted_ips)
    return jsonify({"ok": True, "whitelisted_ips": entries})


@bp.route("/api/ip-whitelist/add", methods=["POST"])
def api_ip_whitelist_add():
    body = request.get_json(silent=True) or {}
    ip = _clean_ip(body.get("ip") or request.args.get("ip") or "")
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    with state.lock:
        state.whitelisted_ips.add(ip)
        entries = sorted(state.whitelisted_ips)
    _save_ip_whitelist()
    _audit_write("ip_whitelist_add", _audit_actor(), {"ip": ip})
    return jsonify({"ok": True, "whitelisted_ips": entries})


@bp.route("/api/ip-whitelist/remove", methods=["POST"])
def api_ip_whitelist_remove():
    body = request.get_json(silent=True) or {}
    ip = _clean_ip(body.get("ip") or request.args.get("ip") or "")
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    with state.lock:
        state.whitelisted_ips.discard(ip)
        entries = sorted(state.whitelisted_ips)
    _save_ip_whitelist()
    _audit_write("ip_whitelist_remove", _audit_actor(), {"ip": ip})
    return jsonify({"ok": True, "whitelisted_ips": entries})
