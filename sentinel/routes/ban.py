# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ban.py -- /api/ban and /api/unban endpoints.
"""
from flask import Blueprint, jsonify, request

from sentinel import config, state
from sentinel.auth import _audit_actor, _audit_write
from sentinel.helpers import _normalize_client_ip
from sentinel.persistence import _iptables_drop, _save_bans

bp = Blueprint("ban", __name__)


@bp.route("/api/ban", methods=["POST"])
def api_ban():
    body = request.get_json(silent=True) or {}
    raw = (body.get("ip") or request.args.get("ip") or "").strip()
    nip = _normalize_client_ip(raw)
    if not nip:
        return jsonify({"error": "invalid ip"}), 400
    with state.lock:
        state.banned_ips.add(nip)
        state.muted_hits.pop(nip, None)
    _save_bans()
    ok_ipt, ipt_err = _iptables_drop(nip, True)
    _audit_write("mute", _audit_actor(), {"ip": nip})
    return jsonify(
        {
            "ok": True,
            "banned_ips": sorted(state.banned_ips),
            "iptables": {"enabled": config.IPTABLES_ENABLED, "ok": ok_ipt, "error": ipt_err},
        }
    )


@bp.route("/api/unban", methods=["POST"])
def api_unban():
    body = request.get_json(silent=True) or {}
    raw = (body.get("ip") or request.args.get("ip") or "").strip()
    nip = _normalize_client_ip(raw)
    if not nip:
        return jsonify({"error": "invalid ip"}), 400
    with state.lock:
        state.banned_ips.discard(nip)
        state.muted_hits.pop(nip, None)
    _save_bans()
    ok_ipt, ipt_err = _iptables_drop(nip, False)
    _audit_write("unban", _audit_actor(), {"ip": nip})
    return jsonify(
        {
            "ok": True,
            "banned_ips": sorted(state.banned_ips),
            "iptables": {"enabled": config.IPTABLES_ENABLED, "ok": ok_ipt, "error": ipt_err},
        }
    )
