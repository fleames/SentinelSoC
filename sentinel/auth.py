# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/auth.py -- Authentication gate and audit helpers.
NOTE: _sentinel_auth_gate is NOT decorated with @app.before_request here.
      app.py registers it via app.before_request(auth._sentinel_auth_gate).
"""
import secrets
import sys

from flask import Response, request

from sentinel import config, state
from sentinel.helpers import _normalize_client_ip, _tag_bad_network_or_asn


def _password_matches(got, expected):
    if got is None or expected is None:
        return False
    try:
        a, b = got.encode("utf-8"), expected.encode("utf-8")
        if len(a) != len(b):
            return False
        return secrets.compare_digest(a, b)
    except Exception:
        return False


def _audit_actor():
    try:
        if request.authorization:
            return request.authorization.username
    except RuntimeError:
        pass
    return "unauthenticated"


def _sentinel_auth_gate():
    if not config.AUTH_ENABLED:
        return None
    if request.path == "/health":
        return None
    # /api/ingest uses its own Bearer-token auth; skip Basic Auth gate for it.
    if request.path == "/api/ingest":
        return None
    auth = request.authorization
    if not auth or auth.username != config.AUTH_USER or not _password_matches(auth.password, config.AUTH_PASSWORD):
        _audit_write("auth_failed", "anonymous", {"path": request.path, "method": request.method})
        if config.AUTH_FAIL_BAN_THRESHOLD > 0:
            ra = request.remote_addr
            nip = _normalize_client_ip(ra) if ra else None
            if nip:
                with state.audit_lock:
                    state.auth_fail_counts[nip] += 1
                    count = state.auth_fail_counts[nip]
                if count >= config.AUTH_FAIL_BAN_THRESHOLD:
                    state.auth_fail_counts.pop(nip, None)
                    _auto_ban(nip, f"auth_fail_{count}x")
        return Response(
            "Authentication required\n",
            401,
            {"WWW-Authenticate": 'Basic realm="Sentinel"'},
        )
    return None


def _auto_ban(ip, reason):
    """Ban an IP programmatically and write an auto_ban audit entry."""
    from sentinel.persistence import _save_bans, _iptables_drop
    nip = _normalize_client_ip(ip)
    if not nip:
        return
    with state.lock:
        if nip in state.banned_ips:
            return
        state.banned_ips.add(nip)
        state.muted_hits.pop(nip, None)
        state.ban_notes[nip] = f"auto: {reason}"
        _tag_bad_network_or_asn(nip)
    _save_bans()
    _iptables_drop(nip, True)
    _audit_write("auto_ban", "sentinel", {"ip": nip, "reason": reason})
    print(f"[sentinel] auto-ban {nip!r}: {reason}", file=sys.stderr, flush=True)


def _audit_write(action, user, detail=None):
    """Append one JSON line to AUDIT_LOG_PATH (analyst accountability)."""
    import json
    import os
    from datetime import datetime, timezone
    if not config.AUDIT_LOG_PATH:
        return
    try:
        ra = request.remote_addr
        xff = (request.headers.get("X-Forwarded-For") or "")[:200]
    except RuntimeError:
        ra, xff = None, ""
    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "user": user if user is not None else "anonymous",
        "remote": ra,
        "xff": xff,
    }
    if detail:
        line["detail"] = detail
    try:
        d = os.path.dirname(config.AUDIT_LOG_PATH) or "."
        os.makedirs(d, exist_ok=True)
        payload = json.dumps(line, separators=(",", ":"), ensure_ascii=True) + "\n"
        with state.audit_lock:
            with open(config.AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(payload)
    except OSError as e:
        print(f"[sentinel] audit write failed ({config.AUDIT_LOG_PATH}): {e}", file=sys.stderr, flush=True)
