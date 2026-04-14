# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ingest.py -- /api/ingest and /api/source/remove endpoints.
"""
import json
import secrets

from flask import Blueprint, jsonify, request

from sentinel import config, state
from sentinel.events import _process_log_event

bp = Blueprint("ingest", __name__)


@bp.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Accept JSONL Caddy access-log events pushed from remote servers.

    Authentication: if SENTINEL_INGEST_KEY is set, the request must carry
    ``Authorization: Bearer <key>``.  If the env var is empty, any caller on
    the trusted network is accepted (set a firewall rule accordingly).

    Body: one JSON object per line (JSONL / newline-delimited JSON).
    Header: ``X-Sentinel-Source`` names the remote source (shown in the
    Log Sources card).  Defaults to the caller's remote address.
    """
    if config.INGEST_KEY:
        auth_header = request.headers.get("Authorization", "")
        expected = f"Bearer {config.INGEST_KEY}"
        if not secrets.compare_digest(auth_header, expected):
            return jsonify({"ok": False, "error": "unauthorized"}), 401

    source = (
        (request.headers.get("X-Sentinel-Source") or "").strip()
        or request.remote_addr
        or "remote"
    )
    source = source[:80]

    body = request.get_data(as_text=False)
    if not body:
        return jsonify({"ok": True, "ingested": 0, "skipped": 0})

    ingested = 0
    skipped = 0
    for raw_line in body.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            obj = json.loads(raw_line)
        except (json.JSONDecodeError, ValueError):
            skipped += 1
            continue
        if not isinstance(obj, dict):
            skipped += 1
            continue
        result = _process_log_event(obj, source=source)
        if result == "ok":
            ingested += 1
        else:
            skipped += 1

    return jsonify({"ok": True, "ingested": ingested, "skipped": skipped})


@bp.route("/api/source/remove", methods=["POST"])
def api_source_remove():
    """Remove a remote source label from the in-memory sources counter."""
    ip = request.json.get("source", "").strip() if request.is_json else ""
    if not ip:
        ip = (request.form.get("source") or request.args.get("source") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "source required"}), 400
    if ip in state.sources:
        del state.sources[ip]
    return jsonify({"ok": True})
