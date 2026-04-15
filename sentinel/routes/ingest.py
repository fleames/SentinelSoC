# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ingest.py -- /api/ingest and /api/source/remove endpoints.

Events are pushed onto state.ingest_queue and processed asynchronously by
_ingest_worker in workers.py.  The HTTP handler returns as soon as the raw
JSON is parsed and enqueued — it does not wait for state mutations.  This
lets three simultaneous ingest requests from remote servers return in
microseconds instead of holding open until every event has acquired state.lock.
"""
import json
import queue
import secrets

from flask import Blueprint, jsonify, request

from sentinel import config, state

bp = Blueprint("ingest", __name__)


@bp.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Accept JSONL Caddy access-log events pushed from remote servers.

    Authentication: if SENTINEL_INGEST_KEY is set, the request must carry
    ``Authorization: Bearer <key>``.

    Body: one JSON object per line (JSONL / newline-delimited JSON).
    Header: ``X-Sentinel-Source`` names the remote source (shown in the
    Log Sources card).  Defaults to the caller's remote address.

    Returns immediately after enqueuing; actual processing is async.
    Response key ``ingested`` reflects events successfully queued (kept for
    backward-compatibility with remote ingest scripts).
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

    queued = 0
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
        try:
            state.ingest_queue.put_nowait((source, obj))
            queued += 1
        except queue.Full:
            skipped += 1

    return jsonify({"ok": True, "ingested": queued, "skipped": skipped})


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
