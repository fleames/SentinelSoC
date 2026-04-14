# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/history.py -- /api/history/* endpoints.
"""
import json
import os
import time
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from sentinel import config, state

bp = Blueprint("history", __name__)


def _parse_epoch_param(raw, default_v):
    if raw is None or raw == "":
        return float(default_v)
    s = str(raw).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return float(default_v)


@bp.route("/api/history/series")
def api_history_series():
    now = time.time()
    from_ts = _parse_epoch_param(request.args.get("from"), now - (config.HISTORY_RETENTION_S // 4))
    to_ts = _parse_epoch_param(request.args.get("to"), now)
    day_f = (request.args.get("day") or "").strip()
    if day_f:
        try:
            day_dt = datetime.strptime(day_f, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            from_ts = day_dt.timestamp()
            to_ts = from_ts + 86400 - 1e-6
        except ValueError:
            day_f = ""
    if to_ts < from_ts:
        from_ts, to_ts = to_ts, from_ts
    bucket = (request.args.get("bucket") or "minute").strip().lower()
    bucket_s = 3600 if bucket == "hour" else 60
    cutoff = now - config.HISTORY_RETENTION_S
    from_ts = max(from_ts, cutoff)
    with state.lock:
        rows = []
        for k in sorted(state.history_buckets.keys()):
            if k < from_ts or k > to_ts:
                continue
            b = state.history_buckets[k]
            rows.append(
                {
                    "ts": int(k),
                    "total": int(b.get("total", 0)),
                    "attacks": int(b.get("attacks", 0)),
                    "client_errors": int(b.get("client_errors", 0)),
                    "server_errors": int(b.get("server_errors", 0)),
                }
            )
    if bucket_s > 60:
        grouped = {}
        for r in rows:
            gk = int(r["ts"] // bucket_s) * bucket_s
            g = grouped.get(gk)
            if g is None:
                g = {"ts": gk, "total": 0, "attacks": 0, "client_errors": 0, "server_errors": 0}
                grouped[gk] = g
            g["total"] += r["total"]
            g["attacks"] += r["attacks"]
            g["client_errors"] += r["client_errors"]
            g["server_errors"] += r["server_errors"]
        rows = [grouped[k] for k in sorted(grouped.keys())]
    return jsonify(
        {
            "ok": True,
            "from": from_ts,
            "to": to_ts,
            "day": day_f,
            "bucket": "hour" if bucket_s == 3600 else "minute",
            "points": rows,
            "retention_days": config.HISTORY_RETENTION_DAYS,
        }
    )


@bp.route("/api/history/days")
def api_history_days():
    now = time.time()
    cutoff = now - config.HISTORY_RETENTION_S
    day_map = {}
    with state.lock:
        for ts, b in state.history_buckets.items():
            if ts < cutoff:
                continue
            day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
            row = day_map.get(day)
            if row is None:
                row = {
                    "day": day,
                    "total": 0,
                    "attacks": 0,
                    "client_errors": 0,
                    "server_errors": 0,
                    "buckets": 0,
                    "has_events_file": False,
                }
                day_map[day] = row
            row["total"] += int(b.get("total", 0))
            row["attacks"] += int(b.get("attacks", 0))
            row["client_errors"] += int(b.get("client_errors", 0))
            row["server_errors"] += int(b.get("server_errors", 0))
            row["buckets"] += 1
    if config.HISTORY_EVENTS_DIR and os.path.isdir(config.HISTORY_EVENTS_DIR):
        for name in os.listdir(config.HISTORY_EVENTS_DIR):
            if not name.endswith(".jsonl"):
                continue
            day = name[:-6]
            if day in day_map:
                day_map[day]["has_events_file"] = True
            else:
                day_map[day] = {
                    "day": day,
                    "total": 0,
                    "attacks": 0,
                    "client_errors": 0,
                    "server_errors": 0,
                    "buckets": 0,
                    "has_events_file": True,
                }
    days = [day_map[k] for k in sorted(day_map.keys(), reverse=True)]
    return jsonify(
        {
            "ok": True,
            "days": days,
            "latest_day": (days[0]["day"] if days else ""),
            "retention_days": config.HISTORY_RETENTION_DAYS,
        }
    )


@bp.route("/api/history/events")
def api_history_events():
    now = time.time()
    from_ts = _parse_epoch_param(request.args.get("from"), now - 86400)
    to_ts = _parse_epoch_param(request.args.get("to"), now)
    day_f = (request.args.get("day") or "").strip()
    if day_f:
        try:
            day_dt = datetime.strptime(day_f, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            from_ts = day_dt.timestamp()
            to_ts = from_ts + 86400 - 1e-6
        except ValueError:
            day_f = ""
    if to_ts < from_ts:
        from_ts, to_ts = to_ts, from_ts
    cutoff = now - config.HISTORY_RETENTION_S
    from_ts = max(from_ts, cutoff)

    try:
        page = max(1, int(request.args.get("page", "1") or "1"))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get("page_size", "100") or "100")
    except ValueError:
        page_size = 100
    page_size = min(max(1, page_size), config.HISTORY_EVENT_PAGE_MAX)
    ip_f = (request.args.get("ip") or "").strip()
    host_f = (request.args.get("host") or "").strip().lower()
    ua_f = (request.args.get("ua") or "").strip().lower()
    path_f = (request.args.get("path") or "").strip().lower()
    status_f = (request.args.get("status") or "").strip()
    tag_f = (request.args.get("tag") or "").strip().lower()

    events = []
    scanned = 0
    if config.HISTORY_EVENTS_DIR and os.path.isdir(config.HISTORY_EVENTS_DIR):
        if day_f:
            file_names = [f"{day_f}.jsonl"]
        else:
            file_names = sorted(os.listdir(config.HISTORY_EVENTS_DIR), reverse=True)
        for name in file_names:
            if not name.endswith(".jsonl"):
                continue
            fp = os.path.join(config.HISTORY_EVENTS_DIR, name)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except OSError:
                continue
            for line in reversed(lines):
                if scanned >= config.HISTORY_EVENT_MAX_SCAN:
                    break
                scanned += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                ts = float(row.get("ts_epoch", 0) or 0)
                if ts < from_ts or ts > to_ts:
                    continue
                if ip_f and str(row.get("ip", "")) != ip_f:
                    continue
                if host_f and host_f not in str(row.get("host", "")).lower():
                    continue
                if ua_f and ua_f not in str(row.get("ua", "")).lower():
                    continue
                if path_f and path_f not in str(row.get("path", row.get("uri", ""))).lower():
                    continue
                if status_f and str(row.get("status", "")) != status_f:
                    continue
                if tag_f:
                    tags = [str(t).lower() for t in list(row.get("tags", []))]
                    if tag_f not in tags:
                        continue
                events.append(
                    {
                        "ts": str(row.get("ts", "")),
                        "ts_epoch": ts,
                        "ip": str(row.get("ip", "")),
                        "host": str(row.get("host", "")),
                        "ua": str(row.get("ua", "")),
                        "path": str(row.get("path", row.get("uri", ""))),
                        "status": int(row.get("status", 0) or 0),
                        "score": int(row.get("score", 0) or 0),
                        "fingerprint": str(row.get("fingerprint", "")),
                        "tags": [str(t) for t in list(row.get("tags", []))],
                    }
                )
            if scanned >= config.HISTORY_EVENT_MAX_SCAN:
                break

    total_rows = len(events)
    start = (page - 1) * page_size
    end = start + page_size
    page_rows = events[start:end]
    return jsonify(
        {
            "ok": True,
            "from": from_ts,
            "to": to_ts,
            "day": day_f,
            "page": page,
            "page_size": page_size,
            "total": total_rows,
            "scanned": scanned,
            "rows": page_rows,
            "retention_days": config.HISTORY_RETENTION_DAYS,
        }
    )
