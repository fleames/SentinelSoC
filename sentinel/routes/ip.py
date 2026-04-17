# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ip.py -- /api/ip and /api/ipenrich endpoints.
"""
import time

from flask import Blueprint, jsonify, request

from sentinel import config, state
from sentinel.enrichment import _fetch_shodan, _fetch_ipinfo, _fetch_abuseipdb, _fetch_greynoise, _fresh

bp = Blueprint("ip", __name__)


@bp.route("/api/ip")
def api_ip():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    with state.lock:
        if ip not in state.ips and ip not in state.ip_geo:
            return jsonify({"error": "not seen yet"}), 404
        from collections import Counter as _Counter
        path_rows = state.ip_paths.get(ip, {}).copy()
        if not isinstance(path_rows, _Counter):
            path_rows = _Counter(path_rows)
        path_rows_list = path_rows.most_common(50)
        uas   = sorted(state.ip_to_uas.get(ip, set()))
        hits  = int(state.ips[ip])
        score = int(state.ip_scores[ip])
        tags  = sorted(state.ip_tags.get(ip, ()))
        note  = state.ip_notes.get(ip, "")
        cat   = state.ip_categories.get(ip, "")
        raw_geo = state.ip_geo.get(ip, {})

    geo = {
        "country": raw_geo.get("country", "") if raw_geo.get("country") not in ("", config.PLACEHOLDER_CC)  else "",
        "asn":     raw_geo.get("asn", "")     if raw_geo.get("asn")     not in ("", config.PLACEHOLDER_ASN) else "",
    }

    return jsonify({
        "ip": ip, "hits": hits, "score": score, "geo": geo,
        "paths": [[p, int(c)] for p, c in path_rows_list],
        "tags": tags, "note": note, "category": cat, "uas": uas,
    })


@bp.route("/api/ip/note", methods=["POST"])
def api_ip_note():
    data = request.json or {}
    ip = str(data.get("ip", "")).strip()
    note = str(data.get("note", "")).strip()[:2000]
    if not ip:
        return jsonify({"error": "ip required"}), 400
    with state.lock:
        if note:
            state.ip_notes[ip] = note
        else:
            state.ip_notes.pop(ip, None)
    return jsonify({"ok": True, "ip": ip, "note": note})


@bp.route("/api/ip/category", methods=["POST"])
def api_ip_category():
    data = request.json or {}
    ip = str(data.get("ip", "")).strip()
    category = str(data.get("category", "")).strip()[:60]
    if not ip:
        return jsonify({"error": "ip required"}), 400
    with state.lock:
        if category:
            state.ip_categories[ip] = category
        else:
            state.ip_categories.pop(ip, None)
    return jsonify({"ok": True, "ip": ip, "category": category})


@bp.route("/api/ipenrich")
def api_ipenrich():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    now = time.time()

    shodan_cached   = state.ipenrich_cache.get(ip)
    ipinfo_cached   = state.ipinfo_cache.get(ip)
    abuse_cached    = state.abuseipdb_cache.get(ip)
    gn_cached       = state.greynoise_cache.get(ip)
    gn_needed = bool(config.GREYNOISE_KEY)

    all_fresh = (
        _fresh(shodan_cached)
        and _fresh(ipinfo_cached)
        and (not config.ABUSEIPDB_KEY or _fresh(abuse_cached))
        and (not gn_needed or _fresh(gn_cached))
    )
    if all_fresh:
        return jsonify({
            "ok": True, "cached": True,
            "shodan":     {k: v for k, v in shodan_cached.items() if k != "ts"},
            "ipinfo":     {k: v for k, v in ipinfo_cached.items()  if k != "ts"},
            "abuseipdb":  {k: v for k, v in abuse_cached.items()  if k != "ts"} if abuse_cached else {},
            "greynoise":  {k: v for k, v in gn_cached.items()     if k != "ts"} if gn_cached    else {},
        })

    shodan_data  = shodan_cached  if _fresh(shodan_cached)  else _fetch_shodan(ip)
    ipinfo_data  = ipinfo_cached  if _fresh(ipinfo_cached)  else _fetch_ipinfo(ip)
    abuse_data   = abuse_cached   if _fresh(abuse_cached)   else _fetch_abuseipdb(ip)
    gn_data      = gn_cached      if _fresh(gn_cached)      else (_fetch_greynoise(ip) if gn_needed else None)

    if shodan_data is not None:
        state.ipenrich_cache[ip]  = {**shodan_data, "ts": now}
    if ipinfo_data is not None:
        state.ipinfo_cache[ip]    = {**ipinfo_data,  "ts": now}
    if abuse_data is not None:
        state.abuseipdb_cache[ip] = {**abuse_data,   "ts": now}
    if gn_data is not None:
        state.greynoise_cache[ip] = {**gn_data,      "ts": now}

    return jsonify({
        "ok": True, "cached": False,
        "shodan":    shodan_data or {},
        "ipinfo":    ipinfo_data or {},
        "abuseipdb": abuse_data  or {},
        "greynoise": gn_data     or {},
    })
