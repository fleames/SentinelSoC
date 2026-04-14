# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ip.py -- /api/ip and /api/ipenrich endpoints.
"""
import time

import requests

from flask import Blueprint, jsonify, request

from sentinel import config, state

bp = Blueprint("ip", __name__)


def _fetch_shodan(ip):
    """Fetch Shodan InternetDB for ip. Returns dict or None on error."""
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        if r.status_code == 404:
            return {"ports": [], "vulns": [], "tags": [], "hostnames": []}
        r.raise_for_status()
        d = r.json()
        return {
            "ports":     list(d.get("ports") or []),
            "vulns":     list(d.get("vulns") or []),
            "tags":      list(d.get("tags") or []),
            "hostnames": list(d.get("hostnames") or []),
        }
    except Exception:
        return None


def _fetch_ipinfo(ip):
    """Fetch ipinfo.io for ip. Returns dict or None on error."""
    try:
        params = {"token": config.IPINFO_TOKEN} if config.IPINFO_TOKEN else {}
        r = requests.get(f"https://ipinfo.io/{ip}/json", params=params, timeout=5)
        r.raise_for_status()
        d = r.json()
        return {
            "org":      str(d.get("org") or ""),
            "hostname": str(d.get("hostname") or ""),
            "city":     str(d.get("city") or ""),
            "region":   str(d.get("region") or ""),
            "country":  str(d.get("country") or ""),
            "timezone": str(d.get("timezone") or ""),
            "abuse_contact": str((d.get("abuse") or {}).get("email") or ""),
        }
    except Exception:
        return None


def _fetch_abuseipdb(ip):
    """Fetch AbuseIPDB v2 check for ip. Returns dict or None on error / no key."""
    if not config.ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=5,
        )
        r.raise_for_status()
        d = r.json().get("data") or {}
        return {
            "abuse_score":   int(d.get("abuseConfidenceScore") or 0),
            "total_reports": int(d.get("totalReports") or 0),
            "usage_type":    str(d.get("usageType") or ""),
            "isp":           str(d.get("isp") or ""),
            "domain":        str(d.get("domain") or ""),
            "country":       str(d.get("countryCode") or ""),
            "is_whitelisted": bool(d.get("isWhitelisted")),
        }
    except Exception:
        return None


@bp.route("/api/ip")
def api_ip():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    with state.lock:
        if ip not in state.ips and ip not in state.ip_geo:
            return jsonify({"error": "not seen yet"}), 404
        path_rows = state.ip_paths.get(ip, {}).copy()
        from collections import Counter as _Counter
        if not isinstance(path_rows, _Counter):
            path_rows = _Counter(path_rows)
        path_rows_list = path_rows.most_common(50)
        return jsonify(
            {
                "ip": ip,
                "hits": int(state.ips[ip]),
                "score": int(state.ip_scores[ip]),
                "geo": state.ip_geo.get(ip, {}),
                "paths": [[p, int(c)] for p, c in path_rows_list],
                "tags": sorted(state.ip_tags.get(ip, ())),
            }
        )


@bp.route("/api/ipenrich")
def api_ipenrich():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    now = time.time()

    shodan_cached   = state.ipenrich_cache.get(ip)
    ipinfo_cached   = state.ipinfo_cache.get(ip)
    abuse_cached    = state.abuseipdb_cache.get(ip)
    def _fresh(c): return c is not None and now - c.get("ts", 0) < 3600
    if _fresh(shodan_cached) and _fresh(ipinfo_cached) and (not config.ABUSEIPDB_KEY or _fresh(abuse_cached)):
        return jsonify({
            "ok": True, "cached": True,
            "shodan":    {k: v for k, v in shodan_cached.items() if k != "ts"},
            "ipinfo":    {k: v for k, v in ipinfo_cached.items()  if k != "ts"},
            "abuseipdb": {k: v for k, v in abuse_cached.items()  if k != "ts"} if abuse_cached else {},
        })

    shodan_data  = shodan_cached  if _fresh(shodan_cached)  else _fetch_shodan(ip)
    ipinfo_data  = ipinfo_cached  if _fresh(ipinfo_cached)  else _fetch_ipinfo(ip)
    abuse_data   = abuse_cached   if _fresh(abuse_cached)   else _fetch_abuseipdb(ip)

    if shodan_data is not None:
        state.ipenrich_cache[ip]  = {**shodan_data, "ts": now}
    if ipinfo_data is not None:
        state.ipinfo_cache[ip]    = {**ipinfo_data,  "ts": now}
    if abuse_data is not None:
        state.abuseipdb_cache[ip] = {**abuse_data,   "ts": now}

    return jsonify({
        "ok": True, "cached": False,
        "shodan":    shodan_data or {},
        "ipinfo":    ipinfo_data or {},
        "abuseipdb": abuse_data  or {},
    })
