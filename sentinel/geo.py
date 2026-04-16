# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/geo.py -- Async geo-lookup worker (ipinfo.io).
"""
import time

import requests

from sentinel import config, state


def geo_worker():
    while True:
        ip = None
        with state.geo_lock:
            if state.geo_queue:
                ip = state.geo_queue.popleft()
        if ip is None:
            time.sleep(0.05)
            continue
        _fetch_geo(ip)


def _fetch_geo(ip):
    if ip in state.geo_cache:
        return state.geo_cache[ip]
    try:
        params = {"token": config.IPINFO_TOKEN} if config.IPINFO_TOKEN else {}
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params=params,
            timeout=4,
        )
        r.raise_for_status()
        d = r.json()
        if "bogon" in d or d.get("error"):
            raise ValueError(d.get("error", {}).get("message", "ipinfo bogon/error"))
        state.geo_cache[ip] = {
            "country": d.get("country") or "??",
            "asn": d.get("org") or "Unknown",
        }
    except Exception:
        state.geo_cache[ip] = {"country": "??", "asn": "Unknown"}
    with state.lock:
        state.ip_geo[ip] = state.geo_cache[ip]
        n = state.pending_geo_hits.pop(ip, 0)
        if n:
            g = state.geo_cache[ip]
            state.asn_counts[g["asn"]] += n
            state.countries[g["country"]] += n
            state.asn_ips[g["asn"]].add(ip)
    return state.geo_cache[ip]


def enqueue_geo(ip):
    if ip in state.geo_cache or ip in ("-", "", "unknown"):
        return
    with state.geo_lock:
        if ip not in state.geo_cache and ip not in state.geo_queue:
            state.geo_queue.append(ip)


def get_geo(ip):
    if ip in state.geo_cache:
        return state.geo_cache[ip]
    enqueue_geo(ip)
    return {"country": config.PLACEHOLDER_CC, "asn": config.PLACEHOLDER_ASN}
