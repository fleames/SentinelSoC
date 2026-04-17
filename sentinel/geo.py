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
    # Throttle when running without a token — free tier is ~50k/month.
    if not config.IPINFO_TOKEN:
        time.sleep(0.5)
    result = None
    try:
        params = {"token": config.IPINFO_TOKEN} if config.IPINFO_TOKEN else {}
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params=params,
            timeout=4,
        )
        if r.status_code == 429:
            # Rate-limited: re-enqueue for later, do not cache.
            time.sleep(60)
            enqueue_geo(ip)
            return {"country": "??", "asn": "Unknown"}
        r.raise_for_status()
        d = r.json()
        if "bogon" in d or d.get("error"):
            # Bogon / private range — cache permanently so we don't retry.
            result = {"country": "??", "asn": "bogon"}
        else:
            result = {
                "country": d.get("country") or "??",
                "asn": d.get("org") or "Unknown",
            }
    except Exception:
        # Transient failure (timeout, DNS, etc.) — do not cache, retry later.
        enqueue_geo(ip)
        return {"country": "??", "asn": "Unknown"}

    state.geo_cache[ip] = result
    with state.lock:
        state.ip_geo[ip] = result
        n = state.pending_geo_hits.pop(ip, 0)
        if n:
            state.asn_counts[result["asn"]] += n
            state.countries[result["country"]] += n
            state.asn_ips[result["asn"]].add(ip)
    return result


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
