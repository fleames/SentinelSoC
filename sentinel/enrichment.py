# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/enrichment.py -- External IP enrichment fetchers.

Shared by sentinel/routes/ip.py (on-demand drill-down) and
sentinel/reputation.py (background auto-enrichment).

All functions return a dict on success or None on failure / missing key.
Results include a "ts" key (epoch float) added by the caller before caching.
"""
import time

import requests

from sentinel import config, state


# ---------------------------------------------------------------------------
# Cache TTL helper
# ---------------------------------------------------------------------------

def _fresh(cached, ttl=3600):
    """Return True if cached dict exists and was stored within ttl seconds."""
    return cached is not None and time.time() - cached.get("ts", 0) < ttl


# ---------------------------------------------------------------------------
# Shodan InternetDB (no key required)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# ipinfo.io
# ---------------------------------------------------------------------------

def _fetch_ipinfo(ip):
    """Fetch ipinfo.io for ip. Returns dict or None on error."""
    try:
        params = {"token": config.IPINFO_TOKEN} if config.IPINFO_TOKEN else {}
        r = requests.get(f"https://ipinfo.io/{ip}/json", params=params, timeout=5)
        r.raise_for_status()
        d = r.json()
        return {
            "org":           str(d.get("org") or ""),
            "hostname":      str(d.get("hostname") or ""),
            "city":          str(d.get("city") or ""),
            "region":        str(d.get("region") or ""),
            "country":       str(d.get("country") or ""),
            "timezone":      str(d.get("timezone") or ""),
            "abuse_contact": str((d.get("abuse") or {}).get("email") or ""),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# AbuseIPDB v2
# ---------------------------------------------------------------------------

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
            "abuse_score":    int(d.get("abuseConfidenceScore") or 0),
            "total_reports":  int(d.get("totalReports") or 0),
            "usage_type":     str(d.get("usageType") or ""),
            "isp":            str(d.get("isp") or ""),
            "domain":         str(d.get("domain") or ""),
            "country":        str(d.get("countryCode") or ""),
            "is_whitelisted": bool(d.get("isWhitelisted")),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# GreyNoise community API
# ---------------------------------------------------------------------------

def _fetch_greynoise(ip):
    """
    Fetch GreyNoise community endpoint for ip.
    Requires SENTINEL_GREYNOISE_KEY set in environment.
    Returns dict or None on error / no key.
    """
    if not config.GREYNOISE_KEY:
        return None
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": config.GREYNOISE_KEY},
            timeout=5,
        )
        if r.status_code == 404:
            return {"noise": False, "riot": False, "classification": "unknown", "name": "", "message": "not found"}
        r.raise_for_status()
        d = r.json()
        return {
            "noise":          bool(d.get("noise")),
            "riot":           bool(d.get("riot")),
            "classification": str(d.get("classification") or "unknown"),
            "name":           str(d.get("name") or ""),
            "link":           str(d.get("link") or ""),
            "message":        str(d.get("message") or ""),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Enqueue helper (called from events.py)
# ---------------------------------------------------------------------------

def enqueue_reputation(ip):
    """
    Add ip to the reputation enrichment queue if it has not been enriched
    recently (within REPUTATION_TTL seconds).
    Safe to call from within state.lock held.
    """
    now = time.time()
    with state.reputation_lock:
        last = state.reputation_seen.get(ip, 0)
        if now - last < config.REPUTATION_TTL:
            return
        state.reputation_seen[ip] = now
        state.reputation_queue.append(ip)
