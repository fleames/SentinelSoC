# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/reputation.py -- Background IP reputation enrichment worker.

Dequeues IPs that scored above REPUTATION_ENRICH_THRESHOLD and fetches
AbuseIPDB, GreyNoise, Shodan InternetDB, and ipinfo.io in the background.
Results are stored in the shared caches (state.*_cache) so the drill-down
modal shows pre-populated data immediately.

High-abuse or GreyNoise-flagged IPs receive extra threat score and tags.
"""
import time

from sentinel import config, state
from sentinel.enrichment import (
    _fetch_abuseipdb,
    _fetch_greynoise,
    _fetch_ipinfo,
    _fetch_shodan,
    _fresh,
)


# Extra score applied when reputation sources confirm the IP is malicious.
_ABUSE_SCORE_BONUS = 8    # AbuseIPDB confidence >= 80
_GREYNOISE_BONUS   = 6    # GreyNoise classification == "malicious"
_SHODAN_VULN_BONUS = 4    # Shodan lists known CVEs


def _apply_reputation_tags(ip, shodan, ipinfo, abuse, greynoise):
    """Update ip_scores and ip_tags based on enrichment results (inside state.lock)."""
    bonus = 0
    tags_to_add = set()

    if abuse:
        score = int(abuse.get("abuse_score") or 0)
        if score >= 80:
            bonus += _ABUSE_SCORE_BONUS
            tags_to_add.add("abuseipdb_high")
        elif score >= 40:
            tags_to_add.add("abuseipdb_medium")
        if int(abuse.get("total_reports") or 0) >= 10:
            tags_to_add.add("reported")

    if greynoise:
        if greynoise.get("classification") == "malicious":
            bonus += _GREYNOISE_BONUS
            tags_to_add.add("greynoise_malicious")
        elif greynoise.get("noise"):
            tags_to_add.add("greynoise_noise")
        if greynoise.get("riot"):
            tags_to_add.add("greynoise_riot")   # known-good infra; reduce suspicion

    if shodan:
        if shodan.get("vulns"):
            bonus += _SHODAN_VULN_BONUS
            tags_to_add.add("shodan_vulns")
        if shodan.get("ports"):
            tags_to_add.add("shodan_open_ports")

    with state.lock:
        if bonus:
            state.ip_scores[ip] += bonus
        for tag in tags_to_add:
            state.ip_tags[ip].add(tag)


def reputation_worker():
    """
    Background daemon thread.
    Drains reputation_queue one IP at a time, fetches all enabled sources,
    caches results, and applies scoring/tags.
    Sleeps briefly when the queue is empty to avoid busy-waiting.
    """
    while True:
        ip = None
        with state.reputation_lock:
            if state.reputation_queue:
                ip = state.reputation_queue.popleft()

        if not ip:
            time.sleep(2)
            continue

        now = time.time()

        # --- Shodan ---
        shodan_cached = state.ipenrich_cache.get(ip)
        if _fresh(shodan_cached):
            shodan = {k: v for k, v in shodan_cached.items() if k != "ts"}
        else:
            shodan = _fetch_shodan(ip)
            if shodan is not None:
                state.ipenrich_cache[ip] = {**shodan, "ts": now}

        # --- ipinfo ---
        ipinfo_cached = state.ipinfo_cache.get(ip)
        if _fresh(ipinfo_cached):
            ipinfo = {k: v for k, v in ipinfo_cached.items() if k != "ts"}
        else:
            ipinfo = _fetch_ipinfo(ip)
            if ipinfo is not None:
                state.ipinfo_cache[ip] = {**ipinfo, "ts": now}

        # --- AbuseIPDB ---
        abuse_cached = state.abuseipdb_cache.get(ip)
        if _fresh(abuse_cached):
            abuse = {k: v for k, v in abuse_cached.items() if k != "ts"}
        else:
            abuse = _fetch_abuseipdb(ip)
            if abuse is not None:
                state.abuseipdb_cache[ip] = {**abuse, "ts": now}

        # --- GreyNoise ---
        gn_cached = state.greynoise_cache.get(ip)
        if _fresh(gn_cached):
            greynoise = {k: v for k, v in gn_cached.items() if k != "ts"}
        else:
            greynoise = _fetch_greynoise(ip)
            if greynoise is not None:
                state.greynoise_cache[ip] = {**greynoise, "ts": now}

        # Apply scoring / tagging based on results
        try:
            _apply_reputation_tags(ip, shodan, ipinfo, abuse, greynoise)
        except Exception:
            pass

        # Small pause between IPs to be a polite API consumer
        time.sleep(0.5)
