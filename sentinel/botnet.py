# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/botnet.py -- Botnet campaign detection worker.
"""
import time
from collections import Counter, defaultdict

from sentinel import config, state
from sentinel.helpers import _campaign_id


def _campaign_for_api(raw):
    c = raw if isinstance(raw, dict) else {}
    return {
        "id": str(c.get("id", "")),
        "trigger_uri": str(c.get("trigger_uri", "")),
        "detected_at": float(c.get("detected_at", 0) or 0),
        "last_active": float(c.get("last_active", 0) or 0),
        "total_hits": int(c.get("total_hits", 0) or 0),
        "ip_count": int(c.get("ip_count", 0) or 0),
        "ips": [str(x) for x in list(c.get("ips", []))[:30]],
        "subnet_count": int(c.get("subnet_count", 0) or 0),
        "asn_count": int(c.get("asn_count", 0) or 0),
        "asns": [str(x) for x in list(c.get("asns", []))[:10]],
        "country_count": int(c.get("country_count", 0) or 0),
        "countries": [str(x) for x in list(c.get("countries", []))[:20]],
        "confidence": int(c.get("confidence", 0) or 0),
        "shared_ua_ips": int(c.get("shared_ua_ips", 0) or 0),
        "shared_seq_ips": int(c.get("shared_seq_ips", 0) or 0),
        "burst_peak_10s": int(c.get("burst_peak_10s", 0) or 0),
    }


def detect_botnets():
    """
    Scan suspicious_hit_buffer and update botnet_campaigns.
    Called every BOTNET_CHECK_INTERVAL seconds by botnet_detection_worker().
    """
    now = time.time()
    cutoff = now - config.BOTNET_WINDOW_S

    buf = [h for h in list(state.suspicious_hit_buffer) if h["ts"] >= cutoff]

    by_uri = defaultdict(list)
    for h in buf:
        by_uri[h["uri"]].append(h)

    active_uris = set()

    with state.botnet_lock:
        for uri, hits in by_uri.items():
            distinct_ips = {h["ip"] for h in hits}
            distinct_subnets = {h["subnet"] for h in hits}
            distinct_asns = {
                h["asn"] for h in hits
                if h["asn"] not in ("", "Unknown", config.PLACEHOLDER_ASN)
            }
            distinct_countries = {
                h["country"] for h in hits
                if h["country"] not in ("", "??", config.PLACEHOLDER_CC)
            }

            if (
                len(distinct_ips) < config.BOTNET_MIN_IPS
                or len(distinct_subnets) < config.BOTNET_MIN_SUBNETS
                or len(distinct_asns) < config.BOTNET_MIN_ASNS
            ):
                continue

            active_uris.add(uri)

            conf = int(
                min(len(distinct_ips), 20) * 2
                + min(len(distinct_asns), 8) * 6
                + min(len(distinct_countries), 4) * 3
            )

            ua_to_ips_local = defaultdict(set)
            seq_to_ips_local = defaultdict(set)
            sec_counts = Counter()
            for h in hits:
                ua_norm = (h.get("ua") or "-").strip().lower()[:160]
                ua_to_ips_local[ua_norm].add(h["ip"])
                seq = (h.get("seq") or "").strip()[:300]
                if seq:
                    seq_to_ips_local[seq].add(h["ip"])
                sec_counts[int(h["ts"])] += 1

            max_shared_ua = max((len(v) for v in ua_to_ips_local.values()), default=0)
            max_shared_seq = max((len(v) for v in seq_to_ips_local.values()), default=0)

            burst_peak = 0
            if sec_counts:
                sec_keys = sorted(sec_counts.keys())
                for base in sec_keys:
                    win_sum = 0
                    for t in range(base, base + 10):
                        win_sum += sec_counts.get(t, 0)
                    burst_peak = max(burst_peak, win_sum)

            if max_shared_ua >= config.BOTNET_MIN_IPS:
                conf += 20
            if max_shared_seq >= config.BOTNET_MIN_IPS:
                conf += 12
            if burst_peak >= max(6, len(hits) // 3):
                conf += 10
            conf = min(100, int(conf))

            if uri in state.botnet_campaigns:
                c = state.botnet_campaigns[uri]
                c["last_active"] = now
                c["total_hits"] = len(hits)
                c["ip_count"] = len(distinct_ips)
                c["ips"] = sorted(distinct_ips)[:30]
                c["subnet_count"] = len(distinct_subnets)
                c["asn_count"] = len(distinct_asns)
                c["asns"] = sorted(distinct_asns)[:10]
                c["country_count"] = len(distinct_countries)
                c["countries"] = sorted(distinct_countries)
                c["confidence"] = conf
                c["shared_ua_ips"] = int(max_shared_ua)
                c["shared_seq_ips"] = int(max_shared_seq)
                c["burst_peak_10s"] = int(burst_peak)
            else:
                state.botnet_campaigns[uri] = {
                    "id": _campaign_id(uri),
                    "trigger_uri": uri,
                    "detected_at": min(h["ts"] for h in hits),
                    "last_active": now,
                    "total_hits": len(hits),
                    "ip_count": len(distinct_ips),
                    "ips": sorted(distinct_ips)[:30],
                    "subnet_count": len(distinct_subnets),
                    "asn_count": len(distinct_asns),
                    "asns": sorted(distinct_asns)[:10],
                    "country_count": len(distinct_countries),
                    "countries": sorted(distinct_countries),
                    "confidence": conf,
                    "shared_ua_ips": int(max_shared_ua),
                    "shared_seq_ips": int(max_shared_seq),
                    "burst_peak_10s": int(burst_peak),
                }

        # Expire stale campaigns
        for uri in [u for u, c in state.botnet_campaigns.items()
                    if now - c["last_active"] > config.BOTNET_EXPIRY_S]:
            del state.botnet_campaigns[uri]


def botnet_detection_worker():
    """Background thread: run botnet detection on a fixed interval."""
    while True:
        time.sleep(config.BOTNET_CHECK_INTERVAL)
        try:
            detect_botnets()
        except Exception:
            pass
