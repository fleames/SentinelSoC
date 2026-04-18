# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/helpers.py -- Pure helper functions (no Flask, no side effects).
"""
import hashlib
import ipaddress
import re
import time
from collections import Counter
from datetime import datetime, timezone

from sentinel import config, state


def _normalize_client_ip(s):
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if s in ("-", "", "unknown"):
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _normalize_client_ip_or_network(s):
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if s in ("-", "", "unknown"):
        return None
    try:
        if "/" in s:
            return str(ipaddress.ip_network(s, strict=False))
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _is_protected_ip(s):
    """Return True if the IP or network is private, loopback, link-local, or otherwise
    not a routable public address that should never be banned."""
    if not s or not isinstance(s, str):
        return True
    try:
        obj = ipaddress.ip_network(s.strip(), strict=False)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except ValueError:
        return False


def _ip_subnet(ip):
    """Return /24 (IPv4) or /48 (IPv6) prefix string for subnet-diversity checks."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
        return str(ipaddress.ip_network(f"{ip}/48", strict=False).network_address)
    except ValueError:
        return ip


def _campaign_id(uri):
    """Stable 6-char hex ID for a botnet campaign keyed by trigger URI."""
    return "BN-" + hashlib.md5(uri.encode("utf-8", errors="replace")).hexdigest()[:6].upper()


def _normalize_uri_campaign(uri):
    """
    Collapse URI to a canonical attack signature that survives minor randomization.
    Strips query string; keeps path lowercased.
    """
    path = (uri or "/").split("?")[0].split("#")[0].lower().rstrip("/") or "/"
    path = re.sub(r"/[0-9a-f]{6,}/", "/*/", path)
    return path


def _fp_key(ip, ua, accept, accept_enc="", accept_lang="", tls_cipher="", cf_ja3=""):
    """
    Stable fingerprint for a client. Core signal: UA + Accept headers + TLS cipher + CF JA3.
    """
    raw = "|".join([
        (ua or "-").strip()[:200],
        (accept or "").strip()[:120],
        (accept_enc or "").strip()[:80],
        (accept_lang or "").strip()[:80],
        (tls_cipher or "").strip()[:40],
        (cf_ja3 or "").strip()[:40],
    ])
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{ip}|{digest}"


def _bucket_path(uri):
    p = (uri or "/").lower().split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    return p[:200]


def _is_login_path(path):
    return path in ("/login", "/wp-login.php", "/wp-login", "/admin", "/admin/login")


_STATIC_EXACT = frozenset((
    "/favicon.ico", "/favicon.svg", "/favicon.png",
    "/manifest.json", "/manifest.webmanifest", "/site.webmanifest",
    "/sw.js", "/service-worker.js", "/workbox.js",
    "/apple-icon", "/apple-touch-icon.png", "/apple-touch-icon",
    "/robots.txt", "/sitemap.xml",
))

def _is_static_asset(path):
    """Return True for paths that look like browser-fetched static resources."""
    p = (path or "").lower().split("?")[0]
    if p in _STATIC_EXACT:
        return True
    if any(p.startswith(pfx) for pfx in (
        "/assets/", "/static/", "/_next/", "/dist/", "/_nuxt/", "/build/",
        "/locales/",    # i18n translation files
        "/pwa-icon",    # PWA icons with size suffix
    )):
        return True
    return p.endswith((
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".avif", ".webp",
        ".map", ".json",   # covers /locales/*.json and manifest files
    ))


def _is_whitelisted_path(path):
    """Return True if path matches any entry in state.whitelisted_paths.
    Each whitelist entry is treated as a prefix: "/locales/" matches "/locales/en/common.json".
    An exact entry like "/api/health" is also supported."""
    p = (path or "").lower().split("?")[0]
    for entry in state.whitelisted_paths:
        e = entry.lower()
        if p == e or p.startswith(e):
            return True
    return False


def _behavior_bonus(ip, ua_key, path):
    b = state.ip_behavior[ip]
    win_s = max(1.0, b["last_seen"] - b["first_seen"])
    uniq_n = len(b["unique_paths"])
    req_n = b["req_count"]
    bonus = 0

    # -- Group 1: existing signals, now also tag the IP --

    if uniq_n >= config.SCANNER_MIN_PATHS and req_n <= config.SCANNER_MAX_REQS and win_s <= config.SCANNER_WINDOW_S:
        bonus += 8
        state.behavior_signal_counts["scanner"] += 1
        state.ip_tags[ip].add("scanner")

    login_pressure = b["login_hits"] + b["wp_login_hits"] + b["admin_hits"]
    if login_pressure >= config.BRUTEFORCE_MIN_HITS and win_s <= config.BRUTEFORCE_WINDOW_S:
        bonus += 6
        state.behavior_signal_counts["bruteforce"] += 1
        state.ip_tags[ip].add("bruteforce")

    if req_n >= config.ERROR_PROBE_MIN_REQS and b["status_4xx"] / max(1, req_n) >= config.ERROR_PROBE_4XX_RATE:
        bonus += 5
        state.behavior_signal_counts["error_probe"] += 1
        state.ip_tags[ip].add("error_probe")

    ua_spread = len(state.ua_to_ips.get(ua_key, ()))
    if ua_key and ua_key != "-" and ua_spread >= config.SHARED_UA_MIN_IPS:
        bonus += 4
        state.behavior_signal_counts["shared_ua_many_ips"] += 1
        state.ip_tags[ip].add("shared_ua")

    if b["ua_switches"] >= config.UA_ROTATION_MIN_SWITCHES and req_n <= config.UA_ROTATION_MAX_REQS and win_s <= config.UA_ROTATION_WINDOW_S:
        bonus += 5
        state.behavior_signal_counts["ip_ua_rotation"] += 1
        state.ip_tags[ip].add("ua_rotation")

    if path.startswith("/wp-") and "bot" in ua_key:
        bonus += 2

    # -- Group 2: new signals from existing state --

    # Server error probe: repeated 5xx responses suggest backend vulnerability scanning.
    if req_n >= config.SERVER_ERROR_MIN_REQS and b["status_5xx"] / max(1, req_n) >= config.SERVER_ERROR_5XX_RATE:
        bonus += 4
        state.behavior_signal_counts["server_error_probe"] += 1
        state.ip_tags[ip].add("server_error_probe")

    # Flood: very high request rate in a short burst window.
    if req_n >= config.FLOOD_REQ_THRESHOLD and win_s <= config.FLOOD_WINDOW_S:
        bonus += 6
        state.behavior_signal_counts["flood"] += 1
        state.ip_tags[ip].add("flood")

    # Headless automation: majority of requests carry no Referer header.
    no_ref = b.get("no_ref_hits", 0)
    if req_n >= config.HEADLESS_MIN_REQS and no_ref / max(1, req_n) >= config.HEADLESS_NO_REF_RATE:
        bonus += 3
        state.behavior_signal_counts["headless"] += 1
        state.ip_tags[ip].add("headless")

    # Multi-host scan: same IP probing several distinct virtual hosts.
    host_count = len(state.ip_hosts.get(ip, ()))
    if host_count >= config.MULTI_HOST_THRESHOLD:
        bonus += 5
        state.behavior_signal_counts["multi_host"] += 1
        state.ip_tags[ip].add("multi_host")

    # Empty UA: consistently no user-agent string.
    if req_n >= config.EMPTY_UA_MIN_REQS and (not ua_key or ua_key == "-"):
        bonus += 2
        state.behavior_signal_counts["empty_ua"] += 1
        state.ip_tags[ip].add("empty_ua")

    # Slow-and-low crawler: sustained activity over hours, many unique paths, low per-hour rate.
    hours_active = win_s / 3600.0
    if (hours_active >= config.SLOW_LOW_MIN_HOURS
            and uniq_n >= config.SLOW_LOW_MIN_PATHS):
        req_per_hour = req_n / hours_active
        err_rate_b = b["status_4xx"] / max(1, req_n)
        if 3.0 <= req_per_hour <= 60.0 and err_rate_b < 0.4:
            bonus += 6
            state.behavior_signal_counts["slow_and_low"] += 1
            state.ip_tags[ip].add("slow_and_low")

    return bonus


def _history_bucket_key(ts):
    return int(ts // config.HISTORY_BUCKET_S) * config.HISTORY_BUCKET_S


def _history_bucket():
    return {
        "ts": 0,
        "total": 0,
        "attacks": 0,
        "client_errors": 0,
        "server_errors": 0,
        "status": Counter(),
        "top_ips": Counter(),
        "top_paths": Counter(),
    }


def _update_ssh_history_bucket(ts):
    """Increment the per-minute SSH bucket. Must be called inside state.lock."""
    key = _history_bucket_key(ts)
    b = state.ssh_history_buckets.get(key)
    if b is None:
        b = {"ts": key, "total": 0}
        state.ssh_history_buckets[key] = b
    b["total"] += 1


def _update_history_bucket(ts, ip, path, status, score_value):
    key = _history_bucket_key(ts)
    b = state.history_buckets.get(key)
    if b is None:
        b = _history_bucket()
        b["ts"] = key
        state.history_buckets[key] = b
    b["total"] += 1
    if score_value > 0:
        b["attacks"] += 1
    if 400 <= status < 500:
        b["client_errors"] += 1
    elif status >= 500:
        b["server_errors"] += 1
    b["status"][str(status)] += 1
    b["top_ips"][ip] += 1
    b["top_paths"][path] += 1


def _prune_runtime_state(now=None):
    now = now or time.time()
    fp_cutoff = now - 86400
    for fp, ts in list(state.fp_last_seen.items()):
        if ts < fp_cutoff:
            state.fp_last_seen.pop(fp, None)
            state.fp_counts.pop(fp, None)

    behavior_cutoff = now - config.HISTORY_RETENTION_S
    cutoff_day = datetime.fromtimestamp(behavior_cutoff, tz=timezone.utc).strftime("%Y-%m-%d")
    for ip, b in list(state.ip_behavior.items()):
        if b.get("last_seen", 0) < behavior_cutoff:
            state.ip_behavior.pop(ip, None)
            state.ip_recent_paths.pop(ip, None)
            state.ip_to_uas.pop(ip, None)
            state.ip_days_seen.pop(ip, None)
            state.ip_hosts.pop(ip, None)
        elif ip in state.ip_days_seen:
            state.ip_days_seen[ip] = {d for d in state.ip_days_seen[ip] if d >= cutoff_day}

    # Rebuild UA to IP index from surviving ip_to_uas
    state.ua_to_ips.clear()
    for ip, uas in state.ip_to_uas.items():
        for u in uas:
            state.ua_to_ips[u].add(ip)

    # Remove TLS fingerprint entries for pruned IPs
    for ip in list(state.ip_tls_fp.keys()):
        if ip not in state.ip_behavior:
            fp_val = state.ip_tls_fp.pop(ip, None)
            if fp_val:
                state.tls_fp_to_ips[fp_val].discard(ip)
                if not state.tls_fp_to_ips[fp_val]:
                    state.tls_fp_to_ips.pop(fp_val, None)

    hist_cutoff_key = _history_bucket_key(now - config.HISTORY_RETENTION_S)
    for k in [k for k in state.history_buckets.keys() if k < hist_cutoff_key]:
        state.history_buckets.pop(k, None)
    for k in [k for k in state.ssh_history_buckets.keys() if k < hist_cutoff_key]:
        state.ssh_history_buckets.pop(k, None)


def _history_bucket_to_json(b):
    return {
        "ts": int(b.get("ts", 0)),
        "total": int(b.get("total", 0)),
        "attacks": int(b.get("attacks", 0)),
        "client_errors": int(b.get("client_errors", 0)),
        "server_errors": int(b.get("server_errors", 0)),
        "status": {str(k): int(v) for k, v in dict(b.get("status", {})).items()},
        "top_ips": [[str(ip), int(c)] for ip, c in Counter(b.get("top_ips", {})).most_common(12)],
        "top_paths": [[str(p), int(c)] for p, c in Counter(b.get("top_paths", {})).most_common(12)],
    }


def threat_level_label(attack_rps, err_rate_pct, top_ip_share_pct):
    """Coarse SOC rollup: not a replacement for SIEM rules."""
    score = 0
    if attack_rps > 50:
        score += 3
    elif attack_rps > 15:
        score += 2
    elif attack_rps > 5:
        score += 1
    if err_rate_pct > 25:
        score += 2
    elif err_rate_pct > 10:
        score += 1
    if top_ip_share_pct > 40:
        score += 1
    if score >= 5:
        return "CRITICAL", "#dc2626"
    if score >= 3:
        return "HIGH", "#ea580c"
    if score >= 1:
        return "ELEVATED", "#ca8a04"
    return "NORMAL", "#22c55e"


def _header_first(headers, *names):
    """Caddy logs headers as map[str][]string; keys may be Host, host, etc."""
    if not headers:
        return ""
    for name in names:
        v = headers.get(name)
        if isinstance(v, list) and v:
            s = (v[0] or "").strip()
            if s:
                return s
        elif isinstance(v, str) and v.strip():
            return v.strip()
    for k, vals in headers.items():
        if k.lower() in {n.lower() for n in names}:
            if isinstance(vals, list) and vals:
                s = (vals[0] or "").strip()
                if s:
                    return s
            elif isinstance(vals, str) and vals.strip():
                return vals.strip()
    return ""


def extract_request_host(req, headers):
    """
    Prefer Caddy's request.host (string). Fall back to Host / X-Forwarded-Host headers.
    """
    raw = req.get("host")
    if isinstance(raw, str) and raw.strip():
        h = raw.strip()
    else:
        h = _header_first(headers, "Host", "host")
    if not h:
        xf = _header_first(headers, "X-Forwarded-Host", "x-forwarded-host")
        if xf:
            h = xf.split(",")[0].strip()
    if not h:
        return "unknown"
    h = h.strip()
    if not h:
        return "unknown"
    low = h.lower().split("@")[-1].strip()
    for suf in (":443", ":80"):
        if low.endswith(suf):
            low = low[: -len(suf)]
            break
    return low or "unknown"


def _client_ip_from_access(data, req, headers):
    """
    Resolve the visitor IP for metrics. Behind Cloudflare, remote_ip is the edge;
    the end user is in Cf-Connecting-Ip or in Caddy's client_ip (trusted_proxies).
    """
    cf = _header_first(headers, "Cf-Connecting-Ip", "cf-connecting-ip", "CF-Connecting-IP")
    if cf:
        return cf.split(",")[0].strip()
    tc = _header_first(headers, "True-Client-Ip", "true-client-ip")
    if tc:
        return tc.split(",")[0].strip()

    for src in (req, data):
        if not isinstance(src, dict):
            continue
        v = src.get("client_ip")
        if isinstance(v, str) and v.strip() and v.strip() not in ("-", "unknown"):
            return v.strip()

    xff = _header_first(headers, "X-Forwarded-For", "x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()

    for src in (req, data):
        if not isinstance(src, dict):
            continue
        v = src.get("remote_ip")
        if isinstance(v, str) and v.strip() and v.strip() not in ("-", "unknown"):
            return v.strip()
    return "-"


def _coerce_http_status(val):
    if val is None or val is False:
        return 0
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, int):
        return val
    s = str(val).strip().split()
    if not s:
        return 0
    try:
        return int(s[0])
    except ValueError:
        return 0


def _normalize_caddy_headers(raw):
    """Caddy usually logs headers as a JSON object; some builds use a list of [name, value] pairs."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        out = {}
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                k = str(item[0])
                v = item[1]
                if k not in out:
                    out[k] = v
        return out
    return {}
