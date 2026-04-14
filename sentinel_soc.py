# ASCII-only source: valid UTF-8 on all platforms (avoids Windows-1252 byte 0x97 issues).
"""
Sentinel - SOC-oriented live log dashboard (Caddy JSON access log, local tail).
"""
import errno
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# ========================
# CONFIG
# ========================
def _effective_log_paths():
    """Return list of log paths to tail. LOG_PATH may be comma-separated for multiple sources."""
    raw = os.environ.get("LOG_PATH", "/var/log/caddy/all-access.log").strip() or "/var/log/caddy/all-access.log"
    return [p.strip() for p in raw.split(",") if p.strip()] or ["/var/log/caddy/all-access.log"]


def _effective_log_path():
    return _effective_log_paths()[0]


def _effective_log_from_start():
    return os.environ.get("LOG_FROM_START", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
        "y",
    )


# Snapshot at import (stream() re-reads env when the tail thread starts).
LOG_PATH = _effective_log_path()
LOG_FROM_START = _effective_log_from_start()
# If True, read the whole file from the start once, then follow new lines. If False, only new lines after startup (like tail -f).
# (Implemented with binary reads so positions match disk size; text-mode tail used to break this on Windows.)
_SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))
# Persistent data root outside the app tree (survives redeploy when you replace /opt/sentinel). When set and
# SENTINEL_BAN_LIST is omitted, defaults to STATE_DIR/bans.json. When SENTINEL_AUDIT_LOG is empty/unset, audit
# defaults to STATE_DIR/audit.jsonl (else next to this script).
STATE_DIR = os.environ.get("SENTINEL_STATE_DIR", "").strip().rstrip("/\\")
# Optional: persist muted-IP list as JSON array of strings. If key is absent and STATE_DIR is set, use STATE_DIR/bans.json.
# If key is present but empty, no ban file (even when STATE_DIR is set).
if "SENTINEL_BAN_LIST" in os.environ:
    BAN_LIST_PATH = os.environ.get("SENTINEL_BAN_LIST", "").strip()
else:
    BAN_LIST_PATH = os.path.join(STATE_DIR, "bans.json") if STATE_DIR else ""
# Optional: also add/remove iptables DROP for each ban (Linux, requires root/cap_net_admin).
IPTABLES_ENABLED = os.environ.get("SENTINEL_IPTABLES", "").lower() in ("1", "true", "yes")
IPTABLES_CHAIN = (os.environ.get("SENTINEL_IPTABLES_CHAIN") or "INPUT").strip() or "INPUT"
# When set, requests that lack Cloudflare headers (CF-Ray) are flagged as origin-bypass attempts.
SENTINEL_EXPECT_CF = os.environ.get("SENTINEL_EXPECT_CF", "").lower() in ("1", "true", "yes")
# Number of distinct UTC days an IP must be seen across before it is labelled a persistent threat.
PERSISTENT_THREAT_DAYS = int(os.environ.get("SENTINEL_PERSISTENT_DAYS", "3") or "3")
# Auth brute-force: auto-ban IPs that fail HTTP Basic Auth this many times. 0 = disabled.
AUTH_FAIL_BAN_THRESHOLD = int(os.environ.get("SENTINEL_AUTH_FAIL_BAN", "10") or "10")
# Remote ingest: Bearer key for POST /api/ingest. Empty = no key required (only safe on trusted nets).
INGEST_KEY      = os.environ.get("SENTINEL_INGEST_KEY",   "").strip()
IPINFO_TOKEN    = os.environ.get("SENTINEL_IPINFO_TOKEN", "3582d5bf47b48b").strip()
ABUSEIPDB_KEY   = os.environ.get("SENTINEL_ABUSEIPDB_KEY", "").strip()

# Optional HTTP Basic Auth for / /data /api/* (set both user and password). Empty = no auth.
AUTH_USER = os.environ.get("SENTINEL_AUTH_USER", "").strip()
AUTH_PASSWORD = os.environ.get("SENTINEL_AUTH_PASSWORD", "")
AUTH_ENABLED = bool(AUTH_USER and AUTH_PASSWORD)
# Append-only JSONL audit log (mute, unban, reset, auth_failed). SENTINEL_AUDIT_DISABLE=1 turns off.
_DEFAULT_AUDIT_LOG = os.path.join(_SENTINEL_DIR, "sentinel-audit.jsonl")
AUDIT_DISABLED = os.environ.get("SENTINEL_AUDIT_DISABLE", "").lower() in ("1", "true", "yes")
_audit_explicit = os.environ.get("SENTINEL_AUDIT_LOG", "").strip()
if AUDIT_DISABLED:
    AUDIT_LOG_PATH = ""
elif _audit_explicit:
    AUDIT_LOG_PATH = _audit_explicit
else:
    AUDIT_LOG_PATH = os.path.join(STATE_DIR, "audit.jsonl") if STATE_DIR else _DEFAULT_AUDIT_LOG

ALERT_QUEUE_MAX = 200
SCORE_ALERT_THRESHOLD = 5
GEO_WORKERS = 4

# Botnet campaign detection
BOTNET_WINDOW_S = 300       # sliding window width (5 min)
BOTNET_CHECK_INTERVAL = 10  # re-evaluate every N seconds
BOTNET_MIN_IPS = 3          # minimum distinct IPs to open a campaign
BOTNET_MIN_SUBNETS = 2      # minimum distinct /24 subnets (rules out one misconfigured host)
BOTNET_MIN_ASNS = 2         # minimum distinct ASNs (rules out one ISP)
BOTNET_EXPIRY_S = 1800      # drop campaigns silent for 30 min
HISTORY_RETENTION_DAYS = int(os.environ.get("SENTINEL_HISTORY_RETENTION_DAYS", "30") or "30")
HISTORY_RETENTION_S = max(1, HISTORY_RETENTION_DAYS) * 86400
HISTORY_BUCKET_S = 60
HISTORY_EVENT_MAX_SCAN = int(os.environ.get("SENTINEL_HISTORY_MAX_SCAN", "20000") or "20000")
HISTORY_EVENT_PAGE_MAX = 500
if STATE_DIR:
    BEHAVIOR_STATE_PATH = os.path.join(STATE_DIR, "behavior-state.json")
    PARSED_STATE_PATH = os.path.join(STATE_DIR, "parsed-state.json")
    HISTORY_BUCKETS_PATH = os.path.join(STATE_DIR, "history-buckets.json")
    HISTORY_EVENTS_DIR = os.path.join(STATE_DIR, "history-events")
else:
    BEHAVIOR_STATE_PATH = ""
    PARSED_STATE_PATH = ""
    HISTORY_BUCKETS_PATH = ""
    HISTORY_EVENTS_DIR = ""

# ========================
# DATA
# ========================
ips = Counter()
domains = Counter()
referers = Counter()
paths = Counter()
status_codes = Counter()
asn_counts = Counter()
countries = Counter()

ip_scores = defaultdict(int)
ip_geo = {}
ip_paths = defaultdict(Counter)
ip_tags = defaultdict(set)
asn_ips = defaultdict(set)

rps = 0
total = 0
current_second = 0
peak_rps = 0
attack_counter = 0
client_err = 0
server_err = 0
bytes_served = 0

rps_timeline = []
attack_timeline = []

geo_cache = {}
recent_alerts = deque(maxlen=ALERT_QUEUE_MAX)
geo_queue = deque()
geo_lock = threading.Lock()

# Requests seen before ipinfo returns: fold into real ASN/country on resolve (no stuck "Resolving..." row).
pending_geo_hits = defaultdict(int)

lock = threading.Lock()
audit_lock = threading.Lock()
stream_started_at = None
# Tail thread only; exposed in /data for debugging parse path vs dashboard total.
stream_parse_debug = {
    "text_lines": 0,
    "json_roots": 0,
    "dicts_yielded": 0,
    "buffer_overflows": 0,
}

# Manual "mute": excluded from dashboard stats. Optional iptables DROP when SENTINEL_IPTABLES=1.
banned_ips = set()
muted_hits = Counter()

# Botnet campaign tracking
# suspicious_hit_buffer holds recent scored hits for cross-IP correlation.
# deque is thread-safe for append in CPython; reads are done under lock snapshot.
suspicious_hit_buffer = deque(maxlen=10000)
botnet_campaigns = {}   # trigger_uri -> campaign dict
botnet_lock = threading.Lock()
fp_counts = Counter()
fp_last_seen = {}
ua_to_ips = defaultdict(set)
ip_to_uas = defaultdict(set)
ip_behavior = defaultdict(
    lambda: {
        "first_seen": 0.0,
        "last_seen": 0.0,
        "req_count": 0,
        "unique_paths": set(),
        "status_4xx": 0,
        "status_5xx": 0,
        "login_hits": 0,
        "wp_login_hits": 0,
        "admin_hits": 0,
        "ua_switches": 0,
        "last_ua": "",
    }
)
ip_recent_paths = defaultdict(lambda: deque(maxlen=4))
ip_days_seen = defaultdict(set)   # ip -> set of "YYYY-MM-DD" UTC day strings
auth_fail_counts = Counter()      # ip -> consecutive auth failures (cleared on ban)
ipenrich_cache   = {}             # ip -> Shodan InternetDB result cached 1h
ipinfo_cache     = {}             # ip -> ipinfo.io result cached 1h
abuseipdb_cache  = {}             # ip -> AbuseIPDB result cached 1h
sources = Counter()               # source label -> total events ingested
behavior_signal_counts = Counter()
history_buckets = {}
history_lock = threading.Lock()

PLACEHOLDER_CC = "..."
PLACEHOLDER_ASN = "Resolving..."


def _load_bans():
    if not BAN_LIST_PATH:
        return
    try:
        with open(BAN_LIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return
        new = set()
        for x in data:
            n = _normalize_client_ip(str(x))
            if n:
                new.add(n)
        with lock:
            banned_ips.clear()
            banned_ips.update(new)
    except (OSError, json.JSONDecodeError, TypeError):
        pass


def _save_bans():
    if not BAN_LIST_PATH:
        return
    try:
        with lock:
            lst = sorted(banned_ips)
        d = os.path.dirname(BAN_LIST_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = BAN_LIST_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(lst, f)
        os.replace(tmp, BAN_LIST_PATH)
    except OSError:
        pass


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
    import hashlib
    return "BN-" + hashlib.md5(uri.encode("utf-8", errors="replace")).hexdigest()[:6].upper()


def _normalize_uri_campaign(uri):
    """
    Collapse URI to a canonical attack signature that survives minor randomization.
    Strips query string; keeps path lowercased.  Longer paths are trimmed so that
    '/wp-admin/install.php?...' and '/wp-admin/install.php' map to the same key.
    """
    path = (uri or "/").split("?")[0].split("#")[0].lower().rstrip("/") or "/"
    # Collapse numeric or hex segments that botnets sometimes randomize, e.g.
    # /probe_a3f2/ -> /probe_*/   so near-identical scans cluster together.
    import re
    path = re.sub(r"/[0-9a-f]{6,}/", "/*/", path)
    return path


def _fp_key(ip, ua, accept, accept_enc="", accept_lang="", tls_cipher="", cf_ja3=""):
    """
    Stable fingerprint for a client. Core signal: UA + Accept headers + TLS cipher + CF JA3.
    IP is prefixed so per-IP dedup still works, but the hash captures device-level identity
    so the same tool rotating IPs produces the same fp suffix.
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


def _is_static_asset(path):
    """Return True for paths that look like browser-fetched static resources.
    These should not count toward unique-path scanner detection or rule scoring.
    """
    p = (path or "").lower().split("?")[0]
    if any(p.startswith(pfx) for pfx in ("/assets/", "/static/", "/_next/", "/dist/", "/_nuxt/", "/build/")):
        return True
    return p.endswith((
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".avif", ".webp",
        ".map",
    ))


def _behavior_bonus(ip, ua_key, path):
    b = ip_behavior[ip]
    win_s = max(1.0, b["last_seen"] - b["first_seen"])
    uniq_n = len(b["unique_paths"])
    req_n = b["req_count"]
    bonus = 0

    if uniq_n >= 20 and req_n <= 60 and win_s <= 180:
        bonus += 8
        behavior_signal_counts["scanner"] += 1
    login_pressure = b["login_hits"] + b["wp_login_hits"] + b["admin_hits"]
    if login_pressure >= 8 and win_s <= 240:
        bonus += 6
        behavior_signal_counts["bruteforce"] += 1
    if req_n >= 15 and b["status_4xx"] / max(1, req_n) >= 0.6:
        bonus += 5
        behavior_signal_counts["error_probe"] += 1

    ua_spread = len(ua_to_ips.get(ua_key, ()))
    if ua_key and ua_key != "-" and ua_spread >= 8:
        bonus += 4
        behavior_signal_counts["shared_ua_many_ips"] += 1
    if b["ua_switches"] >= 6 and req_n <= 80 and win_s <= 300:
        bonus += 5
        behavior_signal_counts["ip_ua_rotation"] += 1

    if path.startswith("/wp-") and "bot" in ua_key:
        bonus += 2
    return bonus


def _history_bucket_key(ts):
    return int(ts // HISTORY_BUCKET_S) * HISTORY_BUCKET_S


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


def _update_history_bucket(ts, ip, path, status, score_value):
    key = _history_bucket_key(ts)
    b = history_buckets.get(key)
    if b is None:
        b = _history_bucket()
        b["ts"] = key
        history_buckets[key] = b
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
    for fp, ts in list(fp_last_seen.items()):
        if ts < fp_cutoff:
            fp_last_seen.pop(fp, None)
            fp_counts.pop(fp, None)

    behavior_cutoff = now - HISTORY_RETENTION_S
    cutoff_day = datetime.fromtimestamp(behavior_cutoff, tz=timezone.utc).strftime("%Y-%m-%d")
    for ip, b in list(ip_behavior.items()):
        if b.get("last_seen", 0) < behavior_cutoff:
            ip_behavior.pop(ip, None)
            ip_recent_paths.pop(ip, None)
            ip_to_uas.pop(ip, None)
            ip_days_seen.pop(ip, None)
        elif ip in ip_days_seen:
            # Drop days older than the retention window
            ip_days_seen[ip] = {d for d in ip_days_seen[ip] if d >= cutoff_day}

    # Rebuild UA to IP index from surviving ip_to_uas
    ua_to_ips.clear()
    for ip, uas in ip_to_uas.items():
        for u in uas:
            ua_to_ips[u].add(ip)

    hist_cutoff_key = _history_bucket_key(now - HISTORY_RETENTION_S)
    for k in [k for k in history_buckets.keys() if k < hist_cutoff_key]:
        history_buckets.pop(k, None)


def _history_events_path(ts):
    if not HISTORY_EVENTS_DIR:
        return ""
    d = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    return os.path.join(HISTORY_EVENTS_DIR, f"{d}.jsonl")


def _append_history_event(event_row):
    path = _history_events_path(event_row.get("ts_epoch", time.time()))
    if not path:
        return
    try:
        os.makedirs(HISTORY_EVENTS_DIR, exist_ok=True)
        payload = json.dumps(event_row, separators=(",", ":"), ensure_ascii=True) + "\n"
        with history_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(payload)
    except OSError:
        pass


def _prune_history_event_files(now=None):
    if not HISTORY_EVENTS_DIR or not os.path.isdir(HISTORY_EVENTS_DIR):
        return
    now = now or time.time()
    cutoff = now - HISTORY_RETENTION_S
    for name in os.listdir(HISTORY_EVENTS_DIR):
        if not name.endswith(".jsonl"):
            continue
        p = os.path.join(HISTORY_EVENTS_DIR, name)
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_mtime < cutoff:
            try:
                os.remove(p)
            except OSError:
                pass


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


def _save_parsed_state():
    if not PARSED_STATE_PATH:
        return
    with lock:
        payload = {
            "saved_at": int(time.time()),
            "total": int(total),
            "rps": int(rps),
            "peak_rps": int(peak_rps),
            "current_second": int(current_second),
            "attack_counter": int(attack_counter),
            "client_err": int(client_err),
            "server_err": int(server_err),
            "bytes_served": int(bytes_served),
            "stream_started_at": float(stream_started_at or 0.0),
            "ips": [[str(k), int(v)] for k, v in ips.items()],
            "domains": [[str(k), int(v)] for k, v in domains.items()],
            "referers": [[str(k), int(v)] for k, v in referers.items()],
            "paths": [[str(k), int(v)] for k, v in paths.items()],
            "status_codes": [[str(k), int(v)] for k, v in status_codes.items()],
            "asn_counts": [[str(k), int(v)] for k, v in asn_counts.items()],
            "countries": [[str(k), int(v)] for k, v in countries.items()],
            "ip_scores": [[str(k), int(v)] for k, v in ip_scores.items()],
            "ip_geo": {
                str(k): {
                    "country": str((v or {}).get("country", "??")),
                    "asn": str((v or {}).get("asn", "Unknown")),
                }
                for k, v in ip_geo.items()
                if isinstance(v, dict)
            },
            "ip_paths": {
                str(ip): [[str(p), int(c)] for p, c in cnt.items()]
                for ip, cnt in ip_paths.items()
            },
            "ip_tags": {str(ip): sorted(str(t) for t in tags) for ip, tags in ip_tags.items()},
            "asn_ips": {str(asn): sorted(str(ip) for ip in ipset) for asn, ipset in asn_ips.items()},
            "rps_timeline": [int(x) for x in rps_timeline[-600:]],
            "attack_timeline": [int(x) for x in attack_timeline[-600:]],
            "recent_alerts": list(recent_alerts),
            "pending_geo_hits": {str(k): int(v) for k, v in pending_geo_hits.items()},
            "geo_cache": {
                str(k): {
                    "country": str((v or {}).get("country", "??")),
                    "asn": str((v or {}).get("asn", "Unknown")),
                }
                for k, v in geo_cache.items()
                if isinstance(v, dict)
            },
            "suspicious_hit_buffer": list(suspicious_hit_buffer),
            "stream_parse_debug": dict(stream_parse_debug),
            "muted_hits": {str(k): int(v) for k, v in muted_hits.items()},
            "sources": [[str(k), int(v)] for k, v in sources.items()],
        }
    with botnet_lock:
        payload["botnet_campaigns"] = {
            str(uri): _campaign_for_api(c) for uri, c in botnet_campaigns.items()
        }
    try:
        d = os.path.dirname(PARSED_STATE_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = PARSED_STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, PARSED_STATE_PATH)
    except OSError:
        pass


def _load_parsed_state():
    global total, rps, peak_rps, current_second, attack_counter, client_err, server_err, bytes_served, stream_started_at
    if not PARSED_STATE_PATH:
        return
    try:
        with open(PARSED_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    with lock:
        total = int(data.get("total", 0) or 0)
        rps = int(data.get("rps", 0) or 0)
        peak_rps = int(data.get("peak_rps", 0) or 0)
        current_second = int(data.get("current_second", 0) or 0)
        attack_counter = int(data.get("attack_counter", 0) or 0)
        client_err = int(data.get("client_err", 0) or 0)
        server_err = int(data.get("server_err", 0) or 0)
        bytes_served = int(data.get("bytes_served", 0) or 0)
        ss = float(data.get("stream_started_at", 0) or 0.0)
        stream_started_at = ss if ss > 0 else time.time()

        ips.clear()
        ips.update({str(k): int(v) for k, v in list(data.get("ips", []))})
        domains.clear()
        domains.update({str(k): int(v) for k, v in list(data.get("domains", []))})
        referers.clear()
        referers.update({str(k): int(v) for k, v in list(data.get("referers", []))})
        paths.clear()
        paths.update({str(k): int(v) for k, v in list(data.get("paths", []))})
        status_codes.clear()
        status_codes.update({str(k): int(v) for k, v in list(data.get("status_codes", []))})
        asn_counts.clear()
        asn_counts.update({str(k): int(v) for k, v in list(data.get("asn_counts", []))})
        countries.clear()
        countries.update({str(k): int(v) for k, v in list(data.get("countries", []))})
        ip_scores.clear()
        ip_scores.update({str(k): int(v) for k, v in list(data.get("ip_scores", []))})

        ip_geo.clear()
        for k, v in dict(data.get("ip_geo", {})).items():
            if isinstance(v, dict):
                ip_geo[str(k)] = {
                    "country": str(v.get("country", "??")),
                    "asn": str(v.get("asn", "Unknown")),
                }

        ip_paths.clear()
        for ip, rows in dict(data.get("ip_paths", {})).items():
            c = Counter()
            for p, cnt in list(rows):
                c[str(p)] += int(cnt)
            ip_paths[str(ip)] = c

        ip_tags.clear()
        for ip, tags in dict(data.get("ip_tags", {})).items():
            ip_tags[str(ip)] = set(str(t) for t in list(tags))

        asn_ips.clear()
        for asn, ip_list in dict(data.get("asn_ips", {})).items():
            asn_ips[str(asn)] = set(str(ip) for ip in list(ip_list))

        rps_timeline.clear()
        rps_timeline.extend(int(x) for x in list(data.get("rps_timeline", []))[-600:])
        attack_timeline.clear()
        attack_timeline.extend(int(x) for x in list(data.get("attack_timeline", []))[-600:])

        recent_alerts.clear()
        for row in list(data.get("recent_alerts", []))[:ALERT_QUEUE_MAX]:
            if isinstance(row, dict):
                recent_alerts.append(row)

        pending_geo_hits.clear()
        pending_geo_hits.update({str(k): int(v) for k, v in dict(data.get("pending_geo_hits", {})).items()})

        geo_cache.clear()
        for k, v in dict(data.get("geo_cache", {})).items():
            if isinstance(v, dict):
                geo_cache[str(k)] = {
                    "country": str(v.get("country", "??")),
                    "asn": str(v.get("asn", "Unknown")),
                }

        suspicious_hit_buffer.clear()
        for row in list(data.get("suspicious_hit_buffer", []))[-10000:]:
            if isinstance(row, dict):
                suspicious_hit_buffer.append(row)

        for k in ("text_lines", "json_roots", "dicts_yielded", "buffer_overflows"):
            stream_parse_debug[k] = int(dict(data.get("stream_parse_debug", {})).get(k, 0) or 0)

        muted_hits.clear()
        muted_hits.update({str(k): int(v) for k, v in dict(data.get("muted_hits", {})).items()})

        sources.clear()
        sources.update({str(k): int(v) for k, v in list(data.get("sources", []))})

    with botnet_lock:
        botnet_campaigns.clear()
        for uri, campaign in dict(data.get("botnet_campaigns", {})).items():
            botnet_campaigns[str(uri)] = _campaign_for_api(campaign)


def _save_behavior_state():
    if not BEHAVIOR_STATE_PATH:
        return
    with lock:
        _prune_runtime_state()
        payload = {
            "saved_at": int(time.time()),
            "fp_counts": [[k, int(v)] for k, v in fp_counts.most_common(25000)],
            "fp_last_seen": {k: float(v) for k, v in fp_last_seen.items()},
            "ip_to_uas": {ip: sorted(list(uas))[:30] for ip, uas in ip_to_uas.items()},
            "ip_behavior": {
                ip: {
                    "first_seen": float(b.get("first_seen", 0.0)),
                    "last_seen": float(b.get("last_seen", 0.0)),
                    "req_count": int(b.get("req_count", 0)),
                    "unique_paths": sorted(list(b.get("unique_paths", set())))[:150],
                    "status_4xx": int(b.get("status_4xx", 0)),
                    "status_5xx": int(b.get("status_5xx", 0)),
                    "login_hits": int(b.get("login_hits", 0)),
                    "wp_login_hits": int(b.get("wp_login_hits", 0)),
                    "admin_hits": int(b.get("admin_hits", 0)),
                    "ua_switches": int(b.get("ua_switches", 0)),
                    "last_ua": str(b.get("last_ua", ""))[:160],
                }
                for ip, b in ip_behavior.items()
            },
            "behavior_signal_counts": {k: int(v) for k, v in behavior_signal_counts.items()},
            "ip_days_seen": {ip: sorted(days) for ip, days in ip_days_seen.items() if days},
        }
    try:
        d = os.path.dirname(BEHAVIOR_STATE_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = BEHAVIOR_STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, BEHAVIOR_STATE_PATH)
    except OSError:
        pass


def _load_behavior_state():
    if not BEHAVIOR_STATE_PATH:
        return
    try:
        with open(BEHAVIOR_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    with lock:
        fp_counts.clear()
        for k, v in data.get("fp_counts", []):
            try:
                fp_counts[str(k)] += int(v)
            except (TypeError, ValueError):
                continue
        fp_last_seen.clear()
        for k, v in dict(data.get("fp_last_seen", {})).items():
            try:
                fp_last_seen[str(k)] = float(v)
            except (TypeError, ValueError):
                continue
        ip_to_uas.clear()
        for ip, uas in dict(data.get("ip_to_uas", {})).items():
            ip_to_uas[str(ip)].update(str(x) for x in list(uas)[:30])
        ua_to_ips.clear()
        for ip, uas in ip_to_uas.items():
            for u in uas:
                ua_to_ips[u].add(ip)
        ip_behavior.clear()
        for ip, raw in dict(data.get("ip_behavior", {})).items():
            if not isinstance(raw, dict):
                continue
            b = ip_behavior[str(ip)]
            b["first_seen"] = float(raw.get("first_seen", 0.0) or 0.0)
            b["last_seen"] = float(raw.get("last_seen", 0.0) or 0.0)
            b["req_count"] = int(raw.get("req_count", 0) or 0)
            b["unique_paths"] = set(str(x) for x in list(raw.get("unique_paths", []))[:150])
            b["status_4xx"] = int(raw.get("status_4xx", 0) or 0)
            b["status_5xx"] = int(raw.get("status_5xx", 0) or 0)
            b["login_hits"] = int(raw.get("login_hits", 0) or 0)
            b["wp_login_hits"] = int(raw.get("wp_login_hits", 0) or 0)
            b["admin_hits"] = int(raw.get("admin_hits", 0) or 0)
            b["ua_switches"] = int(raw.get("ua_switches", 0) or 0)
            b["last_ua"] = str(raw.get("last_ua", ""))[:160]
        behavior_signal_counts.clear()
        for k, v in dict(data.get("behavior_signal_counts", {})).items():
            try:
                behavior_signal_counts[str(k)] = int(v)
            except (TypeError, ValueError):
                continue
        ip_days_seen.clear()
        for ip, days in dict(data.get("ip_days_seen", {})).items():
            ip_days_seen[str(ip)] = set(str(d) for d in list(days) if isinstance(d, str) and len(d) == 10)
        _prune_runtime_state()


def _save_history_buckets():
    if not HISTORY_BUCKETS_PATH:
        return
    with lock:
        _prune_runtime_state()
        payload = {
            "saved_at": int(time.time()),
            "buckets": [_history_bucket_to_json(v) for _, v in sorted(history_buckets.items())],
        }
    try:
        d = os.path.dirname(HISTORY_BUCKETS_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = HISTORY_BUCKETS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, HISTORY_BUCKETS_PATH)
    except OSError:
        pass


def _load_history_buckets():
    if not HISTORY_BUCKETS_PATH:
        return
    try:
        with open(HISTORY_BUCKETS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    with lock:
        history_buckets.clear()
        for raw in data.get("buckets", []):
            if not isinstance(raw, dict):
                continue
            try:
                ts = int(raw.get("ts", 0))
            except (TypeError, ValueError):
                continue
            b = _history_bucket()
            b["ts"] = ts
            b["total"] = int(raw.get("total", 0) or 0)
            b["attacks"] = int(raw.get("attacks", 0) or 0)
            b["client_errors"] = int(raw.get("client_errors", 0) or 0)
            b["server_errors"] = int(raw.get("server_errors", 0) or 0)
            b["status"] = Counter({str(k): int(v) for k, v in dict(raw.get("status", {})).items()})
            b["top_ips"] = Counter({str(k): int(v) for k, v in list(raw.get("top_ips", []))})
            b["top_paths"] = Counter({str(k): int(v) for k, v in list(raw.get("top_paths", []))})
            history_buckets[ts] = b
        _prune_runtime_state()


def _state_flush_worker():
    while True:
        time.sleep(20)
        try:
            _save_parsed_state()
            _save_behavior_state()
            _save_history_buckets()
            _prune_history_event_files()
        except Exception:
            pass


def detect_botnets():
    """
    Scan suspicious_hit_buffer and update botnet_campaigns.
    Called every BOTNET_CHECK_INTERVAL seconds by botnet_detection_worker().

    Algorithm:
    1. Snapshot hits from the last BOTNET_WINDOW_S seconds.
    2. Group by normalized URI (attack signature).
    3. For groups with >= BOTNET_MIN_IPS distinct IPs from >= BOTNET_MIN_SUBNETS
       distinct /24 subnets AND >= BOTNET_MIN_ASNS distinct ASNs -> campaign.
    4. Confidence = weighted score of IP diversity, ASN spread, geographic spread.
    5. Expire campaigns inactive for BOTNET_EXPIRY_S.
    """
    now = time.time()
    cutoff = now - BOTNET_WINDOW_S

    # Thread-safe snapshot (deque iteration is safe under the GIL but we copy to avoid
    # mutation mid-loop from the stream thread).
    buf = [h for h in list(suspicious_hit_buffer) if h["ts"] >= cutoff]

    by_uri = defaultdict(list)
    for h in buf:
        by_uri[h["uri"]].append(h)

    active_uris = set()

    with botnet_lock:
        for uri, hits in by_uri.items():
            distinct_ips = {h["ip"] for h in hits}
            distinct_subnets = {h["subnet"] for h in hits}
            distinct_asns = {
                h["asn"] for h in hits
                if h["asn"] not in ("", "Unknown", PLACEHOLDER_ASN)
            }
            distinct_countries = {
                h["country"] for h in hits
                if h["country"] not in ("", "??", PLACEHOLDER_CC)
            }

            if (
                len(distinct_ips) < BOTNET_MIN_IPS
                or len(distinct_subnets) < BOTNET_MIN_SUBNETS
                or len(distinct_asns) < BOTNET_MIN_ASNS
            ):
                continue

            active_uris.add(uri)

            # Confidence: weighted sum, capped at 100.
            # ASN diversity carries most weight (hardest for attacker to fake).
            # IP count uses diminishing returns via min() cap.
            conf = int(
                min(len(distinct_ips), 20) * 2     # up to 40 pts
                + min(len(distinct_asns), 8) * 6   # up to 48 pts
                + min(len(distinct_countries), 4) * 3  # up to 12 pts
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

            if max_shared_ua >= BOTNET_MIN_IPS:
                conf += 20
            if max_shared_seq >= BOTNET_MIN_IPS:
                conf += 12
            if burst_peak >= max(6, len(hits) // 3):
                conf += 10
            conf = min(100, int(conf))

            if uri in botnet_campaigns:
                c = botnet_campaigns[uri]
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
                botnet_campaigns[uri] = {
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
        for uri in [u for u, c in botnet_campaigns.items()
                    if now - c["last_active"] > BOTNET_EXPIRY_S]:
            del botnet_campaigns[uri]


def botnet_detection_worker():
    """Background thread: run botnet detection on a fixed interval."""
    while True:
        time.sleep(BOTNET_CHECK_INTERVAL)
        try:
            detect_botnets()
        except Exception:
            pass


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


def _iptables_drop(ip_normalized, add):
    """
    Insert or remove INPUT DROP for one IP. Uses iptables / ip6tables as list args (no shell).
    Returns (ok, error_message_or_None).
    """
    if not IPTABLES_ENABLED:
        return True, None
    try:
        ip = ipaddress.ip_address(ip_normalized)
    except ValueError:
        return False, "invalid ip"
    ip_s = ip.compressed if ip.version == 6 else str(ip)
    bin_name = "ip6tables" if ip.version == 6 else "iptables"
    chain = IPTABLES_CHAIN
    check = [bin_name, "-C", chain, "-s", ip_s, "-j", "DROP"]
    r = subprocess.run(check, capture_output=True, timeout=25)
    exists = r.returncode == 0
    if add:
        if exists:
            return True, None
        ins = [bin_name, "-I", chain, "-s", ip_s, "-j", "DROP"]
        r2 = subprocess.run(ins, capture_output=True, timeout=25)
        if r2.returncode != 0:
            msg = (r2.stderr or r2.stdout or b"").decode("utf-8", errors="replace")[:400]
            return False, msg.strip() or "iptables failed"
        return True, None
    if not exists:
        return True, None
    rem = [bin_name, "-D", chain, "-s", ip_s, "-j", "DROP"]
    r2 = subprocess.run(rem, capture_output=True, timeout=25)
    if r2.returncode != 0:
        msg = (r2.stderr or r2.stdout or b"").decode("utf-8", errors="replace")[:400]
        return False, msg.strip() or "iptables failed"
    return True, None


def _sync_iptables_bans():
    if not IPTABLES_ENABLED:
        return
    with lock:
        lst = sorted(banned_ips)
    for ip in lst:
        _iptables_drop(ip, True)


def _password_matches(got, expected):
    if got is None or expected is None:
        return False
    try:
        a, b = got.encode("utf-8"), expected.encode("utf-8")
        if len(a) != len(b):
            return False
        return secrets.compare_digest(a, b)
    except Exception:
        return False


def _audit_actor():
    try:
        if request.authorization:
            return request.authorization.username
    except RuntimeError:
        pass
    return "unauthenticated"


def _audit_write(action, user, detail=None):
    """Append one JSON line to AUDIT_LOG_PATH (analyst accountability)."""
    if not AUDIT_LOG_PATH:
        return
    try:
        ra = request.remote_addr
        xff = (request.headers.get("X-Forwarded-For") or "")[:200]
    except RuntimeError:
        ra, xff = None, ""
    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "user": user if user is not None else "anonymous",
        "remote": ra,
        "xff": xff,
    }
    if detail:
        line["detail"] = detail
    try:
        d = os.path.dirname(AUDIT_LOG_PATH) or "."
        os.makedirs(d, exist_ok=True)
        payload = json.dumps(line, separators=(",", ":"), ensure_ascii=True) + "\n"
        with audit_lock:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(payload)
    except OSError as e:
        print(f"[sentinel] audit write failed ({AUDIT_LOG_PATH}): {e}", file=sys.stderr, flush=True)


def _touch_audit_file(path):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8"):
        pass


def _ensure_state_dir():
    if not STATE_DIR:
        print(
            "[sentinel] WARNING: SENTINEL_STATE_DIR is not set -- all metrics (bytes_served, "
            "totals, history, behavior) will be lost on restart. "
            "Set SENTINEL_STATE_DIR=/var/lib/sentinel (or any writable path) to enable persistence.",
            file=sys.stderr, flush=True,
        )
        return
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        if HISTORY_EVENTS_DIR:
            os.makedirs(HISTORY_EVENTS_DIR, mode=0o700, exist_ok=True)
        print(f"[sentinel] state dir ready: {STATE_DIR}", file=sys.stderr, flush=True)
    except OSError as err:
        print(f"[sentinel] state dir mkdir failed ({STATE_DIR}): {err}", file=sys.stderr, flush=True)


def _ensure_audit_file():
    """Create audit log path on startup so operators can confirm config and permissions."""
    global AUDIT_LOG_PATH
    if not AUDIT_LOG_PATH:
        print("[sentinel] audit log disabled (SENTINEL_AUDIT_DISABLE=1)", file=sys.stderr, flush=True)
        return
    try:
        _touch_audit_file(AUDIT_LOG_PATH)
        print(f"[sentinel] audit log ready: {AUDIT_LOG_PATH}", file=sys.stderr, flush=True)
        return
    except OSError as e:
        # systemd ProtectSystem=strict: paths outside ReadWritePaths hit EROFS, not EACCES.
        if (
            AUDIT_LOG_PATH != _DEFAULT_AUDIT_LOG
            and getattr(e, "errno", None) == errno.EROFS
        ):
            bad = AUDIT_LOG_PATH
            AUDIT_LOG_PATH = _DEFAULT_AUDIT_LOG
            print(
                f"[sentinel] audit log: {bad!r} is read-only in this unit ({e}); "
                f"using fallback {AUDIT_LOG_PATH!r} (remove SENTINEL_AUDIT_LOG or add ReadWritePaths)",
                file=sys.stderr,
                flush=True,
            )
            try:
                _touch_audit_file(AUDIT_LOG_PATH)
                print(f"[sentinel] audit log ready: {AUDIT_LOG_PATH}", file=sys.stderr, flush=True)
            except OSError as e2:
                print(f"[sentinel] audit log init failed ({AUDIT_LOG_PATH}): {e2}", file=sys.stderr, flush=True)
            return
        print(
            f"[sentinel] audit log init failed ({AUDIT_LOG_PATH}): {e} "
            "(under ProtectSystem=strict, add the directory to ReadWritePaths; "
            "or use SENTINEL_STATE_DIR under a writable path; "
            "or rely on the fallback file next to sentinel_soc.py)",
            file=sys.stderr,
            flush=True,
        )


# ========================
# GEO (async queue to avoid blocking stream)
# ========================
def geo_worker():
    while True:
        with geo_lock:
            if not geo_queue:
                time.sleep(0.05)
                continue
            ip = geo_queue.popleft()
        _fetch_geo(ip)


def _fetch_geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params=params,
            timeout=4,
        )
        r.raise_for_status()
        d = r.json()
        if "bogon" in d or d.get("error"):
            raise ValueError(d.get("error", {}).get("message", "ipinfo bogon/error"))
        geo_cache[ip] = {
            "country": d.get("country") or "??",
            "asn": d.get("org") or "Unknown",
        }
    except Exception:
        geo_cache[ip] = {"country": "??", "asn": "Unknown"}
    with lock:
        ip_geo[ip] = geo_cache[ip]
        n = pending_geo_hits.pop(ip, 0)
        if n:
            g = geo_cache[ip]
            asn_counts[g["asn"]] += n
            countries[g["country"]] += n
            asn_ips[g["asn"]].add(ip)
    return geo_cache[ip]


def enqueue_geo(ip):
    if ip in geo_cache or ip in ("-", "", "unknown"):
        return
    with geo_lock:
        if ip not in geo_cache and ip not in geo_queue:
            geo_queue.append(ip)


def get_geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    enqueue_geo(ip)
    return {"country": PLACEHOLDER_CC, "asn": PLACEHOLDER_ASN}


# ========================
# UA TAGS (crawler vs generic bot / automation)
# ========================
_CRAWLER_MARKERS = (
    "googlebot",
    "bingbot",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "yandex.com/bots",
    "slurp",
    "semrushbot",
    "ahrefsbot",
    "mj12bot",
    "dotbot",
    "petalbot",
    "bytespider",
    "facebookexternalhit",
    "linkedinbot",
    "twitterbot",
    "slackbot",
    "discordbot",
    "telegrambot",
    "applebot",
    "ia_archiver",
    "amazonbot",
    "pinterestbot",
    "tiktokspider",
    "crawler",
    "google-inspectiontool",
    "gptbot",
    "claudebot",
    "anthropic-ai",
    "perplexitybot",
)
_BOT_TOOL_MARKERS = (
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "httpx/",
    "go-http-client",
    "okhttp",
    "java/",
    "httpclient",
    "libwww",
    "scrapy",
    "headless",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "zgrab",
    "masscan",
    "nmap",
    "nikto",
    "sqlmap",
)


def _ua_tags(ua):
    """
    Classify User-Agent for UI tags. crawler = search/index/social fetchers;
    bot = broader automation (includes crawlers, HTTP libraries, empty UA).
    """
    ul = (ua or "").strip().lower()
    tags = []
    if any(m in ul for m in _CRAWLER_MARKERS):
        tags.append("crawler")
    is_bot = bool(tags) or not ul
    if not is_bot:
        if any(m in ul for m in _BOT_TOOL_MARKERS):
            is_bot = True
        elif "bot" in ul or "spider" in ul:
            is_bot = True
    if is_bot:
        tags.append("bot")
    out = []
    seen = set()
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ========================
# DETECTION RULES ENGINE
# ========================
# Each rule: name, match(event_dict)->bool, score int.
# "skip" rules short-circuit scoring entirely (e.g. trusted infra).
# event_dict keys: uri, ua, path, status, asn, country, cf_ray, cf_ip.
DETECTION_RULES = [
    # ── Trusted infra (short-circuit) ──────────────────────────────
    {
        "name": "cloudflare_trusted",
        "skip": True,
        "match": lambda e: "cloudflare" in (e.get("asn") or "").lower(),
        "score": 0,
    },
    # ── Static assets (short-circuit) ──────────────────────────────
    {
        "name": "static_asset",
        "skip": True,
        "match": lambda e: _is_static_asset((e.get("uri") or "").split("?")[0]),
        "score": 0,
    },
    # ── High-value paths ───────────────────────────────────────────
    {
        "name": "sensitive_path",
        "match": lambda e: any(x in (e.get("uri") or "").lower() for x in (
            ".env", ".git", "wp-admin", "xmlrpc", "phpmyadmin", "adminer",
            ".aws", "credentials", "shell", "eval-stdin", "boaform", "cgi-bin",
            "/actuator", "/api/v1/pods", "/.ds_store", "/server-status",
            "/config/", "/backup", "/.git/", "/.svn/", "/debug",
        )),
        "score": 10,
    },
    # ── Suspicious user-agents ─────────────────────────────────────
    {
        "name": "scanner_ua",
        "match": lambda e: any(x in (e.get("ua") or "").lower() for x in (
            "bot", "curl", "python", "wget", "scanner", "nikto", "sqlmap",
            "masscan", "zgrab", "nmap", "dirbuster", "gobuster", "wfuzz",
            "nuclei", "hydra", "metasploit",
        )),
        "score": 3,
    },
    # ── Missing / empty UA ─────────────────────────────────────────
    {
        "name": "empty_ua",
        "match": lambda e: not (e.get("ua") or "").strip() or (e.get("ua") or "-").strip() == "-",
        "score": 2,
    },
    # ── Credential stuffing / brute-force ──────────────────────────
    {
        "name": "credential_stuffing",
        "match": lambda e: (e.get("path") or "").lower() in (
            "/login", "/wp-login.php", "/signin", "/auth/login",
            "/account/login", "/user/login", "/admin/login",
        ) and e.get("status") in (401, 403),
        "score": 6,
    },
    # ── Origin-bypass (direct-to-origin when CF expected) ──────────
    {
        "name": "origin_bypass",
        "match": lambda e: SENTINEL_EXPECT_CF and not e.get("cf_ray"),
        "score": 5,
    },
]


def _apply_rules(event):
    """
    Run DETECTION_RULES against an event dict.
    Returns (total_score, list_of_matched_rule_names).
    Short-circuit rules with skip=True return (0, []) immediately when matched.
    """
    for rule in DETECTION_RULES:
        if rule.get("skip"):
            try:
                if rule["match"](event):
                    return 0, []
            except Exception:
                pass
    total = 0
    matched = []
    for rule in DETECTION_RULES:
        if rule.get("skip"):
            continue
        try:
            if rule["match"](event):
                total += rule.get("score", 0)
                matched.append(rule["name"])
        except Exception:
            pass
    return max(0, total), matched


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
    # Normalize for grouping: lowercase, drop default ports
    low = h.lower().split("@")[-1].strip()
    for suf in (":443", ":80"):
        if low.endswith(suf):
            low = low[: -len(suf)]
            break
    return low or "unknown"


def _client_ip_from_access(data, req, headers):
    """
    Resolve the visitor IP for metrics. Behind Cloudflare, remote_ip is the edge (e.g. 172.71.x.x);
    the end user is in Cf-Connecting-Ip or in Caddy's client_ip (trusted_proxies). Some JSON layouts
    put client_ip on the log root only, not inside request.
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


def _parse_caddy_access_line(data):
    """
    Normalize Caddy HTTP access log JSON. Many builds use {"request": {...}, "status": N}.
    Some emit a flat object: method, host, uri, remote_ip, headers, ... at the top level
    (no nested "request" key).
    """
    if not isinstance(data, dict):
        return None, 0
    status = _coerce_http_status(data.get("status"))
    req = data.get("request")
    # Empty {} is not usable; fall through and merge from top-level fields.
    if isinstance(req, dict) and req:
        return req, status

    hdrs = _normalize_caddy_headers(data.get("headers"))

    msg_l = str(data.get("msg") or "").lower()
    logger_l = str(data.get("logger") or "").lower()
    # Same file often mixes http.log.access lines with admin / TLS / startup JSON. Do not treat
    # "method+uri+remote_ip" alone as access (admin.api POST /load matches that shape).
    if "received request" in msg_l:
        return None, status
    if logger_l.startswith("admin"):
        return None, status

    has_access_metrics = (
        "bytes_read" in data
        or "duration" in data
        or data.get("size") is not None
    )
    is_access_logger = "log.access" in logger_l
    looks_flat_access = (
        ("handled request" in msg_l and data.get("remote_ip"))
        or (is_access_logger and data.get("remote_ip"))
        or (
            data.get("remote_ip")
            and has_access_metrics
            and 100 <= status < 600
        )
    )
    if looks_flat_access:
        return (
            {
                "host": data.get("host"),
                "uri": data.get("uri", "/"),
                "remote_ip": data.get("remote_ip"),
                "client_ip": data.get("client_ip"),
                "proto": data.get("proto"),
                "method": data.get("method"),
                "headers": hdrs,
            },
            status,
        )

    return None, status


def iter_caddy_log_objects(path, from_start=False):
    """
    Yield one dict per log record. Uses JSONDecoder.raw_decode on a text buffer so we support:
    - one JSON object per line (NDJSON),
    - pretty-printed objects spanning many lines,
    - multiple concatenated objects without newlines between them,
    in O(total bytes) without retrying json.loads on ever-growing strings.
    """
    dec = json.JSONDecoder()
    buf = ""
    max_buf = 24 * 1024 * 1024

    def _emit_obj(obj):
        if isinstance(obj, dict):
            stream_parse_debug["dicts_yielded"] += 1
            yield obj
        elif isinstance(obj, list):
            for x in obj:
                if isinstance(x, dict):
                    stream_parse_debug["dicts_yielded"] += 1
                    yield x

    for line in iter_log_lines(path, from_start=from_start):
        if not buf:
            line = line.lstrip("\ufeff")
        if not line.strip():
            continue
        buf += line + "\n"
        stream_parse_debug["text_lines"] += 1
        if len(buf) > max_buf:
            stream_parse_debug["buffer_overflows"] += 1
            print(
                f"[sentinel] JSON parse buffer > {max_buf} bytes; clearing (noise or huge record)",
                file=sys.stderr,
                flush=True,
            )
            buf = ""
            continue
        while True:
            buf = buf.lstrip()
            if not buf:
                break
            try:
                obj, end = dec.raw_decode(buf, 0)
            except json.JSONDecodeError:
                break
            buf = buf[end:]
            stream_parse_debug["json_roots"] += 1
            yield from _emit_obj(obj)

    buf = buf.lstrip()
    if buf:
        try:
            obj, end = dec.raw_decode(buf, 0)
            stream_parse_debug["json_roots"] += 1
            yield from _emit_obj(obj)
        except json.JSONDecodeError:
            pass


# ========================
# STREAM
# ========================
def iter_log_lines(path, from_start=False):
    """
    Follow a growing log file (tail -f). Uses binary reads + UTF-8 decode so file
    position matches os.stat().st_size on Windows and Linux (text mode tell() does not).
    When from_start is True, (re)open the current path at offset 0 so the full file is read,
    including after rotation or recreate (not only the initial open).
    """
    buf = bytearray()
    f = None
    inode = None
    seek_tail = not from_start
    opened_msg = False

    def open_fresh():
        nonlocal f, inode, opened_msg
        if f:
            try:
                f.close()
            except OSError:
                pass
        while True:
            try:
                f = open(path, "rb")
                break
            except FileNotFoundError:
                time.sleep(1)
            except OSError as oe:
                print(f"[sentinel] cannot open log {path!r}: {oe}", file=sys.stderr, flush=True)
                time.sleep(2)
        if seek_tail:
            f.seek(0, os.SEEK_END)
        st0 = os.stat(path)
        inode = st0.st_ino
        if not opened_msg:
            opened_msg = True
            mode = "replay from offset 0" if not seek_tail else "tail from EOF"
            print(
                f"[sentinel] log opened {path!r} size={st0.st_size} ({mode})",
                file=sys.stderr,
                flush=True,
            )

    open_fresh()
    try:
        while True:
            chunk = f.read(65536)
            if chunk:
                buf.extend(chunk)
                while True:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        break
                    raw = bytes(buf[: nl + 1])
                    del buf[: nl + 1]
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    yield line
                continue

            time.sleep(0.12)
            try:
                st = os.stat(path)
            except FileNotFoundError:
                buf.clear()
                while not os.path.exists(path):
                    time.sleep(0.5)
                open_fresh()
                continue

            pos = f.tell()
            if st.st_ino != inode or st.st_size < pos:
                buf.clear()
                open_fresh()
                continue

            if st.st_size > pos:
                continue
    finally:
        if f:
            try:
                f.close()
            except OSError:
                pass


def _process_log_event(data, source=""):
    """Process one Caddy access-log dict. Returns 'ok', 'noreq', or 'banned'."""
    global total, current_second, attack_counter, client_err, server_err, bytes_served

    req, status = _parse_caddy_access_line(data)
    if not req:
        return "noreq"

    h_root = _normalize_caddy_headers(data.get("headers"))
    h_req = _normalize_caddy_headers(req.get("headers"))
    headers = {**h_root, **h_req}
    ip_raw = _client_ip_from_access(data, req, headers)
    nip = _normalize_client_ip(ip_raw) if ip_raw else None
    mute_key = nip if nip is not None else (ip_raw.strip() if isinstance(ip_raw, str) else str(ip_raw))
    with lock:
        ip_banned = mute_key in banned_ips
        if ip_banned:
            muted_hits[mute_key] += 1
    if ip_banned:
        return "banned"

    ip = nip if nip is not None else ip_raw

    host = extract_request_host(req, headers)
    ref = _header_first(headers, "Referer", "referer") or "-"
    uri = req.get("uri", "/")
    path_bucket = _bucket_path(uri)
    ua = _header_first(headers, "User-Agent", "user-agent") or ""
    accept_v = _header_first(headers, "Accept", "accept")
    accept_enc_v = _header_first(headers, "Accept-Encoding", "accept-encoding")
    accept_lang_v = _header_first(headers, "Accept-Language", "accept-language")
    cf_ray_v = _header_first(headers, "CF-Ray", "cf-ray", "Cf-Ray")
    cf_ja3_v = _header_first(
        headers,
        "CF-HTTP-Fingerprint", "cf-http-fingerprint",
        "X-JA3-Fingerprint", "x-ja3-fingerprint",
    )
    tls_info = data.get("tls") if isinstance(data.get("tls"), dict) else {}
    tls_cipher_v = str(tls_info.get("cipher_suite", "") or "")
    ua_norm = (ua or "-").strip().lower()[:160]

    geo = get_geo(ip)
    asn = geo["asn"]
    country = geo.get("country", "??")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_epoch = time.time()
    fp = _fp_key(
        ip, ua, accept_v,
        accept_enc=accept_enc_v, accept_lang=accept_lang_v,
        tls_cipher=tls_cipher_v, cf_ja3=cf_ja3_v,
    )
    s, matched_rules = _apply_rules({
        "uri": uri,
        "ua": ua,
        "path": path_bucket,
        "status": status,
        "asn": asn,
        "cf_ray": bool(cf_ray_v),
    })

    with lock:
        total += 1
        current_second += 1
        try:
            bytes_served += int(data.get("size") or 0)
        except (TypeError, ValueError):
            pass

        ips[ip] += 1
        domains[host] += 1
        referers[ref] += 1
        paths[uri] += 1
        status_codes[status] += 1

        if 400 <= status < 500:
            client_err += 1
        elif status >= 500:
            server_err += 1

        # Lookup may finish between get_geo() and this lock; use cache so we do not strand counts on "Resolving...".
        resolved = geo_cache.get(ip)
        if resolved is not None:
            asn_u = resolved["asn"]
            country_u = resolved.get("country", "??")
        else:
            asn_u = asn
            country_u = country

        if asn_u == PLACEHOLDER_ASN:
            pending_geo_hits[ip] += 1
        else:
            asn_counts[asn_u] += 1
            asn_ips[asn_u].add(ip)
        if country_u and country_u != PLACEHOLDER_CC:
            countries[country_u] += 1

        ip_geo[ip] = resolved if resolved is not None else geo
        ip_paths[ip][uri] += 1
        for tg in _ua_tags(ua):
            ip_tags[ip].add(tg)

        fp_counts[fp] += 1
        fp_last_seen[fp] = ts_epoch
        ua_to_ips[ua_norm].add(ip)
        ip_to_uas[ip].add(ua_norm)

        b = ip_behavior[ip]
        if not b["first_seen"]:
            b["first_seen"] = ts_epoch
        b["last_seen"] = ts_epoch
        b["req_count"] += 1
        if not _is_static_asset(path_bucket) and (len(b["unique_paths"]) < 300 or path_bucket in b["unique_paths"]):
            b["unique_paths"].add(path_bucket)
        if 400 <= status < 500:
            b["status_4xx"] += 1
        elif status >= 500:
            b["status_5xx"] += 1
        if path_bucket in ("/login", "/signin"):
            b["login_hits"] += 1
        if path_bucket in ("/wp-login", "/wp-login.php"):
            b["wp_login_hits"] += 1
        if path_bucket.startswith("/admin"):
            b["admin_hits"] += 1
        if b["last_ua"] and b["last_ua"] != ua_norm:
            b["ua_switches"] += 1
        b["last_ua"] = ua_norm

        ip_recent_paths[ip].append(path_bucket)
        b_bonus = _behavior_bonus(ip, ua_norm, path_bucket)
        if b_bonus:
            s += b_bonus

        # Persistence detection: flag IPs seen across multiple calendar days.
        day_str = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime("%Y-%m-%d")
        ip_days_seen[ip].add(day_str)
        if len(ip_days_seen[ip]) >= PERSISTENT_THREAT_DAYS:
            ip_tags[ip].add("persistent")
            if s > 0:
                s += 3  # slow-burn attacker bonus

        ip_scores[ip] += s
        if s > 0:
            attack_counter += 1
            # Feed botnet correlation buffer (outside this lock to avoid contention,
            # but deque.append is atomic under the GIL so appending here is safe).
            suspicious_hit_buffer.append({
                "ts": time.time(),
                "ip": ip,
                "uri": _normalize_uri_campaign(uri),
                "asn": asn_u,
                "country": country_u,
                "subnet": _ip_subnet(ip),
                "ua": ua_norm,
                "fp": fp,
                "seq": ">".join(list(ip_recent_paths[ip])[-3:]),
            })

        if s >= SCORE_ALERT_THRESHOLD:
            recent_alerts.appendleft(
                {
                    "ts": ts,
                    "ip": ip,
                    "uri": uri[:200],
                    "score": s,
                    "status": status,
                    "country": country_u,
                    "asn": asn_u[:120],
                    "ua": (ua or "-")[:80],
                    "tags": _ua_tags(ua),
                    "rules": matched_rules,
                }
            )
        _update_history_bucket(ts_epoch, ip, path_bucket, status, s)
        if source:
            sources[source] += 1

    if country_u == PLACEHOLDER_CC or asn_u == PLACEHOLDER_ASN:
        enqueue_geo(ip)

    _append_history_event(
        {
            "ts": ts,
            "ts_epoch": ts_epoch,
            "ip": ip,
            "host": host,
            "ua": ua[:200],
            "accept": (accept_v or "")[:120],
            "fingerprint": fp,
            "uri": uri[:220],
            "path": path_bucket,
            "status": int(status),
            "score": int(s),
            "country": country_u,
            "asn": asn_u[:120],
            "tags": _ua_tags(ua),
        }
    )

    return "ok"


def stream(path=None, from_start=None, source_label=None):
    global stream_started_at

    log_path = path or _effective_log_path()
    from_start_flag = from_start if from_start is not None else _effective_log_from_start()
    if source_label is None:
        source_label = log_path

    if stream_started_at is None:
        stream_started_at = time.time()
    print(
        f"[sentinel] log tail path={log_path!r} LOG_FROM_START={from_start_flag} source={source_label!r}",
        file=sys.stderr,
        flush=True,
    )
    objects_seen = 0
    no_request = 0
    ingested = 0
    diag_issued = False
    try:
        for data in iter_caddy_log_objects(log_path, from_start=from_start_flag):
            if not isinstance(data, dict):
                continue
            objects_seen += 1

            result = _process_log_event(data, source=source_label)
            if result == "noreq":
                no_request += 1
                if no_request <= 2:
                    print(
                        f"[sentinel] skip non-access JSON object; sample keys={list(data.keys())[:25]}",
                        file=sys.stderr,
                        flush=True,
                    )
                continue
            if result != "ok":
                continue

            ingested += 1
            if from_start_flag and ingested > 0 and ingested % 25000 == 0:
                print(
                    f"[sentinel] replay progress: {ingested} lines ingested from {log_path!r}",
                    file=sys.stderr,
                    flush=True,
                )

            if not diag_issued and objects_seen >= 200 and ingested == 0:
                diag_issued = True
                try:
                    st = os.stat(log_path)
                    sz = st.st_size
                except OSError:
                    sz = -1
                print(
                    f"[sentinel] ingest stalled: parsed {objects_seen} JSON objects, 0 access records; "
                    f"no_request={no_request} file_bytes={sz} "
                    f"(check LOG_PATH and that objects look like Caddy access logs)",
                    file=sys.stderr,
                    flush=True,
                )
    except Exception:
        import traceback

        traceback.print_exc()


# ========================
# RESET LOOP
# ========================
def reset():
    global rps, current_second, peak_rps, attack_counter

    ticks = 0
    while True:
        time.sleep(1)
        with lock:
            rps = current_second
            peak_rps = max(peak_rps, rps)

            rps_timeline.append(rps)
            attack_timeline.append(attack_counter)

            if len(rps_timeline) > 60:
                rps_timeline.pop(0)
            if len(attack_timeline) > 60:
                attack_timeline.pop(0)

            current_second = 0
            attack_counter = 0
            ticks += 1
            if ticks % 30 == 0:
                _prune_runtime_state()
        if ticks % 60 == 0:
            _prune_history_event_files()


def reset_dashboard_state():
    """Clear all counters, timelines, geo cache, and alerts. Log reader thread keeps running."""
    global rps, total, current_second, peak_rps, attack_counter, client_err, server_err, bytes_served, stream_started_at
    with geo_lock:
        geo_queue.clear()
    with lock:
        ips.clear()
        domains.clear()
        referers.clear()
        paths.clear()
        status_codes.clear()
        asn_counts.clear()
        countries.clear()
        ip_scores.clear()
        ip_geo.clear()
        ip_paths.clear()
        ip_tags.clear()
        asn_ips.clear()
        geo_cache.clear()
        recent_alerts.clear()
        pending_geo_hits.clear()
        rps = 0
        total = 0
        current_second = 0
        peak_rps = 0
        attack_counter = 0
        client_err = 0
        server_err = 0
        bytes_served = 0
        rps_timeline.clear()
        attack_timeline.clear()
        stream_started_at = time.time()
        muted_hits.clear()
        stream_parse_debug["text_lines"] = 0
        stream_parse_debug["json_roots"] = 0
        stream_parse_debug["dicts_yielded"] = 0
        stream_parse_debug["buffer_overflows"] = 0
        suspicious_hit_buffer.clear()
        fp_counts.clear()
        fp_last_seen.clear()
        ua_to_ips.clear()
        ip_to_uas.clear()
        ip_behavior.clear()
        ip_recent_paths.clear()
        ip_days_seen.clear()
        auth_fail_counts.clear()
        sources.clear()
        behavior_signal_counts.clear()
        history_buckets.clear()
    with botnet_lock:
        botnet_campaigns.clear()


# ========================
# API
# ========================
def _auto_ban(ip, reason):
    """Ban an IP programmatically and write an auto_ban audit entry."""
    nip = _normalize_client_ip(ip)
    if not nip:
        return
    with lock:
        if nip in banned_ips:
            return  # already banned - nothing to do
        banned_ips.add(nip)
        muted_hits.pop(nip, None)
    _save_bans()
    _iptables_drop(nip, True)
    _audit_write("auto_ban", "sentinel", {"ip": nip, "reason": reason})
    print(f"[sentinel] auto-ban {nip!r}: {reason}", file=sys.stderr, flush=True)


@app.before_request
def _sentinel_auth_gate():
    if not AUTH_ENABLED:
        return None
    if request.path == "/health":
        return None
    # /api/ingest uses its own Bearer-token auth; skip Basic Auth gate for it.
    if request.path == "/api/ingest":
        return None
    auth = request.authorization
    if not auth or auth.username != AUTH_USER or not _password_matches(auth.password, AUTH_PASSWORD):
        _audit_write("auth_failed", "anonymous", {"path": request.path, "method": request.method})
        if AUTH_FAIL_BAN_THRESHOLD > 0:
            ra = request.remote_addr
            nip = _normalize_client_ip(ra) if ra else None
            if nip:
                with audit_lock:
                    auth_fail_counts[nip] += 1
                    count = auth_fail_counts[nip]
                if count >= AUTH_FAIL_BAN_THRESHOLD:
                    auth_fail_counts.pop(nip, None)
                    _auto_ban(nip, f"auth_fail_{count}x")
        return Response(
            "Authentication required\n",
            401,
            {"WWW-Authenticate": 'Basic realm="Sentinel"'},
        )
    return None


@app.route("/health")
def health():
    return Response("ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/data")
def data():
    with lock:
        rps_now = rps
        peak_now = peak_rps
        total_now = total
        client_err_now = client_err
        server_err_now = server_err
        uniq = len(ips)
        te = client_err_now + server_err_now
        err_rate = round(100.0 * te / total_now, 2) if total_now else 0.0
        top_ip_n = ips.most_common(1)
        top_share = round(100.0 * top_ip_n[0][1] / total_now, 1) if total_now and top_ip_n else 0.0
        attack_rps = attack_timeline[-1] if attack_timeline else 0
        level, level_color = threat_level_label(attack_rps, err_rate, top_share)

        top_threats = sorted(ip_scores.items(), key=lambda x: -x[1])[:20]
        threats_enriched = []
        for tip, sc in top_threats:
            if sc <= 0:
                continue
            g = ip_geo.get(tip, {})
            if not isinstance(g, dict):
                g = {}
            top_path = ip_paths[tip].most_common(1)
            p = top_path[0][0] if top_path else ""
            threats_enriched.append(
                {
                    "ip": tip,
                    "score": sc,
                    "hits": ips[tip],
                    "country": g.get("country", "?"),
                    "asn": (g.get("asn") or "")[:100],
                    "top_path": p[:120],
                    "tags": sorted(ip_tags.get(tip, ())),
                }
            )

        alerts_list = list(recent_alerts)[:50]

        uptime_s = int(time.time() - stream_started_at) if stream_started_at else None
        bytes_served_now = int(bytes_served)
        muted_total = int(sum(muted_hits.values()))
        sources_snapshot = dict(sources)
        banned_sorted = sorted(banned_ips)
        muted_dict = {k: int(muted_hits[k]) for k in banned_sorted}
        ip_tags_payload = {k: sorted(v) for k, v in ip_tags.items() if v}
        ips_top = ips.most_common(15)
        domains_top = domains.most_common(10)
        referers_top = referers.most_common(10)
        paths_top = paths.most_common(10)
        # Keep JSON keys as strings; mixed int/str keys can break Flask's sorted dumps.
        status_snapshot = {str(k): int(v) for k, v in status_codes.items()}
        asn_top = asn_counts.most_common(10)
        countries_top = countries.most_common(12)
        scores_snapshot = dict(ip_scores)
        geo_snapshot = {}
        for k, v in ip_geo.items():
            if isinstance(v, dict):
                geo_snapshot[k] = {
                    "country": str(v.get("country", "??") or "??"),
                    "asn": str(v.get("asn", "Unknown") or "Unknown"),
                }
            else:
                geo_snapshot[k] = {"country": "??", "asn": "Unknown"}
        rps_timeline_snapshot = list(rps_timeline)
        attack_timeline_snapshot = list(attack_timeline)
        stream_parse_debug_snapshot = dict(stream_parse_debug)
        fp_total = int(sum(fp_counts.values()))
        fp_unique = int(len(fp_counts))
        ua_cluster_max = int(max((len(v) for v in ua_to_ips.values()), default=0))
        ip_behavior_count = int(len(ip_behavior))
        behavior_signal_snapshot = {k: int(v) for k, v in behavior_signal_counts.items()}
        history_bucket_count = int(len(history_buckets))
        history_latest = int(max(history_buckets.keys()) if history_buckets else 0)

    # Snapshot botnet campaigns under their own lock (after releasing main lock)
    with botnet_lock:
        campaigns_snapshot = [
            _campaign_for_api(c)
            for c in sorted(
                botnet_campaigns.values(),
                key=lambda c: -int((c if isinstance(c, dict) else {}).get("confidence", 0) or 0),
            )
        ]

    return jsonify(
        {
            "rps": rps_now,
            "peak": peak_now,
            "total": total_now,
            "unique_ips": uniq,
            "client_errors": client_err_now,
            "server_errors": server_err_now,
            "error_rate_pct": err_rate,
            "threat_level": level,
            "threat_color": level_color,
            "attack_rps_last_tick": attack_rps,
            "stream_uptime_s": uptime_s,
            "ips": ips_top,
            "domains": domains_top,
            "referers": referers_top,
            "paths": paths_top,
            "status": status_snapshot,
            "asn": asn_top,
            "countries": countries_top,
            "scores": scores_snapshot,
            "geo": geo_snapshot,
            "top_threats": threats_enriched,
            "alerts": alerts_list,
            "botnet_campaigns": campaigns_snapshot,
            "rps_timeline": rps_timeline_snapshot,
            "attack_timeline": attack_timeline_snapshot,
            "server_time": datetime.now(timezone.utc).isoformat(),
            "banned_ips": banned_sorted,
            "muted_hits": muted_dict,
            "muted_total": muted_total,
            "bytes_served": bytes_served_now,
            "iptables_enabled": IPTABLES_ENABLED,
            "iptables_chain": IPTABLES_CHAIN,
            "auth_enabled": AUTH_ENABLED,
            "audit_log": bool(AUDIT_LOG_PATH),
            "audit_path": AUDIT_LOG_PATH,
            "state_dir": STATE_DIR,
            "ban_list_path": BAN_LIST_PATH,
            "parsed_state_path": PARSED_STATE_PATH,
            "log_path": _effective_log_path(),
            "log_paths": _effective_log_paths(),
            "log_from_start": _effective_log_from_start(),
            "ingest_enabled": True,
            "sources": sources_snapshot,
            "stream_parse_debug": stream_parse_debug_snapshot,
            "ip_tags": ip_tags_payload,
            "fingerprint_stats": {
                "unique": fp_unique,
                "total_hits": fp_total,
                "largest_ua_cluster_ips": ua_cluster_max,
            },
            "behavior_stats": {
                "tracked_ips": ip_behavior_count,
                "signals": behavior_signal_snapshot,
            },
            "history_stats": {
                "retention_days": HISTORY_RETENTION_DAYS,
                "bucket_count": history_bucket_count,
                "latest_bucket_ts": history_latest,
            },
        }
    )


@app.route("/api/reset", methods=["POST"])
def api_reset():
    reset_dashboard_state()
    _save_parsed_state()
    _save_behavior_state()
    _save_history_buckets()
    _audit_write("reset", _audit_actor(), {})
    return jsonify({"ok": True})


@app.route("/api/ban", methods=["POST"])
def api_ban():
    body = request.get_json(silent=True) or {}
    raw = (body.get("ip") or request.args.get("ip") or "").strip()
    nip = _normalize_client_ip(raw)
    if not nip:
        return jsonify({"error": "invalid ip"}), 400
    with lock:
        banned_ips.add(nip)
        muted_hits.pop(nip, None)
    _save_bans()
    ok_ipt, ipt_err = _iptables_drop(nip, True)
    _audit_write("mute", _audit_actor(), {"ip": nip})
    return jsonify(
        {
            "ok": True,
            "banned_ips": sorted(banned_ips),
            "iptables": {"enabled": IPTABLES_ENABLED, "ok": ok_ipt, "error": ipt_err},
        }
    )


@app.route("/api/unban", methods=["POST"])
def api_unban():
    body = request.get_json(silent=True) or {}
    raw = (body.get("ip") or request.args.get("ip") or "").strip()
    nip = _normalize_client_ip(raw)
    if not nip:
        return jsonify({"error": "invalid ip"}), 400
    with lock:
        banned_ips.discard(nip)
        muted_hits.pop(nip, None)
    _save_bans()
    ok_ipt, ipt_err = _iptables_drop(nip, False)
    _audit_write("unban", _audit_actor(), {"ip": nip})
    return jsonify(
        {
            "ok": True,
            "banned_ips": sorted(banned_ips),
            "iptables": {"enabled": IPTABLES_ENABLED, "ok": ok_ipt, "error": ipt_err},
        }
    )


@app.route("/api/audit", methods=["GET", "DELETE"])
def api_audit():
    if request.method == "DELETE":
        if not AUDIT_LOG_PATH:
            return jsonify({"ok": True, "cleared": 0})
        cleared = 0
        try:
            with audit_lock:
                try:
                    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                        cleared = sum(1 for ln in f if ln.strip())
                except OSError:
                    pass
                with open(AUDIT_LOG_PATH, "w", encoding="utf-8"):
                    pass  # truncate
        except OSError as e:
            return jsonify({"error": str(e)}), 500
        _audit_write("audit_cleared", _audit_actor(), {"entries_removed": cleared})
        return jsonify({"ok": True, "cleared": cleared})

    # GET
    limit = min(int(request.args.get("limit", 100)), 500)
    if not AUDIT_LOG_PATH or not os.path.exists(AUDIT_LOG_PATH):
        return jsonify({"entries": [], "audit_path": AUDIT_LOG_PATH, "audit_enabled": bool(AUDIT_LOG_PATH)})
    entries = []
    try:
        with audit_lock:
            with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    except OSError:
        pass
    return jsonify({"entries": entries[-limit:], "audit_path": AUDIT_LOG_PATH, "audit_enabled": True})


@app.route("/api/ip")
def api_ip():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    with lock:
        if ip not in ips and ip not in ip_geo:
            return jsonify({"error": "not seen yet"}), 404
        path_rows = ip_paths.get(ip, Counter()).most_common(50)
        return jsonify(
            {
                "ip": ip,
                "hits": int(ips[ip]),
                "score": int(ip_scores[ip]),
                "geo": ip_geo.get(ip, {}),
                "paths": [[p, int(c)] for p, c in path_rows],
                "tags": sorted(ip_tags.get(ip, ())),
            }
        )


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
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
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
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
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


@app.route("/api/ipenrich")
def api_ipenrich():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    now = time.time()

    # Check caches
    shodan_cached   = ipenrich_cache.get(ip)
    ipinfo_cached   = ipinfo_cache.get(ip)
    abuse_cached    = abuseipdb_cache.get(ip)
    def _fresh(c): return c is not None and now - c.get("ts", 0) < 3600
    if _fresh(shodan_cached) and _fresh(ipinfo_cached) and (not ABUSEIPDB_KEY or _fresh(abuse_cached)):
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
        ipenrich_cache[ip]  = {**shodan_data, "ts": now}
    if ipinfo_data is not None:
        ipinfo_cache[ip]    = {**ipinfo_data,  "ts": now}
    if abuse_data is not None:
        abuseipdb_cache[ip] = {**abuse_data,   "ts": now}

    return jsonify({
        "ok": True, "cached": False,
        "shodan":    shodan_data or {},
        "ipinfo":    ipinfo_data or {},
        "abuseipdb": abuse_data  or {},
    })


def _parse_epoch_param(raw, default_v):
    if raw is None or raw == "":
        return float(default_v)
    s = str(raw).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        # Accept ISO timestamp values from UI if needed.
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return float(default_v)


@app.route("/api/history/series")
def api_history_series():
    now = time.time()
    from_ts = _parse_epoch_param(request.args.get("from"), now - (HISTORY_RETENTION_S // 4))
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
    cutoff = now - HISTORY_RETENTION_S
    from_ts = max(from_ts, cutoff)
    with lock:
        rows = []
        for k in sorted(history_buckets.keys()):
            if k < from_ts or k > to_ts:
                continue
            b = history_buckets[k]
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
            "retention_days": HISTORY_RETENTION_DAYS,
        }
    )


@app.route("/api/history/days")
def api_history_days():
    now = time.time()
    cutoff = now - HISTORY_RETENTION_S
    day_map = {}
    with lock:
        for ts, b in history_buckets.items():
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
    if HISTORY_EVENTS_DIR and os.path.isdir(HISTORY_EVENTS_DIR):
        for name in os.listdir(HISTORY_EVENTS_DIR):
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
            "retention_days": HISTORY_RETENTION_DAYS,
        }
    )


@app.route("/api/history/events")
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
    cutoff = now - HISTORY_RETENTION_S
    from_ts = max(from_ts, cutoff)

    try:
        page = max(1, int(request.args.get("page", "1") or "1"))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get("page_size", "100") or "100")
    except ValueError:
        page_size = 100
    page_size = min(max(1, page_size), HISTORY_EVENT_PAGE_MAX)
    ip_f = (request.args.get("ip") or "").strip()
    host_f = (request.args.get("host") or "").strip().lower()
    ua_f = (request.args.get("ua") or "").strip().lower()
    path_f = (request.args.get("path") or "").strip().lower()
    status_f = (request.args.get("status") or "").strip()
    tag_f = (request.args.get("tag") or "").strip().lower()

    events = []
    scanned = 0
    if HISTORY_EVENTS_DIR and os.path.isdir(HISTORY_EVENTS_DIR):
        if day_f:
            file_names = [f"{day_f}.jsonl"]
        else:
            file_names = sorted(os.listdir(HISTORY_EVENTS_DIR), reverse=True)
        for name in file_names:
            if not name.endswith(".jsonl"):
                continue
            fp = os.path.join(HISTORY_EVENTS_DIR, name)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except OSError:
                continue
            for line in reversed(lines):
                if scanned >= HISTORY_EVENT_MAX_SCAN:
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
            if scanned >= HISTORY_EVENT_MAX_SCAN:
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
            "retention_days": HISTORY_RETENTION_DAYS,
        }
    )


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Accept JSONL Caddy access-log events pushed from remote servers.

    Authentication: if SENTINEL_INGEST_KEY is set, the request must carry
    ``Authorization: Bearer <key>``.  If the env var is empty, any caller on
    the trusted network is accepted (set a firewall rule accordingly).

    Body: one JSON object per line (JSONL / newline-delimited JSON).
    Header: ``X-Sentinel-Source`` names the remote source (shown in the
    Log Sources card).  Defaults to the caller's remote address.
    """
    if INGEST_KEY:
        auth_header = request.headers.get("Authorization", "")
        expected = f"Bearer {INGEST_KEY}"
        if not secrets.compare_digest(auth_header, expected):
            return jsonify({"ok": False, "error": "unauthorized"}), 401

    source = (
        (request.headers.get("X-Sentinel-Source") or "").strip()
        or request.remote_addr
        or "remote"
    )
    source = source[:80]  # cap label length

    body = request.get_data(as_text=False)
    if not body:
        return jsonify({"ok": True, "ingested": 0, "skipped": 0})

    ingested = 0
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
        result = _process_log_event(obj, source=source)
        if result == "ok":
            ingested += 1
        else:
            skipped += 1

    return jsonify({"ok": True, "ingested": ingested, "skipped": skipped})


@app.route("/api/source/remove", methods=["POST"])
def api_source_remove():
    """Remove a remote source label from the in-memory sources counter."""
    ip = request.json.get("source", "").strip() if request.is_json else ""
    if not ip:
        ip = (request.form.get("source") or request.args.get("source") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "source required"}), 400
    if ip in sources:
        del sources[ip]
    return jsonify({"ok": True})


# ========================
# UI - SOC command center
# ========================
@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sentinel | SOC</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"></script>
<style>
:root {
  --bg:#010208; --surface:rgba(4,8,20,0.65); --surface-solid:#040812;
  --glass:rgba(255,255,255,0.028); --glass-bright:rgba(255,255,255,0.065);
  --border:rgba(255,255,255,0.06); --border-bright:rgba(0,229,255,0.3);
  --border-glow:rgba(0,229,255,0.14);
  --muted:#2e4057; --text:#e2eeff; --text-dim:#6888a8;
  --accent:#00e5ff; --accent-glow:rgba(0,229,255,0.35); --accent-dim:rgba(0,229,255,0.09);
  --accent2:#a855f7; --accent2-glow:rgba(168,85,247,0.35); --accent2-dim:rgba(168,85,247,0.09);
  --accent3:#ff0080; --accent3-glow:rgba(255,0,128,0.35); --accent3-dim:rgba(255,0,128,0.09);
  --warn:#ffaa00; --warn-glow:rgba(255,170,0,0.35);
  --danger:#ff3344; --danger-glow:rgba(255,51,68,0.35);
  --ok:#00ff88; --ok-glow:rgba(0,255,136,0.35);
  --focus:#a855f7;
  --mono:'JetBrains Mono',ui-monospace,monospace;
  --sans:'Inter',system-ui,sans-serif;
  --radius:12px; --transition:0.18s cubic-bezier(0.4,0,0.2,1);
  --card-blur:saturate(200%) blur(24px);
}
*,*::before,*::after{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;}
/* Ambient orbs */
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 1100px 700px at 10% 8%, rgba(0,229,255,0.075) 0%,transparent 65%),
    radial-gradient(ellipse 800px 600px at 88% 82%, rgba(168,85,247,0.09) 0%,transparent 65%),
    radial-gradient(ellipse 600px 450px at 55% 25%, rgba(0,229,255,0.035) 0%,transparent 60%),
    radial-gradient(ellipse 500px 400px at 78% 15%, rgba(255,0,128,0.06) 0%,transparent 60%);
  animation:orbDrift 35s ease-in-out infinite alternate;
}
@keyframes orbDrift{
  0%  {opacity:1;}
  33% {opacity:0.85;}
  66% {opacity:0.95;}
  100%{opacity:0.8;}
}
/* Scanline + vignette overlay */
body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.13) 2px,
      rgba(0,0,0,0.13) 4px
    ),
    radial-gradient(ellipse 140% 100% at 50% 50%, transparent 40%, rgba(0,0,0,0.55) 100%);
  animation:scanShift 8s linear infinite;
}
@keyframes scanShift{from{background-position:0 0,center;}to{background-position:0 4px,center;}}
/* Add new keyframes for futuristic effects */
@keyframes glitch{
  0%,95%,100%{transform:none;filter:none;}
  96%{transform:translate(-2px,0) skewX(-3deg);filter:drop-shadow(2px 0 0 var(--accent3)) drop-shadow(-2px 0 0 var(--accent));}
  97%{transform:translate(2px,0) skewX(2deg);filter:drop-shadow(-2px 0 0 var(--accent2)) drop-shadow(2px 0 0 var(--accent3));}
  98%{transform:translate(-1px,1px);filter:none;}
  99%{transform:none;}
}
@keyframes holoShimmer{
  0%{background-position:0% 50%;}
  50%{background-position:100% 50%;}
  100%{background-position:0% 50%;}
}
@keyframes sweepDown{
  0%{transform:translateY(-100%);opacity:0;}
  20%{opacity:0.6;}
  100%{transform:translateY(200%);opacity:0;}
}
@keyframes stripePulse{
  0%,100%{opacity:1;box-shadow:0 0 18px var(--ok),0 0 50px var(--ok),0 0 80px rgba(0,255,136,0.3);}
  50%{opacity:0.7;box-shadow:0 0 8px var(--ok),0 0 20px var(--ok);}
}
header,.toolbar,.kpi-row,.layout,footer,.modal-backdrop{position:relative;z-index:1;}
#postureStrip{position:fixed;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--ok),var(--accent),var(--ok));background-size:200% 100%;transition:background 0.6s,box-shadow 0.6s;z-index:200;box-shadow:0 0 18px var(--ok),0 0 50px var(--ok);animation:stripePulse 3s ease-in-out infinite;}
/* Live dot */
@keyframes livePulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.5)}}
@keyframes sonarRing{0%{transform:scale(1);opacity:.6}100%{transform:scale(3.5);opacity:0}}
.live-dot{position:relative;width:8px;height:8px;border-radius:50%;background:var(--ok);flex-shrink:0;animation:livePulse 2s ease-in-out infinite;}
.live-dot::after{content:'';position:absolute;inset:0;border-radius:50%;background:var(--ok);animation:sonarRing 2s ease-out infinite;}
.live-dot.stale{background:var(--warn);animation-duration:3.5s;}
.live-dot.stale::after{background:var(--warn);}
/* Header */
header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;padding:14px 24px;margin-top:3px;background:rgba(2,5,14,0.82);border-bottom:1px solid rgba(255,255,255,0.06);backdrop-filter:var(--card-blur);box-shadow:0 1px 0 rgba(0,229,255,0.12),0 4px 40px rgba(0,0,0,0.6),0 0 80px rgba(0,229,255,0.04);}
.brand{display:flex;align-items:center;gap:12px;}
.brand-logo{font-size:1.1rem;font-weight:700;letter-spacing:.18em;background:linear-gradient(90deg,#e0f8ff 0%,var(--accent) 25%,var(--accent2) 55%,var(--accent3) 80%,#e0f8ff 100%);background-size:300% 100%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;filter:drop-shadow(0 0 12px rgba(0,229,255,0.5));animation:glitch 7s ease-in-out infinite,holoShimmer 5s linear infinite;}
.brand-sub{color:var(--muted);font-size:11px;margin-top:1px;}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);font-weight:700;font-size:10px;letter-spacing:.1em;border:1px solid var(--border-bright);color:var(--accent);background:var(--accent-dim);font-family:var(--mono);box-shadow:0 0 16px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,0.1);}
.badge.frozen{border-color:rgba(255,170,0,0.4);color:var(--warn);background:rgba(255,170,0,0.08);box-shadow:0 0 16px var(--warn-glow);}
/* DEFCON */
.posture-area{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.defcon-wrap{display:flex;flex-direction:column;align-items:center;gap:5px;}
.defcon-label{font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-family:var(--mono);}
.defcon-blocks{display:flex;gap:5px;}
.defcon-block{width:20px;height:34px;clip-path:polygon(4px 0%,100% 0%,calc(100% - 4px) 100%,0% 100%);background:rgba(255,255,255,0.025);border:1px solid rgba(255,255,255,0.06);transition:background var(--transition),box-shadow var(--transition),border-color var(--transition);backdrop-filter:blur(4px);}
.defcon-block.lit{border-color:transparent;}
@keyframes defPulse{0%,100%{opacity:1}50%{opacity:.35}}
.defcon-block.blk-pulse{animation:defPulse 1s ease-in-out infinite;}
/* Toolbar */
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 24px;background:rgba(2,4,12,0.72);border-bottom:1px solid rgba(255,255,255,0.05);backdrop-filter:var(--card-blur);box-shadow:0 1px 0 rgba(0,229,255,0.08),0 0 40px rgba(0,0,0,0.4);}
.toolbar input[type="search"]{flex:1;min-width:180px;max-width:360px;padding:7px 13px;border-radius:8px;border:1px solid rgba(255,255,255,0.09);background:rgba(255,255,255,0.04);color:var(--text);font-family:var(--mono);font-size:12px;transition:border-color var(--transition),box-shadow var(--transition);outline:none;backdrop-filter:blur(8px);}
.toolbar input[type="search"]:focus{border-color:var(--border-bright);box-shadow:0 0 0 3px var(--accent-dim),0 0 24px rgba(0,229,255,0.12);}
.hist-day-select{
  min-width:190px;max-width:230px;padding:6px 10px;
  border-radius:8px;border:1px solid rgba(255,255,255,0.09);
  background:rgba(255,255,255,0.04);color:var(--text);
  font-family:var(--mono);font-size:12px;outline:none;
  backdrop-filter:blur(8px);
  transition:border-color var(--transition),box-shadow var(--transition),color var(--transition);
}
.hist-day-select:focus{border-color:var(--border-bright);box-shadow:0 0 0 3px var(--accent-dim),0 0 20px rgba(0,212,255,0.1);}
.hist-day-select option{background:#07101e;color:#dde8f5;}
.hist-table-wrap{
  max-height:260px;overflow:auto;border:1px solid var(--border);border-radius:8px;
  scrollbar-width:thin;scrollbar-color:#1e293b transparent;
}
.hist-table-wrap::-webkit-scrollbar{width:6px;height:6px;}
.hist-table-wrap::-webkit-scrollbar-track{background:transparent;}
.hist-table-wrap::-webkit-scrollbar-thumb{
  background:linear-gradient(180deg,rgba(0,212,255,.35),rgba(30,41,59,.9));
  border-radius:999px;
}
.hist-table-wrap::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,rgba(0,212,255,.55),rgba(51,65,85,.95));}
.hist-table-wrap::-webkit-scrollbar-button{display:none;width:0;height:0;}
/* Global scrollbar theme (dashboard + modal surfaces) */
*{
  scrollbar-width:thin;
  scrollbar-color:#1e293b transparent;
}
*::-webkit-scrollbar{width:6px;height:6px;}
*::-webkit-scrollbar-track{background:transparent;}
*::-webkit-scrollbar-thumb{
  background:linear-gradient(180deg,rgba(0,212,255,.35),rgba(30,41,59,.9));
  border-radius:999px;
}
*::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,rgba(0,212,255,.55),rgba(51,65,85,.95));}
*::-webkit-scrollbar-button{display:none;width:0;height:0;}
.toolbar-sep{width:1px;height:20px;background:var(--border);flex-shrink:0;}
.toolbtn{padding:6px 14px;clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);border:1px solid rgba(255,255,255,0.08);background:rgba(255,255,255,0.035);color:var(--text-dim);font-size:11px;font-family:var(--mono);cursor:pointer;white-space:nowrap;transition:border-color var(--transition),color var(--transition),box-shadow var(--transition),background var(--transition),transform 0.1s;outline:none;backdrop-filter:blur(10px);}
.toolbtn:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,229,255,0.07);box-shadow:0 0 20px var(--accent-glow),inset 0 1px 0 rgba(0,229,255,0.2);}
.toolbtn:active{transform:scale(0.94);}
.toolbtn.on{border-color:var(--accent);background:rgba(0,229,255,0.12);color:var(--accent);box-shadow:0 0 18px var(--accent-glow),inset 0 1px 0 rgba(0,229,255,0.2);}
.toolbtn.danger:hover{border-color:var(--danger);color:var(--danger);background:rgba(255,51,68,0.08);box-shadow:0 0 20px var(--danger-glow);}
.poll-seg{display:flex;border:1px solid rgba(255,255,255,0.09);border-radius:8px;overflow:hidden;backdrop-filter:blur(8px);}
.poll-seg .poll-opt{border:none;border-radius:0;background:transparent;border-right:1px solid rgba(255,255,255,0.07);padding:6px 11px;}
.poll-seg .poll-opt:last-child{border-right:none;}
.poll-seg .poll-opt.on{background:rgba(0,229,255,0.12);color:var(--accent);box-shadow:inset 0 0 16px rgba(0,229,255,0.08);}
.poll-seg .poll-opt:hover:not(.on){background:rgba(255,255,255,0.05);box-shadow:none;border-color:transparent;}
/* KPI row */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;padding:16px 24px;}
.kpi{
  background:linear-gradient(135deg,rgba(255,255,255,0.045) 0%,rgba(255,255,255,0.015) 100%);
  border:1px solid rgba(255,255,255,0.07);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:2px solid transparent;
  clip-path:polygon(0% 0%,calc(100% - 10px) 0%,100% 10px,100% 100%,10px 100%,0% calc(100% - 10px));
  padding:12px 14px;
  backdrop-filter:var(--card-blur);
  transition:border-left-color .5s,box-shadow .5s;
  position:relative;overflow:hidden;
}
.kpi::after{content:'';position:absolute;inset:0;background:linear-gradient(180deg,rgba(255,255,255,0.05) 0%,transparent 45%);pointer-events:none;}
.kpi::before{
  content:'';position:absolute;top:0;right:0;
  width:10px;height:10px;
  background:linear-gradient(135deg,transparent 50%,rgba(0,229,255,0.4) 50%);
  pointer-events:none;
}
.kpi.ok    {border-left-color:var(--ok);    box-shadow:0 4px 32px rgba(0,0,0,0.5),0 0 30px rgba(0,255,136,0.12), inset 0 0 60px rgba(0,255,136,0.05);}
.kpi.warn  {border-left-color:var(--warn);  box-shadow:0 4px 32px rgba(0,0,0,0.5),0 0 30px rgba(255,170,0,0.12),inset 0 0 60px rgba(255,170,0,0.05);}
.kpi.danger{border-left-color:var(--danger);box-shadow:0 4px 32px rgba(0,0,0,0.5),0 0 30px rgba(255,51,68,0.12), inset 0 0 60px rgba(255,51,68,0.05);}
.kpi-hd{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;position:relative;}
.kpi .label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.12em;font-weight:500;}
.kpi .val{
  font-family:var(--mono);font-size:1.4rem;font-weight:700;font-variant-numeric:tabular-nums;
  letter-spacing:-.01em;position:relative;
  background:linear-gradient(90deg,#e0f8ff 0%,var(--accent) 40%,var(--accent2) 80%,#e0f8ff 100%);
  background-size:250% 100%;
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
  animation:holoShimmer 6s linear infinite;
}
.kpi.ok .val    {background-image:linear-gradient(90deg,#e0fff0 0%,var(--ok) 40%,var(--accent) 80%,#e0fff0 100%);background-size:250% 100%;}
.kpi.warn .val  {background-image:linear-gradient(90deg,#fff7e0 0%,var(--warn) 40%,#ffdd77 80%,#fff7e0 100%);background-size:250% 100%;}
.kpi.danger .val{background-image:linear-gradient(90deg,#ffe0e0 0%,var(--danger) 40%,var(--accent3) 80%,#ffe0e0 100%);background-size:250% 100%;}
.delta{font-size:9px;font-family:var(--mono);padding:2px 6px;border-radius:5px;font-weight:700;flex-shrink:0;backdrop-filter:blur(4px);}
.delta.up  {background:rgba(239,68,68,0.12); color:#f87171;border:1px solid rgba(239,68,68,0.2);}
.delta.down{background:rgba(34,197,94,0.12); color:#4ade80;border:1px solid rgba(34,197,94,0.2);}
.delta.nc  {color:var(--muted);}
/* Layout */
.layout{display:grid;grid-template-columns:1fr clamp(310px,27vw,460px);gap:16px;padding:0 24px 24px;max-width:1720px;margin:0 auto;transition:grid-template-columns .25s ease;}
.layout.sb-hidden{grid-template-columns:1fr 32px;}
@media(max-width:1100px){.layout,.layout.sb-hidden{grid-template-columns:1fr !important;}}
.sidebar{min-width:0;overflow:hidden;}
.layout.sb-hidden .sidebar .card{display:none;}
.sb-toggle-row{display:flex;justify-content:flex-end;margin-bottom:8px;}
/* Cards */
.card{
  background:linear-gradient(160deg,rgba(255,255,255,0.048) 0%,rgba(255,255,255,0.014) 50%,rgba(0,0,0,0.12) 100%);
  border:1px solid rgba(255,255,255,0.07);
  border-top:1px solid rgba(255,255,255,0.11);
  border-radius:var(--radius);margin-bottom:14px;overflow:hidden;
  backdrop-filter:var(--card-blur);
  box-shadow:0 8px 40px rgba(0,0,0,0.55),0 1px 0 rgba(255,255,255,0.06),0 0 0 1px rgba(0,0,0,0.3),0 0 60px rgba(0,229,255,0.025);
  position:relative;
}
/* Corner bracket HUD decoration */
.card::before{
  content:'';position:absolute;inset:0;pointer-events:none;z-index:0;
  background:
    linear-gradient(var(--accent),var(--accent)) top left / 12px 1px no-repeat,
    linear-gradient(var(--accent),var(--accent)) top left / 1px 12px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) top right / 12px 1px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) top right / 1px 12px no-repeat,
    linear-gradient(var(--accent3),var(--accent3)) bottom left / 12px 1px no-repeat,
    linear-gradient(var(--accent3),var(--accent3)) bottom left / 1px 12px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) bottom right / 12px 1px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) bottom right / 1px 12px no-repeat,
    linear-gradient(90deg,transparent 0%,rgba(0,229,255,0.18) 30%,rgba(168,85,247,0.12) 70%,transparent 100%) top / 100% 1px no-repeat;
}
.card h2{margin:0;padding:11px 16px;font-size:10px;text-transform:uppercase;letter-spacing:.16em;color:var(--text-dim);border-bottom:1px solid rgba(255,255,255,0.055);font-weight:600;background:rgba(0,0,0,0.25);position:relative;z-index:1;}
.card .hint{font-weight:400;text-transform:none;letter-spacing:0;color:#253444;margin-left:8px;}
.card .body{padding:8px 10px;max-height:290px;overflow:auto;}
.card .body::-webkit-scrollbar{width:4px;}
.card .body::-webkit-scrollbar-track{background:transparent;}
.card .body::-webkit-scrollbar-thumb{background:rgba(0,212,255,0.2);border-radius:2px;}
/* ── List rows (shared premium style) ── */
.list-empty{padding:18px 12px;color:var(--muted);font-family:var(--mono);font-size:11px;text-align:center;}
.list-row{display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:8px;font-family:var(--mono);font-size:11px;transition:background var(--transition),transform var(--transition),box-shadow var(--transition);cursor:default;position:relative;overflow:hidden;margin-bottom:2px;}
.list-row:hover{background:rgba(0,229,255,0.055);transform:translateX(3px);box-shadow:inset 0 0 0 1px rgba(0,229,255,0.1),0 0 20px rgba(0,229,255,0.04);}
.list-row.row-ip{cursor:pointer;}
.list-row.row-ip:active{background:rgba(0,229,255,0.12);}
.list-row.hl-focus{box-shadow:inset 0 0 0 1px rgba(168,85,247,0.55);background:rgba(168,85,247,0.09);}
.list-row-bg{position:absolute;left:0;top:0;bottom:0;background:linear-gradient(90deg,rgba(0,229,255,0.08),rgba(0,229,255,0.02));border-radius:8px;pointer-events:none;transition:width .5s cubic-bezier(0.4,0,0.2,1);}
.list-row-bg.danger{background:linear-gradient(90deg,rgba(255,51,68,0.1),rgba(255,51,68,0.02));}
.list-rank{font-size:9px;color:var(--muted);min-width:15px;text-align:right;flex-shrink:0;font-weight:700;position:relative;}
.list-rank.r1{color:var(--accent);}
.list-key{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#cbd5e1;position:relative;display:flex;align-items:center;gap:4px;min-width:0;}
.list-key.wrap{white-space:normal;flex-wrap:wrap;}
.list-val{font-size:11px;color:var(--accent);font-weight:700;flex-shrink:0;position:relative;font-variant-numeric:tabular-nums;}
.list-val.danger{color:var(--danger);}
.list-val.warn{color:var(--warn);}
.list-val.ok{color:var(--ok);}
.list-pct{font-size:9px;color:var(--muted);flex-shrink:0;min-width:34px;text-align:right;position:relative;font-variant-numeric:tabular-nums;}
/* Status code dot */
.sc-dot{display:inline-block;width:6px;height:6px;border-radius:50%;flex-shrink:0;}
/* Tags */
.tag{font-size:9px;text-transform:uppercase;letter-spacing:.06em;padding:1px 5px;border-radius:3px;font-weight:600;flex-shrink:0;font-family:var(--sans);}
.tag-bot       {background:rgba(12,39,68,0.8);  color:#7dd3fc;border:1px solid rgba(30,73,118,0.6);}
.tag-crawler   {background:rgba(42,31,61,0.8);  color:#d8b4fe;border:1px solid rgba(76,29,149,0.5);}
.tag-persistent{background:rgba(60,10,10,0.9);  color:#fca5a5;border:1px solid rgba(185,28,28,0.7);}
/* Charts */
.charts-dual{display:grid;grid-template-columns:1fr 190px;gap:12px;}
@media(max-width:900px){.charts-dual{grid-template-columns:1fr;}}
.chart-wrap{padding:12px;height:210px;position:relative;background:rgba(0,0,0,0.15);border-radius:10px;}
/* World map */
#worldMapWrap{padding:8px 10px;height:310px;position:relative;}
.map-hover-tip{
  position:fixed;display:none;z-index:99999;pointer-events:none;
  background:rgba(2,6,18,0.94);border:1px solid rgba(0,229,255,0.28);
  color:var(--text);font-family:var(--mono);font-size:11px;
  padding:6px 12px;clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);
  box-shadow:0 8px 40px rgba(0,0,0,0.7),0 0 24px rgba(0,229,255,0.14);
  backdrop-filter:blur(16px);
  transform:translate(12px,-16px);white-space:nowrap;
}
.map-hover-readout{padding:0 10px 8px;color:var(--text-dim);font-family:var(--mono);font-size:11px;}
.map-legend{display:flex;align-items:center;gap:10px;padding:0 10px 10px 10px;}
.map-legend-item{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:10px;font-family:var(--mono);}
.map-legend-swatch{width:10px;height:10px;border-radius:999px;display:inline-block;border:1px solid rgba(255,255,255,0.18);}
.map-legend-swatch.low{background:#1e3a8a;}
.map-legend-swatch.med{background:#0ea5e9;}
.map-legend-swatch.high{background:#67e8f9;}
.jvm-tooltip{background:rgba(2,6,18,0.94) !important;border:1px solid rgba(0,229,255,0.28) !important;color:var(--text) !important;font-family:var(--mono) !important;font-size:11px !important;padding:6px 12px !important;border-radius:8px !important;box-shadow:0 8px 40px rgba(0,0,0,0.7),0 0 24px rgba(0,229,255,0.14) !important;backdrop-filter:blur(16px) !important;}
/* Alert feed */
.alert-row{
  border-left:3px solid var(--danger);padding:9px 11px;margin-bottom:7px;
  background:linear-gradient(135deg,rgba(255,51,68,0.07) 0%,rgba(4,8,20,0.65) 100%);
  border-radius:8px;font-size:11px;font-family:var(--mono);cursor:pointer;
  transition:background var(--transition),box-shadow var(--transition),transform var(--transition);
  box-shadow:-3px 0 18px rgba(255,51,68,0.22),0 2px 14px rgba(0,0,0,0.35),inset 0 1px 0 rgba(255,255,255,0.05);
  backdrop-filter:blur(10px);overflow:hidden;position:relative;
}
.alert-row::before{
  content:'';position:absolute;left:0;right:0;top:0;height:1px;
  background:linear-gradient(90deg,var(--danger),transparent 60%);
  opacity:0.6;pointer-events:none;
}
.alert-row::after{
  content:'';position:absolute;left:0;right:0;height:40%;
  background:linear-gradient(180deg,rgba(255,51,68,0.06),transparent);
  pointer-events:none;animation:sweepDown 4s ease-in-out infinite;
  animation-play-state:paused;
}
.alert-row:hover::after{animation-play-state:running;}
.alert-row:hover{background:linear-gradient(135deg,rgba(255,51,68,0.11) 0%,rgba(8,14,32,0.75) 100%);transform:translateX(3px);box-shadow:-4px 0 24px rgba(255,51,68,0.3),0 2px 14px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.07);}
.alert-row.sev-med{border-left-width:4px;border-left-color:var(--warn);background:linear-gradient(135deg,rgba(255,170,0,0.07) 0%,rgba(4,8,20,0.65) 100%);box-shadow:-4px 0 20px rgba(255,170,0,0.25),0 2px 14px rgba(0,0,0,0.35);}
.alert-row.sev-med::before{background:linear-gradient(90deg,var(--warn),transparent 60%);}
.alert-row.sev-hi {border-left-width:5px;border-left-color:var(--danger);background:linear-gradient(135deg,rgba(255,51,68,0.09) 0%,rgba(4,8,20,0.65) 100%);box-shadow:-5px 0 28px rgba(255,51,68,0.35),0 2px 14px rgba(0,0,0,0.35),0 0 50px rgba(255,51,68,0.08);}
.alert-row.hl-focus{border-left-color:var(--focus);box-shadow:-4px 0 20px rgba(168,85,247,0.4);background:linear-gradient(135deg,rgba(168,85,247,0.09) 0%,rgba(4,8,20,0.65) 100%);}
.alert-row.hl-focus::before{background:linear-gradient(90deg,var(--accent2),transparent 60%);}
.alert-hd{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:5px;}
.alert-time{color:var(--muted);font-size:10px;margin-left:auto;flex-shrink:0;}
.score-pill{display:inline-flex;align-items:center;justify-content:center;min-width:28px;height:18px;clip-path:polygon(5px 0%,100% 0%,calc(100% - 5px) 100%,0% 100%);font-size:9px;font-family:var(--mono);font-weight:700;padding:0 8px;flex-shrink:0;backdrop-filter:blur(6px);}
.score-pill.lo {background:rgba(0,30,55,0.8); color:var(--accent);border:1px solid rgba(0,229,255,0.3);box-shadow:0 0 12px rgba(0,229,255,0.2);}
.score-pill.med{background:rgba(40,25,0,0.8);  color:var(--warn);border:1px solid rgba(255,170,0,0.35);box-shadow:0 0 12px rgba(255,170,0,0.25);}
.score-pill.hi {background:rgba(40,5,10,0.8); color:var(--danger);border:1px solid rgba(255,51,68,0.4);box-shadow:0 0 14px rgba(255,51,68,0.3);}
.alert-row .uri{color:#f87171;word-break:break-all;}
.alert-row .ua {color:var(--muted);font-size:10px;margin-top:4px;}
.alert-ip{font-size:12px;font-weight:700;letter-spacing:0.03em;cursor:pointer;}
.alert-flag{font-size:13px;flex-shrink:0;}
.alert-cc{font-size:9px;color:var(--muted);flex-shrink:0;}
.alert-tags{display:flex;align-items:center;gap:3px;flex-wrap:wrap;}
.alert-uri{color:#f87171;word-break:break-all;margin-top:4px;font-size:11px;padding-left:2px;}
.alert-meta{color:var(--muted);font-size:10px;margin-top:3px;display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding-left:2px;}
.alert-sep{opacity:0.4;}
.alert-ua{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:280px;}
@keyframes newFlash{0%{opacity:1;transform:scale(1.1)}100%{opacity:0;transform:scale(1)}}
.new-badge{font-size:8px;font-family:var(--mono);font-weight:700;letter-spacing:.1em;padding:1px 5px;clip-path:polygon(4px 0%,100% 0%,calc(100% - 4px) 100%,0% 100%);background:var(--accent-dim);color:var(--accent);border:1px solid var(--border-bright);box-shadow:0 0 12px var(--accent-glow);animation:newFlash 3s ease-out forwards;}
/* Threat board */
.th-grid{display:grid;grid-template-columns:22px 1fr 72px 54px 34px;gap:6px;padding:7px 10px;font-size:10px;font-family:var(--mono);color:var(--muted);border-bottom:1px solid rgba(255,255,255,0.06);text-transform:uppercase;letter-spacing:.06em;}
.th-row{display:grid;grid-template-columns:22px 1fr 72px 54px 34px;gap:6px;padding:7px 10px;font-family:var(--mono);font-size:11px;border-bottom:1px solid rgba(255,255,255,0.025);align-items:center;cursor:pointer;border-radius:7px;margin:0 2px;transition:background var(--transition),transform var(--transition),box-shadow var(--transition);}
.th-row:hover{background:rgba(0,229,255,0.055);transform:translateX(2px);box-shadow:inset 0 0 0 1px rgba(0,229,255,0.1),0 0 20px rgba(0,229,255,0.03);}
.th-row.rank1{box-shadow:inset 0 0 0 1px rgba(255,51,68,0.3);background:rgba(255,51,68,0.035);animation:defPulse 2.5s ease-in-out infinite;}
.th-row.hl-focus{box-shadow:inset 0 0 0 1px rgba(168,85,247,0.5);background:rgba(168,85,247,0.06);}
.th-row .rank{color:var(--muted);font-size:10px;text-align:center;}
.th-row .rank.r1{color:var(--danger);text-shadow:0 0 8px var(--danger-glow);}
.th-row .ip{color:var(--accent);overflow:hidden;min-width:0;display:flex;flex-wrap:wrap;align-items:center;gap:3px;}
.th-row .hits{text-align:right;color:var(--text-dim);}
.th-row .cc{text-align:center;}
.sc-segs{display:flex;gap:2px;align-items:center;justify-content:flex-end;}
.sc-seg{width:8px;height:14px;border-radius:2px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.06);transition:background var(--transition),box-shadow var(--transition);}
.sc-seg.lit{border-color:transparent;}
.sc-num{font-size:10px;color:var(--warn);min-width:22px;text-align:right;font-weight:700;}
/* Modal */
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,3,.85);z-index:100;align-items:flex-start;justify-content:center;padding:20px;overflow:auto;backdrop-filter:blur(16px);}
.modal-backdrop.open{display:flex;}
@keyframes modalIn{from{opacity:0;transform:translateY(32px) scale(0.95);}to{opacity:1;transform:none;}}
.modal{
  width:100%;max-width:680px;
  background:linear-gradient(160deg,rgba(8,14,30,0.94) 0%,rgba(4,8,20,0.97) 100%);
  border:1px solid rgba(255,255,255,0.09);
  border-top:1px solid rgba(0,229,255,0.3);
  border-radius:18px;
  box-shadow:0 40px 120px rgba(0,0,0,.9),0 0 0 1px rgba(0,0,0,0.4),0 0 100px rgba(0,229,255,0.09),0 0 60px rgba(168,85,247,0.07),0 0 40px rgba(255,0,128,0.04);
  margin:auto;animation:modalIn .25s cubic-bezier(0.4,0,0.2,1);overflow:hidden;
  backdrop-filter:saturate(200%) blur(28px);
  position:relative;
}
/* Modal HUD corner brackets */
.modal::before{
  content:'';position:absolute;inset:0;pointer-events:none;z-index:1;
  background:
    linear-gradient(var(--accent),var(--accent)) top left / 18px 1px no-repeat,
    linear-gradient(var(--accent),var(--accent)) top left / 1px 18px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) top right / 18px 1px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) top right / 1px 18px no-repeat,
    linear-gradient(var(--accent3),var(--accent3)) bottom left / 18px 1px no-repeat,
    linear-gradient(var(--accent3),var(--accent3)) bottom left / 1px 18px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) bottom right / 18px 1px no-repeat,
    linear-gradient(var(--accent2),var(--accent2)) bottom right / 1px 18px no-repeat;
  border-radius:18px;
}
/* Header banner */
.modal-banner{padding:20px 22px 16px;position:relative;overflow:hidden;border-bottom:1px solid rgba(255,255,255,0.06);}
.modal-banner::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,229,255,0.1) 0%,rgba(168,85,247,0.05) 50%,transparent 70%);pointer-events:none;}
.modal-banner-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:12px;}
.modal-ip-line{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.modal-flag{font-size:26px;line-height:1;-webkit-text-fill-color:initial;}
.modal-ip{font-family:var(--mono);font-size:1.25rem;font-weight:700;letter-spacing:-.01em;background:linear-gradient(90deg,#e0f8ff 0%,var(--accent) 50%,var(--accent2) 100%);background-size:200% 100%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:holoShimmer 4s linear infinite;filter:drop-shadow(0 0 16px rgba(0,229,255,0.5));}
.modal-cc-pill{font-size:10px;font-family:var(--mono);font-weight:700;letter-spacing:.1em;padding:3px 9px;clip-path:polygon(5px 0%,100% 0%,calc(100% - 5px) 100%,0% 100%);background:rgba(0,229,255,0.1);color:var(--accent);border:1px solid rgba(0,229,255,0.28);box-shadow:0 0 14px rgba(0,229,255,0.2);}
.modal-actions{display:flex;gap:6px;flex-wrap:wrap;flex-shrink:0;}
/* Stat strip */
.modal-stats{display:flex;gap:0;border:1px solid rgba(255,255,255,0.08);border-top:1px solid rgba(255,255,255,0.1);border-radius:10px;overflow:hidden;background:rgba(0,0,0,0.35);backdrop-filter:blur(8px);}
.modal-stat{flex:1;padding:9px 14px;border-right:1px solid rgba(255,255,255,0.06);min-width:0;}
.modal-stat:last-child{border-right:none;}
.modal-stat-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:3px;font-weight:500;}
.modal-stat-val{font-family:var(--mono);font-size:1rem;font-weight:700;font-variant-numeric:tabular-nums;color:var(--text);}
.modal-stat-val.hi{color:var(--danger);text-shadow:0 0 18px rgba(255,51,68,0.7);}
.modal-stat-val.med{color:var(--warn);text-shadow:0 0 18px rgba(255,170,0,0.7);}
.modal-stat-val.ok{color:var(--ok);text-shadow:0 0 18px rgba(0,255,136,0.7);}
/* Geo strip */
.modal-geo-strip{display:flex;gap:24px;flex-wrap:wrap;padding:14px 22px;border-bottom:1px solid rgba(255,255,255,0.05);background:rgba(0,0,0,0.25);}
.modal-geo-item{display:flex;flex-direction:column;gap:2px;min-width:0;}
.geo-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);font-weight:500;}
.geo-val{font-family:var(--mono);font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
/* Tags row */
.modal-tags{display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:10px 22px;border-bottom:1px solid rgba(255,255,255,0.05);min-height:40px;}
.modal-tags-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-weight:500;margin-right:2px;}
/* Paths section */
.modal-paths-hd{display:flex;align-items:center;justify-content:space-between;padding:12px 22px 6px;font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-weight:600;}
.modal-paths-hd span:last-child{text-align:right;}
.path-list{padding:0 10px 14px;}
.path-row{display:flex;align-items:center;gap:10px;padding:6px 12px;border-radius:7px;font-family:var(--mono);font-size:11px;transition:background var(--transition);cursor:default;margin-bottom:2px;position:relative;overflow:hidden;}
.path-row:hover{background:rgba(0,212,255,0.05);}
.path-row-bg{position:absolute;left:0;top:0;bottom:0;background:rgba(0,212,255,0.055);border-radius:7px;pointer-events:none;transition:width .4s cubic-bezier(0.4,0,0.2,1);}
.path-row-rank{font-size:9px;color:var(--muted);min-width:16px;text-align:right;flex-shrink:0;font-weight:700;}
.path-row-rank.r1{color:var(--accent);}
.path-row-text{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#cbd5e1;position:relative;}
.path-row-hits{font-size:11px;color:var(--accent);font-weight:700;flex-shrink:0;position:relative;font-variant-numeric:tabular-nums;}
.path-row-pct{font-size:9px;color:var(--muted);flex-shrink:0;min-width:32px;text-align:right;position:relative;font-variant-numeric:tabular-nums;}
/* Botnet campaigns */
.bn-hdr{display:grid;grid-template-columns:70px 1fr 40px 36px 80px 64px;gap:8px;padding:7px 12px;font-size:9px;font-family:var(--mono);color:var(--muted);border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.07em;align-items:center;}
.bn-row{display:grid;grid-template-columns:70px 1fr 40px 36px 80px 64px;gap:8px;padding:7px 12px;font-family:var(--mono);font-size:11px;border-bottom:1px solid rgba(255,255,255,0.025);align-items:center;cursor:default;transition:background var(--transition),box-shadow var(--transition);}
.bn-row:hover{background:rgba(0,212,255,0.04);box-shadow:inset 0 0 0 1px rgba(0,212,255,0.07);}
.bn-id{font-size:9px;font-weight:700;letter-spacing:.08em;color:var(--warn);}
.bn-uri{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#94a3b8;}
.bn-num{text-align:right;font-variant-numeric:tabular-nums;color:var(--text);}
.bn-flags{font-size:11px;letter-spacing:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bn-conf{display:flex;align-items:center;gap:5px;}
.bn-conf-track{flex:1;height:4px;border-radius:2px;background:rgba(255,255,255,0.06);overflow:hidden;}
.bn-conf-fill{height:100%;border-radius:2px;transition:width .6s cubic-bezier(0.4,0,0.2,1);}
.bn-conf-fill.lo {background:var(--ok);}
.bn-conf-fill.med{background:var(--warn);}
.bn-conf-fill.hi {background:var(--danger);}
.bn-conf-val{font-size:9px;font-weight:700;min-width:24px;text-align:right;flex-shrink:0;}
.bn-conf-val.lo {color:var(--ok);}
.bn-conf-val.med{color:var(--warn);}
.bn-conf-val.hi {color:var(--danger);}
/* Muted IPs */
.ban-inp{flex:1;min-width:0;padding:7px 12px;border-radius:8px;border:1px solid rgba(255,255,255,0.09);background:rgba(255,255,255,0.04);color:var(--text);font-family:var(--mono);font-size:12px;outline:none;transition:border-color var(--transition),box-shadow var(--transition);backdrop-filter:blur(8px);}
.ban-inp:focus{border-color:var(--border-bright);box-shadow:0 0 0 3px var(--accent-dim),0 0 24px rgba(0,229,255,0.12);}
.ban-actions{display:flex;gap:8px;margin-bottom:10px;align-items:stretch;}
.ban-row{display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid rgba(255,255,255,0.025);font-family:var(--mono);font-size:11px;}
.ban-row .kip{flex:1;overflow:hidden;text-overflow:ellipsis;color:#cbd5e1;}
.ban-row .cnt{color:var(--warn);flex-shrink:0;}
footer{padding:8px 24px;color:var(--muted);font-size:11px;border-top:1px solid rgba(255,255,255,0.05);font-family:var(--mono);position:relative;z-index:1;background:rgba(1,3,10,0.8);backdrop-filter:blur(16px);box-shadow:0 -1px 0 rgba(0,229,255,0.07);}
kbd{font-family:var(--mono);font-size:10px;padding:2px 5px;border:1px solid var(--border);border-radius:4px;background:rgba(255,255,255,0.05);}
</style>
</head>
<body>

<div id="postureStrip"></div>

<header>
  <div class="brand">
    <div id="liveDot" class="live-dot"></div>
    <div>
      <div class="brand-logo">SENTINEL</div>
      <div class="brand-sub">Live Caddy access telemetry &mdash; <span id="updatedAgo">connecting...</span></div>
    </div>
  </div>
  <div class="posture-area">
    <span class="badge frozen" id="freezeBadge" style="display:none">FROZEN</span>
    <span class="badge" id="authBadge" style="display:none" title="HTTP Basic Auth enabled">AUTH</span>
    <div class="defcon-wrap">
      <div class="defcon-blocks">
        <div class="defcon-block" id="db0"></div>
        <div class="defcon-block" id="db1"></div>
        <div class="defcon-block" id="db2"></div>
        <div class="defcon-block" id="db3"></div>
        <div class="defcon-block" id="db4"></div>
      </div>
      <div class="defcon-label" id="defconLabel">POSTURE: &mdash;</div>
    </div>
  </div>
</header>

<div class="toolbar">
  <input type="search" id="q" placeholder="Filter lists..." autocomplete="off"/>
  <div class="toolbar-sep"></div>
  <button type="button" class="toolbtn" id="btnPause">Pause</button>
  <span style="color:var(--muted);font-size:11px;font-family:var(--mono)">Poll:</span>
  <div class="poll-seg">
    <button type="button" class="toolbtn poll-opt" data-ms="1000">1s</button>
    <button type="button" class="toolbtn poll-opt on" data-ms="1500">1.5s</button>
    <button type="button" class="toolbtn poll-opt" data-ms="3000">3s</button>
    <button type="button" class="toolbtn poll-opt" data-ms="5000">5s</button>
  </div>
  <div class="toolbar-sep"></div>
  <span style="color:var(--muted);font-size:11px;font-family:var(--mono)">History:</span>
  <div class="poll-seg">
    <button type="button" class="toolbtn hist-range on" data-sec="86400">24h</button>
    <button type="button" class="toolbtn hist-range" data-sec="604800">7d</button>
    <button type="button" class="toolbtn hist-range" data-sec="2592000">30d</button>
  </div>
  <select id="histDaySelect" class="hist-day-select" title="Select a specific saved UTC day">
    <option value="">Range mode</option>
  </select>
  <button type="button" class="toolbtn" id="btnHistMode">History chart</button>
  <div class="toolbar-sep"></div>
  <button type="button" class="toolbtn" id="btnExport">Export JSON</button>
  <div class="toolbar-sep"></div>
  <button type="button" class="toolbtn danger" id="btnClearFocus" style="display:none">Clear focus</button>
  <button type="button" class="toolbtn danger" id="btnReset">Reset</button>
  <span style="color:var(--muted);font-size:11px;font-family:var(--mono);margin-left:4px"><kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> close</span>
</div>

<div class="kpi-row">
  <div class="kpi" id="kpi-rps">
    <div class="kpi-hd"><div class="label">Req / sec</div><div class="delta nc" id="delta-rps"></div></div>
    <div class="val" id="rps">0</div>
  </div>
  <div class="kpi" id="kpi-peak">
    <div class="kpi-hd"><div class="label">Peak RPS</div><div class="delta nc" id="delta-peak"></div></div>
    <div class="val" id="peak">0</div>
  </div>
  <div class="kpi ok" id="kpi-total">
    <div class="kpi-hd"><div class="label">Total events</div></div>
    <div class="val" id="total">0</div>
  </div>
  <div class="kpi" id="kpi-uniq">
    <div class="kpi-hd"><div class="label">Unique IPs</div><div class="delta nc" id="delta-uniq"></div></div>
    <div class="val" id="uniq">0</div>
  </div>
  <div class="kpi" id="kpi-errs">
    <div class="kpi-hd"><div class="label">4xx / 5xx</div></div>
    <div class="val" id="errs">0 / 0</div>
  </div>
  <div class="kpi" id="kpi-errpct">
    <div class="kpi-hd"><div class="label">Error rate</div><div class="delta nc" id="delta-errpct"></div></div>
    <div class="val" id="errpct">0%</div>
  </div>
  <div class="kpi" id="kpi-atk">
    <div class="kpi-hd"><div class="label">Susp / sec</div><div class="delta nc" id="delta-atk"></div></div>
    <div class="val" id="atk">0</div>
  </div>
  <div class="kpi ok" id="kpi-muted">
    <div class="kpi-hd"><div class="label">Muted (excl.)</div></div>
    <div class="val" id="mutedTotal">0</div>
  </div>
  <div class="kpi ok" id="kpi-bytes">
    <div class="kpi-hd"><div class="label">Data served</div></div>
    <div class="val" id="bytesServed">0 B</div>
  </div>
</div>

<div class="layout" id="layout">
  <div>
    <div class="card">
      <h2>Throughput &amp; suspicious activity <span class="hint">click any IP for drill-down</span></h2>
      <div class="charts-dual">
        <div class="chart-wrap"><canvas id="comboChart"></canvas></div>
        <div class="chart-wrap"><canvas id="statusDonut"></canvas></div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
      <div class="card"><h2>Top source IPs <span class="hint" id="focusLbl"></span></h2><div class="body" id="ips"></div></div>
      <div class="card"><h2>Hosts (virtual)</h2><div class="body" id="domains"></div></div>
      <div class="card"><h2>Requested paths</h2><div class="body" id="paths"></div></div>
      <div class="card"><h2>Referers</h2><div class="body" id="refs"></div></div>
      <div class="card"><h2>ASN / org</h2><div class="body" id="asn"></div></div>
    </div>
    <div class="card">
      <h2>Botnet campaigns <span class="hint">distributed coordinated attacks &mdash; 5 min window</span></h2>
      <div class="body" style="max-height:none;padding:0">
        <div class="bn-hdr">
          <span>Campaign</span><span>Trigger URI</span>
          <span style="text-align:right">IPs</span>
          <span style="text-align:right">ASNs</span>
          <span>Countries</span>
          <span style="text-align:right">Confidence</span>
        </div>
        <div id="botnets"></div>
      </div>
    </div>
    <div class="card">
      <h2>Historical telemetry <span class="hint">aggregated and event drilldown</span></h2>
      <div class="body" style="max-height:none">
        <div id="historyMeta" style="margin-bottom:8px;color:var(--muted);font-family:var(--mono);font-size:11px">Loading history...</div>
        <div class="hist-table-wrap">
          <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px">
            <thead>
              <tr style="position:sticky;top:0;background:rgba(8,12,22,0.96)">
                <th style="text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)">Time (UTC)</th>
                <th style="text-align:right;padding:6px 8px;border-bottom:1px solid var(--border)">IP</th>
                <th style="text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)">Host</th>
                <th style="text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)">Path</th>
                <th style="text-align:right;padding:6px 8px;border-bottom:1px solid var(--border)">Status</th>
                <th style="text-align:right;padding:6px 8px;border-bottom:1px solid var(--border)">Score</th>
              </tr>
            </thead>
            <tbody id="historyRows"></tbody>
          </table>
        </div>
        <div style="display:flex;gap:8px;margin-top:8px;justify-content:flex-end">
          <button type="button" class="toolbtn" id="btnHistPrev">Prev</button>
          <button type="button" class="toolbtn" id="btnHistNext">Next</button>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>Origin countries &mdash; world map</h2>
      <div id="worldMapWrap"><div id="worldMap" style="width:100%;height:100%"></div><div id="mapHoverTip" class="map-hover-tip"></div></div>
      <div id="mapHoverReadout" class="map-hover-readout">Hover country: &mdash;</div>
      <div class="map-legend">
        <span class="map-legend-item"><span class="map-legend-swatch low"></span>Low</span>
        <span class="map-legend-item"><span class="map-legend-swatch med"></span>Medium</span>
        <span class="map-legend-item"><span class="map-legend-swatch high"></span>High</span>
      </div>
    </div>
  </div>
  <div class="sidebar" id="sidebar">
    <div class="sb-toggle-row">
      <button type="button" class="toolbtn sb-toggle" id="sbToggle" title="Collapse sidebar">&#9664;</button>
    </div>
    <div class="card">
      <h2>Alert feed <span class="hint">click row = focus + drill-down</span></h2>
      <div class="body" style="max-height:370px" id="alerts"></div>
    </div>
    <div class="card">
      <h2>Top scored sources (threat board)</h2>
      <div class="body" style="max-height:none;padding:0">
        <div class="th-grid">
          <span>#</span><span>Source</span><span style="text-align:right">Score</span>
          <span style="text-align:right">Hits</span><span style="text-align:center">CC</span>
        </div>
        <div id="threats"></div>
      </div>
    </div>
    <div class="card"><h2>HTTP status mix</h2><div class="body" id="status"></div></div>
    <div class="card">
      <h2>Muted IPs <span class="hint" id="iptablesHintShort"></span></h2>
      <div class="body" style="max-height:none">
        <p id="iptablesHintP" style="margin:0 0 10px;font-size:11px;color:var(--muted);line-height:1.5"></p>
        <div class="ban-actions">
          <input type="text" id="banIp" class="ban-inp" placeholder="IPv4 / IPv6" autocomplete="off"/>
          <button type="button" class="toolbtn danger" id="btnBan">Mute</button>
        </div>
        <div id="banList"></div>
      </div>
    </div>
    <div class="card" id="sourcesCard">
      <h2>Log sources <span class="hint">file tails + remote ingest</span></h2>
      <div class="body" style="max-height:none;padding:0" id="sourcesList"></div>
    </div>
    <div class="card" id="auditCard">
      <h2 style="display:flex;align-items:center;justify-content:space-between">
        <span>Analyst audit log <span class="hint">mute / unban / reset actions</span></span>
        <button type="button" class="toolbtn danger" id="btnClearAudit" style="font-size:9px;padding:3px 9px;margin:-2px 0">Clear log</button>
      </h2>
      <div class="body" style="max-height:220px;padding:0" id="auditList"></div>
    </div>
  </div>
</div>
<footer id="foot">Server time &mdash;</footer>

<div class="modal-backdrop" id="modalBg" aria-hidden="true">
  <div class="modal" role="dialog" aria-labelledby="modalIpText">
    <div class="modal-banner">
      <div class="modal-banner-top">
        <div class="modal-ip-line">
          <span class="modal-flag" id="modalFlag"></span>
          <span class="modal-ip" id="modalIpText">&mdash;</span>
          <span class="modal-cc-pill" id="modalCcPill" style="display:none"></span>
        </div>
        <div class="modal-actions">
          <button type="button" class="toolbtn" id="modalCopy">Copy IP</button>
          <button type="button" class="toolbtn" id="modalExtLink">Lookup &#8599;</button>
          <button type="button" class="toolbtn danger" id="modalBan">Mute</button>
          <button type="button" class="toolbtn" id="modalClose">&#10005;</button>
        </div>
      </div>
      <div class="modal-stats" id="modalStats">
        <div class="modal-stat"><div class="modal-stat-lbl">Total hits</div><div class="modal-stat-val" id="mStatHits">&mdash;</div></div>
        <div class="modal-stat"><div class="modal-stat-lbl">Threat score</div><div class="modal-stat-val" id="mStatScore">&mdash;</div></div>
        <div class="modal-stat"><div class="modal-stat-lbl">Unique paths</div><div class="modal-stat-val" id="mStatPaths">&mdash;</div></div>
        <div class="modal-stat"><div class="modal-stat-lbl">Classification</div><div class="modal-stat-val" id="mStatClass">&mdash;</div></div>
        <div class="modal-stat" id="mStatEnrichWrap" style="display:none"><div class="modal-stat-lbl">Shodan</div><div class="modal-stat-val" id="mStatEnrich">&mdash;</div></div>
        <div class="modal-stat" id="mStatIpinfoWrap" style="display:none"><div class="modal-stat-lbl">IPInfo</div><div class="modal-stat-val" id="mStatIpinfo">&mdash;</div></div>
        <div class="modal-stat" id="mStatAbuseWrap" style="display:none"><div class="modal-stat-lbl">AbuseIPDB</div><div class="modal-stat-val" id="mStatAbuse">&mdash;</div></div>
      </div>
    </div>
    <div class="modal-geo-strip" id="modalGeoStrip" style="display:none"></div>
    <div class="modal-tags" id="modalTagsRow" style="display:none">
      <span class="modal-tags-lbl">Tags</span>
    </div>
    <div id="modalPathsWrap">
      <div class="modal-paths-hd"><span>Requested paths</span><span>Hits &nbsp; %</span></div>
      <div class="path-list" id="modalPaths"></div>
    </div>
  </div>
</div>

<script>
// ── State ──
const MAX=60;
let rpsHist=[],atkHist=[];
let lastPayload=null;
let focusIp='';
let pollMs=1500;
let pollTimer=null;
let paused=false;
let lastLoadMs=0;
let prevKpi={rps:0,peak:0,uniq:0,errpct:0,atk:0};
let knownAlertCount=0;
let newAlertsSinceBlur=0;
let isPageVisible=true;
let sidebarOpen=true;
let worldMap=null;
let countryHitsMap={};
let mapHoverCode='';
let mapHoverPos={x:0,y:0};
let mapHoverPoll=null;
let seenAlertKeys=new Set();
let modalIp='';
let historyRangeSec=2592000;
let historyMode=false;
let historyPoints=[];
let historyPage=1;
let historyTotal=0;
let historySelectedDay='';
let historyDaysLoaded=false;

/* Tab visibility for alert count */
document.addEventListener('visibilitychange',function(){
  if(!document.hidden){
    isPageVisible=true;
    newAlertsSinceBlur=0;
    document.title='Sentinel | SOC';
  }else{
    isPageVisible=false;
  }
});

// ── Live ticker ──
setInterval(function(){
  if(!lastLoadMs) return;
  var s=Math.floor((Date.now()-lastLoadMs)/1000);
  var el=document.getElementById('updatedAgo');
  var dot=document.getElementById('liveDot');
  if(s<=2){el.textContent='live';el.style.color='var(--ok)';dot.className='live-dot';}
  else if(s<=8){el.textContent=s+'s ago';el.style.color='var(--ok)';dot.className='live-dot';}
  else{el.textContent=s+'s ago';el.style.color='var(--warn)';dot.className='live-dot stale';}
},1000);

// ── Gradient helper ──
function makeGrad(ctx,chart,colorTop,colorBot){
  var ca=chart.chartArea;
  if(!ca) return colorTop;
  var g=ctx.createLinearGradient(0,ca.top,0,ca.bottom);
  g.addColorStop(0,colorTop); g.addColorStop(1,colorBot); return g;
}

// ── Combo chart ──
var hasChartJs=(typeof Chart==='function');
if(!hasChartJs){
  var comboCanvas=document.getElementById('comboChart');
  if(comboCanvas) comboCanvas.title='Chart.js unavailable (blocked by browser/privacy settings)';
  var donutCanvas=document.getElementById('statusDonut');
  if(donutCanvas) donutCanvas.title='Chart.js unavailable (blocked by browser/privacy settings)';
}
const comboChart=hasChartJs?new Chart(document.getElementById('comboChart'),{
  type:'line',
  data:{labels:[],datasets:[
    {label:'RPS',data:[],borderColor:'#00d4ff',borderWidth:1.5,
     backgroundColor:function(ctx){return makeGrad(ctx.chart.ctx,ctx.chart,'rgba(0,212,255,0.28)','rgba(0,212,255,0)');},
     fill:true,tension:0.4,pointRadius:0,yAxisID:'y'},
    {label:'Susp/s',data:[],borderColor:'#f87171',borderWidth:1.5,
     backgroundColor:function(ctx){return makeGrad(ctx.chart.ctx,ctx.chart,'rgba(248,113,113,0.2)','rgba(248,113,113,0)');},
     fill:true,tension:0.4,pointRadius:0,yAxisID:'y2'}
  ]},
  options:{responsive:true,maintainAspectRatio:false,
    interaction:{mode:'index',intersect:false},
    plugins:{
      legend:{display:true,position:'top',align:'end',
        labels:{color:'#64748b',boxWidth:10,font:{size:9,family:"'JetBrains Mono',monospace"},padding:8}},
      tooltip:{backgroundColor:'rgba(10,16,28,0.95)',borderColor:'rgba(0,212,255,0.2)',borderWidth:1,
        titleColor:'#94a3b8',bodyColor:'#e2e8f0',padding:8,cornerRadius:7,
        titleFont:{family:"'JetBrains Mono',monospace",size:10},
        bodyFont:{family:"'JetBrains Mono',monospace",size:11}}},
    scales:{
      x:{display:false,grid:{display:false}},
      y:{beginAtZero:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#4a5568',font:{size:9}},
         title:{display:true,text:'RPS',color:'#4a5568',font:{size:9}}},
      y2:{beginAtZero:true,position:'right',grid:{display:false},ticks:{color:'#f87171',font:{size:9}},
          title:{display:true,text:'Susp/s',color:'#f87171',font:{size:9}}}}}
}):{data:{labels:[],datasets:[{data:[]},{data:[]}]},update:function(){}};

const statusDonut=hasChartJs?new Chart(document.getElementById('statusDonut'),{
  type:'doughnut',
  data:{labels:['2xx','3xx','4xx','5xx','other'],
    datasets:[{data:[0,0,0,0,0],
      backgroundColor:['#22c55e','#00d4ff','#f59e0b','#ef4444','#4a5568'],
      borderWidth:0,spacing:2,borderRadius:3}]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{
      legend:{position:'bottom',labels:{color:'#64748b',boxWidth:9,font:{size:9},padding:6}},
      tooltip:{backgroundColor:'rgba(10,16,28,0.95)',borderColor:'rgba(0,212,255,0.2)',borderWidth:1,
        titleColor:'#94a3b8',bodyColor:'#e2e8f0',padding:8,cornerRadius:7,
        titleFont:{family:"'JetBrains Mono',monospace",size:10},
        bodyFont:{family:"'JetBrains Mono',monospace",size:11},
        callbacks:{label:function(c){
          var sum=c.dataset.data.reduce(function(a,b){return a+b;},0)||1;
          return c.label+': '+c.raw+' ('+((c.raw/sum)*100).toFixed(1)+'%)';
        }}}}}
}):{data:{datasets:[{data:[0,0,0,0,0]}]},update:function(){}};

// ── World map ──
function initWorldMap(){
  if(worldMap||typeof jsVectorMap==='undefined') return;
  function regionCodeFromTarget(t){
    if(!t) return '';
    var el=t.closest ? t.closest('path, g, [data-code], [data-region], [id]') : t;
    if(!el) return '';
    var direct=(el.getAttribute && (el.getAttribute('data-code') || el.getAttribute('data-region'))) || '';
    direct=String(direct).trim().toUpperCase();
    if(/^[A-Z]{2}$/.test(direct)) return direct;
    if(el.dataset){
      var ds=(el.dataset.code || el.dataset.region || '').toString().trim().toUpperCase();
      if(/^[A-Z]{2}$/.test(ds)) return ds;
    }
    var attrs=['data-code','data-region','data-name','name','id'];
    for(var i=0;i<attrs.length;i++){
      var raw=(el.getAttribute && el.getAttribute(attrs[i])) || '';
      var m=String(raw).toUpperCase().match(/\b[A-Z]{2}\b/);
      if(m) return m[0];
    }
    return '';
  }
  function mapTooltipMessage(code){
    var cc=String(code||'').toUpperCase();
    if(!cc || cc==='UNDEFINED') cc='??';
    var hits=countryHitsMap[cc]||0;
    return cc+' \u2014 '+hits+' hits';
  }
  function applyMapTooltip(tooltip,msg){
    try{
      if(!tooltip) return;
      if(typeof tooltip.html==='function'){
        try{ tooltip.html(msg,true); }catch(_e1){ try{ tooltip.html(msg); }catch(_e2){} }
      }
      if(typeof tooltip.text==='function'){
        try{ tooltip.text(msg,true); }catch(_e3){ try{ tooltip.text(msg); }catch(_e4){} }
      }
      if(typeof tooltip.setText==='function'){
        try{ tooltip.setText(msg); }catch(_e5){}
      }
      var candidates=[
        tooltip,
        tooltip.element,
        tooltip._tooltip,
        tooltip.selector,
        tooltip.container,
        tooltip.node,
        tooltip[0]
      ];
      candidates.forEach(function(el){
        try{
          if(!el) return;
          if(typeof el.innerHTML!=='undefined') el.innerHTML=msg;
          if(typeof el.textContent!=='undefined') el.textContent=msg;
        }catch(_e6){}
      });
    }catch(_e){}
  }
  function mapTip(msg,x,y){
    var tip=document.getElementById('mapHoverTip');
    var readout=document.getElementById('mapHoverReadout');
    if(!tip) return;
    tip.textContent=msg;
    tip.style.display='block';
    tip.style.left=Math.max(6,(x||0))+'px';
    tip.style.top=Math.max(6,(y||0))+'px';
    if(readout) readout.textContent='Hover country: '+msg;
  }
  function hideMapTip(){
    var tip=document.getElementById('mapHoverTip');
    var readout=document.getElementById('mapHoverReadout');
    if(tip) tip.style.display='none';
    if(readout) readout.textContent='Hover country: \u2014';
  }
  function hoveredRegionCode(mapEl){
    if(!mapEl) return '';
    var el=mapEl.querySelector('.jvm-region:hover,[data-code]:hover,[data-region]:hover,path:hover');
    return regionCodeFromTarget(el);
  }
  try{
    worldMap=new jsVectorMap({
      selector:'#worldMap',map:'world',
      backgroundColor:'transparent',zoomOnScroll:false,
      regionTooltip:false,
      regionStyle:{
        initial:{fill:'#1a2e47',stroke:'#0a1421',strokeWidth:0.45,fillOpacity:0.95},
        hover:{fill:'#2c4f74',cursor:'pointer'}
      },
      onRegionTooltipShow:function(e,tooltip,code){ applyMapTooltip(tooltip,mapTooltipMessage(code)); },
      onRegionTipShow:function(e,tooltip,code){ applyMapTooltip(tooltip,mapTooltipMessage(code)); },
      onRegionOver:function(e,code){
        mapHoverCode=String(code||'').toUpperCase();
        mapTip(mapTooltipMessage(mapHoverCode),e.clientX||0,e.clientY||0);
      },
      onRegionOut:function(){
        mapHoverCode='';
        hideMapTip();
      },
      series:{regions:[{
        attribute:'fill',
        scale:{
          1:'#1e3a8a', /* low */
          2:'#0ea5e9', /* medium */
          3:'#06b6d4', /* high */
          4:'#67e8f9'  /* very high */
        },
        normalizeFunction:'linear',
        values:{}
      }]}
    });
    var mapEl=document.getElementById('worldMapWrap');
    if(mapEl){
      if(mapHoverPoll) clearInterval(mapHoverPoll);
      mapHoverPoll=setInterval(function(){
        var cc=hoveredRegionCode(mapEl);
        if(!cc){
          if(!mapHoverCode) return;
          mapHoverCode='';
          hideMapTip();
          return;
        }
        mapHoverCode=cc;
        mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x||0,mapHoverPos.y||0);
      },120);
      mapEl.addEventListener('mousemove',function(e){
        mapHoverPos.x=e.clientX||0;
        mapHoverPos.y=e.clientY||0;
        var ccByHover=hoveredRegionCode(mapEl);
        if(ccByHover){
          mapHoverCode=ccByHover;
          try{
            var p=e.target && e.target.closest ? e.target.closest('.jvm-region,path') : null;
            if(p && p.setAttribute) p.setAttribute('title',mapTooltipMessage(mapHoverCode));
          }catch(_e0){}
          mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
          return;
        }
        var cc=regionCodeFromTarget(e.target);
        if(cc){
          mapHoverCode=cc;
          try{
            var p2=e.target && e.target.closest ? e.target.closest('.jvm-region,path') : null;
            if(p2 && p2.setAttribute) p2.setAttribute('title',mapTooltipMessage(mapHoverCode));
          }catch(_e1){}
          mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
          return;
        }
        if(!mapHoverCode) return;
        mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
      });
      mapEl.addEventListener('mouseleave',function(){ mapHoverCode=''; hideMapTip(); });
      mapEl.addEventListener('mouseover',function(e){
        var cc=regionCodeFromTarget(e.target);
        if(!cc) return;
        mapHoverCode=cc;
        mapHoverPos.x=e.clientX||0;
        mapHoverPos.y=e.clientY||0;
        mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
      });
      mapEl.addEventListener('mouseout',function(e){
        var toEl=e.relatedTarget;
        if(toEl && mapEl.contains(toEl)) return;
        mapHoverCode='';
        hideMapTip();
      });
    }
  }catch(e){
    document.getElementById('worldMapWrap').innerHTML='<div style="color:var(--muted);text-align:center;padding:80px 0;font-family:var(--mono);font-size:12px">Map unavailable (CDN)</div>';
  }
}
function updateWorldMap(countries){
  if(!worldMap) return;
  try{
    var vals={};
    countryHitsMap={};
    (countries||[]).forEach(function(p){
      var cc=String(p[0]||'').toUpperCase();
      var n=Math.max(0,+p[1]||0);
      if(!cc||cc.length!==2||n<=0) return;
      countryHitsMap[cc]=n;
      var bucket=1;
      if(n>=1000) bucket=4;
      else if(n>=200) bucket=3;
      else if(n>=25) bucket=2;
      vals[cc]=bucket;
    });
    worldMap.series.regions[0].setValues(vals);
  }catch(e){}
}

function historyRangeBounds(){
  if(historySelectedDay){
    var start=Date.parse(historySelectedDay+'T00:00:00Z');
    if(!isNaN(start)){
      var from=Math.floor(start/1000);
      return {from:from,to:from+86400-1};
    }
  }
  var to=Math.floor(Date.now()/1000);
  return {from:Math.max(0,to-historyRangeSec),to:to};
}

function applyHistoryChart(points){
  historyPoints=points||[];
  if(!historyMode||!historyPoints.length) return;
  var labels=historyPoints.map(function(p){
    try{return new Date((p.ts||0)*1000).toISOString().slice(11,16);}catch(e){return '';}
  });
  comboChart.data.labels=labels;
  comboChart.data.datasets[0].data=historyPoints.map(function(p){return p.total||0;});
  comboChart.data.datasets[1].data=historyPoints.map(function(p){return p.attacks||0;});
  comboChart.update('none');
}

async function loadHistorySeries(){
  var b=historyRangeBounds();
  var bucket=historySelectedDay?'minute':(historyRangeSec>172800?'hour':'minute');
  try{
    var q='/api/history/series?from='+b.from+'&to='+b.to+'&bucket='+bucket;
    if(historySelectedDay) q+='&day='+encodeURIComponent(historySelectedDay);
    var r=await fetch(q,{credentials:'same-origin'});
    var j=await r.json();
    if(!r.ok||!j.ok) return;
    historyPoints=j.points||[];
    if(historyMode) applyHistoryChart(historyPoints);
    var sumT=0,sumA=0,sum4=0,sum5=0;
    historyPoints.forEach(function(p){sumT+=(p.total||0);sumA+=(p.attacks||0);sum4+=(p.client_errors||0);sum5+=(p.server_errors||0);});
    var modeLabel=historySelectedDay?('Day '+historySelectedDay):('Range '+(historyRangeSec/86400).toFixed(0)+'d');
    document.getElementById('historyMeta').innerText=modeLabel+' | points '+historyPoints.length+' | total '+sumT+' | suspicious '+sumA+' | 4xx '+sum4+' | 5xx '+sum5;
  }catch(e){}
}

function renderHistoryEvents(rows){
  var el=document.getElementById('historyRows');
  var arr=rows||[];
  if(!arr.length){
    el.innerHTML='<tr><td colspan="6" style="padding:10px;color:var(--muted);text-align:center">No historical events in selected range</td></tr>';
    return;
  }
  el.innerHTML=arr.map(function(r){
    return '<tr>'
      +'<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05)">'+escapeHtml(r.ts||'')+'</td>'
      +'<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);text-align:right"><span class="hist-ip-link" data-ip="'+escapeAttr(r.ip||'')+'" style="color:var(--accent);cursor:pointer;font-weight:700" title="Click to drill down">'+escapeHtml(r.ip||'')+'</span></td>'
      +'<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05)" title="'+escapeAttr(r.host||'')+'">'+escapeHtml(r.host||'')+'</td>'
      +'<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05)" title="'+escapeAttr(r.path||'')+'">'+escapeHtml(r.path||'')+'</td>'
      +'<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);text-align:right">'+(r.status||0)+'</td>'
      +'<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);text-align:right">'+(r.score||0)+'</td>'
      +'</tr>';
  }).join('');
}

async function loadHistoryEvents(){
  var b=historyRangeBounds();
  try{
    var q='/api/history/events?from='+b.from+'&to='+b.to+'&page='+historyPage+'&page_size=50';
    if(historySelectedDay) q+='&day='+encodeURIComponent(historySelectedDay);
    if(focusIp) q+='&ip='+encodeURIComponent(focusIp);
    var r=await fetch(q,{credentials:'same-origin'});
    var j=await r.json();
    if(!r.ok||!j.ok){renderHistoryEvents([]);return;}
    historyTotal=j.total||0;
    renderHistoryEvents(j.rows||[]);
  }catch(e){
    renderHistoryEvents([]);
  }
}

async function refreshHistory(){
  if(!historyDaysLoaded) await loadHistoryDays();
  await loadHistorySeries();
  await loadHistoryEvents();
}

async function loadHistoryDays(){
  try{
    var r=await fetch('/api/history/days',{credentials:'same-origin'});
    var j=await r.json();
    if(!r.ok||!j.ok) return;
    var sel=document.getElementById('histDaySelect');
    var keep=historySelectedDay;
    sel.innerHTML='<option value="">Range mode</option>';
    (j.days||[]).forEach(function(d){
      var o=document.createElement('option');
      o.value=d.day;
      o.textContent=d.day+'  ('+(d.total||0)+' req)';
      sel.appendChild(o);
    });
    if(keep && (j.days||[]).some(function(d){return d.day===keep;})){
      sel.value=keep;
      historySelectedDay=keep;
    }else{
      historySelectedDay='';
      sel.value='';
    }
    historyDaysLoaded=true;
  }catch(e){}
}

/* Helpers */
function fmtBytes(n){
  if(n===undefined||n===null) return '0 B';
  if(n<1024) return n+' B';
  if(n<1048576) return (n/1024).toFixed(1)+' KB';
  if(n<1073741824) return (n/1048576).toFixed(1)+' MB';
  if(n<1099511627776) return (n/1073741824).toFixed(2)+' GB';
  return (n/1099511627776).toFixed(2)+' TB';
}
function escapeHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escapeAttr(s){ return escapeHtml(s).replace(/'/g,'&#39;'); }

function timeAgo(ts){
  if(!ts) return '';
  const d=Date.now()-new Date(ts).getTime();
  if(d<5000) return 'just now';
  if(d<60000) return Math.floor(d/1000)+'s ago';
  if(d<3600000) return Math.floor(d/60000)+'m ago';
  return Math.floor(d/3600000)+'h ago';
}

function ccFlag(cc){
  if(!cc||cc.length!==2) return '';
  try{
    return cc.toUpperCase().split('').map(function(c){
      return String.fromCodePoint(0x1F1E6+c.charCodeAt(0)-65);
    }).join('');
  }catch(e){ return ''; }
}

function scorePillCls(n){ if(n>=10) return 'hi'; if(n>=5) return 'med'; return 'lo'; }

function filterPairs(pairs,q){
  var a=pairs||[];
  if(q&&q.trim()){ var t=q.toLowerCase(); a=a.filter(function(p){ return String(p[0]).toLowerCase().includes(t); }); }
  return a;
}

function listRow(rank,key,val,barPct,pct,opts){
  /* opts: {danger,warn,ok,ipClick,tags,bgCls,keyWrap} */
  opts=opts||{};
  var hl=(focusIp&&String(key)===focusIp)?' hl-focus':'';
  var ipCls=opts.ipClick?' row-ip':'';
  var dataIp=opts.ipClick?' data-ip="'+escapeAttr(key)+'"':'';
  var valCls=opts.danger?' danger':opts.warn?' warn':opts.ok?' ok':'';
  var bgCls=opts.bgCls?(' '+opts.bgCls):'';
  var rankCls=rank===1?' r1':'';
  var keyWrap=opts.keyWrap?' wrap':'';
  var pills=(opts.ipClick&&opts.tags&&opts.tags.length)
    ? ' '+opts.tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join('')
    : '';
  var pctHtml=pct!=null?('<span class="list-pct">'+pct+'</span>'):'';
  return '<div class="list-row'+hl+ipCls+'"'+dataIp+'>'
    +'<div class="list-row-bg'+bgCls+'" style="width:'+barPct+'%"></div>'
    +'<span class="list-rank'+rankCls+'">'+rank+'</span>'
    +'<span class="list-key'+keyWrap+'" title="'+escapeAttr(key)+'">'+escapeHtml(key)+pills+'</span>'
    +'<span class="list-val'+valCls+'">'+val+'</span>'
    +pctHtml
    +'</div>';
}

// ── DEFCON posture ──
var DEFCON={'NORMAL':{blocks:1,color:'#22c55e'},'ELEVATED':{blocks:2,color:'#ca8a04'},'HIGH':{blocks:3,color:'#ea580c'},'CRITICAL':{blocks:5,color:'#dc2626'}};
function updateDefcon(level,color){
  var def=DEFCON[level]||DEFCON['NORMAL'];
  var cnt=def.blocks,col=color||def.color,isCrit=(level==='CRITICAL');
  for(var i=0;i<5;i++){
    var b=document.getElementById('db'+i); if(!b) continue;
    if(i<cnt){b.className='defcon-block lit'+(isCrit?' blk-pulse':'');b.style.background=col;b.style.boxShadow='0 0 10px '+col+'80';}
    else{b.className='defcon-block';b.style.background='';b.style.boxShadow='';}
  }
  var lbl=document.getElementById('defconLabel');
  if(lbl){lbl.textContent='POSTURE: '+(level||'-');lbl.style.color=col;}
  var strip=document.getElementById('postureStrip');
  if(strip){strip.style.background=col;strip.style.boxShadow='0 0 16px '+col;}
}

/* KPI helpers */
function kpiLevel(id,val,warnT,dangerT){
  var el=document.getElementById(id);
  if(!el) return;
  el.classList.remove('ok','warn','danger');
  if(dangerT!=null&&val>=dangerT) el.classList.add('danger');
  else if(warnT!=null&&val>=warnT) el.classList.add('warn');
  else el.classList.add('ok');
}
function kpiDelta(id,cur,prev){
  var el=document.getElementById(id);
  if(!el) return;
  if(prev==null){ el.textContent=''; el.className='delta nc'; return; }
  var diff=cur-prev;
  if(diff===0||prev===0){ el.textContent='\u2014'; el.className='delta nc'; return; }
  var pct=Math.abs(Math.round((diff/Math.max(prev,1))*100));
  el.textContent=(diff>0?'\u2191':'\u2193')+pct+'%';
  el.className='delta '+(diff>0?'up':'down');
}

/* Render lists */
function renderIpList(el,pairs,tagMap){
  var q=document.getElementById('q').value;
  var pf=filterPairs(pairs,q);
  if(!pf.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No matches</span></div>';return;}
  var maxV=pf[0][1]||1;
  var total=pf.reduce(function(s,p){return s+(p[1]||0);},0)||1;
  var html='';
  pf.forEach(function(p,i){
    var tags=(tagMap&&tagMap[p[0]])||[];
    var barPct=Math.round(((p[1]||0)/maxV)*100);
    var pct=(((p[1]||0)/total)*100).toFixed(1)+'%';
    html+=listRow(i+1,p[0],p[1],barPct,pct,{ipClick:true,tags:tags});
  });
  el.innerHTML=html;
}
function renderList(el,data,flag,ipCol){
  var q=document.getElementById('q').value;
  var pairs=filterPairs(data,q);
  if(!pairs.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No matches</span></div>';return;}
  var maxV=pairs[0][1]||1;
  var total=pairs.reduce(function(s,p){return s+(p[1]||0);},0)||1;
  var html='';
  pairs.forEach(function(p,i){
    var barPct=Math.round(((p[1]||0)/maxV)*100);
    var pct=(((p[1]||0)/total)*100).toFixed(1)+'%';
    var isDanger=flag&&p[1]>100;
    html+=listRow(i+1,p[0],p[1],barPct,pct,{danger:isDanger,ipClick:ipCol,bgCls:isDanger?'danger':''});
  });
  el.innerHTML=html;
}
function renderStatus(el,obj){
  var q=document.getElementById('q').value;
  var keys=Object.keys(obj||{}).sort(function(a,b){ return obj[b]-obj[a]; });
  if(q&&q.trim()){ var t=q.toLowerCase(); keys=keys.filter(function(k){ return String(k).toLowerCase().includes(t); }); }
  keys=keys.slice(0,20);
  if(!keys.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No matches</span></div>';return;}
  var maxV=Math.max.apply(null,keys.map(function(k){return obj[k]||0;}).concat([1]));
  var total=keys.reduce(function(s,k){return s+(obj[k]||0);},0)||1;
  var html='';
  keys.forEach(function(k,i){
    var n=obj[k], code=parseInt(k,10);
    var is5xx=code>=500, is4xx=code>=400&&code<500, is3xx=code>=300&&code<400, is2xx=code>=200&&code<300;
    var valCls=is5xx?'danger':is4xx?'warn':is2xx?'ok':'';
    var bgCls=is5xx?'danger':'';
    var barPct=Math.round((n/maxV)*100);
    var pct=((n/total)*100).toFixed(1)+'%';
    html+=listRow(i+1,k+'',n,barPct,pct,{danger:is5xx,warn:is4xx,ok:is2xx,bgCls:bgCls});
  });
  el.innerHTML=html;
}

function renderAlerts(el,alerts){
  var q=document.getElementById('q').value;
  var arr=alerts||[];
  if(focusIp) arr=arr.filter(function(a){return a.ip===focusIp;});
  if(q&&q.trim()){var t=q.toLowerCase();arr=arr.filter(function(a){return String(a.ip+a.uri+(a.asn||'')+(a.country||'')+(a.tags||[]).join(' ')).toLowerCase().includes(t);});}
  if(!arr.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">'+(focusIp?'No alerts for focus IP':'No alerts in buffer')+'</span></div>';return;}
  el.innerHTML=arr.map(function(a){
    var hl=(focusIp&&a.ip===focusIp)?' hl-focus':'';
    var sc=a.score||0,sevCls=sc>=10?' sev-hi':sc>=5?' sev-med':'',pillCls=scorePillCls(sc);
    var ap=(a.tags&&a.tags.length)?a.tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join(''):'';
    var flag=ccFlag(a.country||'');
    var key=a.ip+'|'+a.ts,isNew=!seenAlertKeys.has(key);
    seenAlertKeys.add(key);
    var ipGlow=sc>=10?'color:#f87171;text-shadow:0 0 10px rgba(248,113,113,0.6)':sc>=5?'color:#fb923c;text-shadow:0 0 8px rgba(251,146,60,0.5)':'color:var(--accent);text-shadow:0 0 8px rgba(0,212,255,0.4)';
    return '<div class="alert-row'+hl+sevCls+'" data-ip="'+escapeAttr(a.ip)+'">'
      +'<div class="alert-hd">'
        +'<span class="score-pill '+pillCls+'">+'+sc+'</span>'
        +'<span class="alert-ip" style="'+ipGlow+'" title="'+escapeAttr(a.ip)+'">'+escapeHtml(a.ip)+'</span>'
        +(flag?'<span class="alert-flag">'+flag+'</span>':'')
        +(a.country&&a.country!=='??'?'<span class="alert-cc">'+escapeHtml(a.country)+'</span>':'')
        +(ap?'<span class="alert-tags">'+ap+'</span>':'')
        +(isNew?'<span class="new-badge">NEW</span>':'')
        +'<span class="alert-time">'+timeAgo(a.ts)+'</span>'
      +'</div>'
      +'<div class="alert-uri" title="'+escapeAttr(a.uri)+'">'+escapeHtml(a.uri)+'</div>'
      +(a.asn||a.ua?'<div class="alert-meta">'+escapeHtml(a.asn||'')+(a.ua?'<span class="alert-sep">\u2022</span><span class="alert-ua">'+escapeHtml(a.ua)+'</span>':'')+'</div>':'')
      +'</div>';
  }).join('');
}

function renderThreats(el,rows){
  var q=document.getElementById('q').value;
  var r=rows||[];
  if(q&&q.trim()){var t=q.toLowerCase();r=r.filter(function(tw){return String(tw.ip+tw.asn+tw.top_path+(tw.country||'')+(tw.tags||[]).join(' ')).toLowerCase().includes(t);});}
  if(focusIp) r=r.filter(function(tw){return tw.ip===focusIp;});
  if(!r.length){el.innerHTML='<div class="th-row"><span></span><span class="ip" style="color:var(--muted)">'+(focusIp?'No threats for focus':'No scored sources')+'</span></div>';return;}
  var maxScore=Math.max.apply(null,r.map(function(t){return t.score||0;}).concat([1]));
  el.innerHTML=r.map(function(t,i){
    var hl=(focusIp&&t.ip===focusIp)?' hl-focus':'',rankCls=i===0?' rank1':'',rankNumCls=i===0?' r1':'';
    var tp=(t.tags&&t.tags.length)?t.tags.map(function(x){return '<span class="tag tag-'+escapeAttr(x)+'">'+escapeHtml(x)+'</span>';}).join(''):'';
    var filled=Math.max(1,Math.round((t.score/maxScore)*5));
    var barColor=t.score>=10?'#dc2626':t.score>=5?'#ea580c':'#f59e0b';
    var barGlow=t.score>=10?'0 0 6px rgba(220,38,38,0.6)':t.score>=5?'0 0 6px rgba(234,88,12,0.5)':'0 0 4px rgba(245,158,11,0.4)';
    var segs='';for(var s=0;s<5;s++){segs+='<div class="sc-seg'+(s<filled?' lit':'')+'" style="'+(s<filled?'background:'+barColor+';box-shadow:'+barGlow:'')+'"></div>';}
    var flag=ccFlag(t.country||'');
    return '<div class="th-row'+hl+rankCls+'" data-ip="'+escapeAttr(t.ip)+'" title="'+escapeAttr((t.asn||'')+' '+t.top_path)+'">'
      +'<span class="rank'+rankNumCls+'">'+(i+1)+'</span>'
      +'<span class="ip">'+escapeHtml(t.ip)+(tp?' '+tp:'')+'</span>'
      +'<div class="sc-segs">'+segs+'<span class="sc-num">'+t.score+'</span></div>'
      +'<span class="hits">'+t.hits+'</span>'
      +'<span class="cc" title="'+escapeHtml(t.country||'?')+'">'+(flag||escapeHtml(t.country||'?'))+'</span>'
      +'</div>';
  }).join('');
}

function statusBuckets(st){
  var a=[0,0,0,0,0];
  Object.keys(st||{}).forEach(function(k){
    var v=+st[k], c=parseInt(k,10);
    if(c>=200&&c<300) a[0]+=v;
    else if(c>=300&&c<400) a[1]+=v;
    else if(c>=400&&c<500) a[2]+=v;
    else if(c>=500&&c<600) a[3]+=v;
    else a[4]+=v;
  });
  return a;
}

function confCls(n){ return n>=70?'hi':n>=40?'med':'lo'; }

function renderBotnetCampaigns(el,campaigns){
  var arr=campaigns||[];
  if(!arr.length){
    el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No active campaigns detected &mdash; waiting for coordinated multi-IP probes</span></div>';
    return;
  }
  el.innerHTML=arr.map(function(c){
    var cls=confCls(c.confidence);
    var flags=(c.countries||[]).slice(0,7).map(function(cc){return ccFlag(cc)||cc;}).join('');
    var age=timeAgo(new Date(c.detected_at*1000).toISOString());
    return '<div class="bn-row" title="Campaign '+escapeAttr(c.id)+'\\nFirst seen: '+age+'\\nSubnets: '+c.subnet_count+'\\nHits: '+c.total_hits+'">'
      +'<span class="bn-id">'+escapeHtml(c.id)+'</span>'
      +'<span class="bn-uri" title="'+escapeAttr(c.trigger_uri)+'">'+escapeHtml(c.trigger_uri)+'</span>'
      +'<span class="bn-num">'+c.ip_count+'</span>'
      +'<span class="bn-num">'+c.asn_count+'</span>'
      +'<span class="bn-flags">'+flags+'</span>'
      +'<div class="bn-conf">'
        +'<div class="bn-conf-track"><div class="bn-conf-fill '+cls+'" style="width:'+c.confidence+'%"></div></div>'
        +'<span class="bn-conf-val '+cls+'">'+c.confidence+'</span>'
      +'</div>'
      +'</div>';
  }).join('');
}

function renderSources(el,sources,logPaths,ingestEnabled){
  if(!el) return;
  var rows=Object.entries(sources||{}).sort(function(a,b){return b[1]-a[1];});
  // show tailed paths that have no events yet too
  (logPaths||[]).forEach(function(p){
    if(!sources||sources[p]===undefined) rows.push([p,0]);
  });
  if(!rows.length&&!ingestEnabled){el.innerHTML='<div style="padding:10px 14px;color:var(--muted);font-size:12px">No sources configured</div>';return;}
  var h='';
  rows.forEach(function(r){
    var label=r[0],count=r[1];
    var isFile=label.startsWith('/');
    var icon=isFile? '&#128196;' : '&#127760;';
    var removeBtn=isFile?'':'<button type="button" class="src-remove-btn" data-src="'+escapeAttr(label)+'" style="margin-left:6px;background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;line-height:1;padding:0 2px" title="Remove source">&times;</button>';
    h+='<div style="display:flex;align-items:center;gap:8px;padding:7px 14px;border-bottom:1px solid var(--border)">'
      +'<span style="font-size:13px">'+icon+'</span>'
      +'<span style="flex:1;font-size:11px;word-break:break-all;color:var(--fg)">'+escapeHtml(label)+'</span>'
      +'<span style="font-size:12px;color:var(--muted);white-space:nowrap">'+count.toLocaleString()+' events</span>'
      +removeBtn
      +'</div>';
  });
  if(ingestEnabled){
    h+='<div style="padding:6px 14px;font-size:10px;color:var(--ok)">HTTP ingest endpoint active (POST /api/ingest)</div>';
  }
  el.innerHTML=h;
}

function renderBanList(d){
  var el=document.getElementById('banList');
  var bans=d.banned_ips||[];
  var mh=d.muted_hits||{};
  if(!bans.length){ el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No muted IPs</span></div>'; return; }
  el.innerHTML=bans.map(function(ip){
    var c=mh[ip]||0;
    return '<div class="ban-row"><span class="kip" title="'+escapeAttr(ip)+'">'+escapeHtml(ip)+'</span>'
      +'<span class="cnt">'+c+' excl.</span>'
      +'<button type="button" class="toolbtn" data-unban="'+escapeAttr(ip)+'">Unmute</button></div>';
  }).join('');
}

/* Poll control */
function setPoll(ms){
  pollMs=ms;
  document.querySelectorAll('.poll-opt').forEach(function(b){ b.classList.toggle('on',+b.dataset.ms===ms); });
  schedulePoll();
}
function schedulePoll(){
  if(pollTimer) clearInterval(pollTimer);
  pollTimer=null;
  if(paused||pollMs<=0) return;
  pollTimer=setInterval(load,pollMs);
}
function setPaused(p){
  paused=p;
  document.getElementById('btnPause').classList.toggle('on',p);
  document.getElementById('btnPause').innerText=p?'Resume':'Pause';
  document.getElementById('freezeBadge').style.display=p?'inline-flex':'none';
  schedulePoll();
}

function exportJson(){
  if(!lastPayload) return;
  var blob=new Blob([JSON.stringify(lastPayload,null,2)],{type:'application/json'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='sentinel-snapshot.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

/* IP Modal */
function closeModal(){ document.getElementById('modalBg').classList.remove('open'); }



async function openIpModal(ip){
  if(!ip) return;
  modalIp=ip;
  document.getElementById('modalIpText').innerText=ip;
  document.getElementById('modalFlag').innerText='';
  document.getElementById('modalCcPill').style.display='none';
  document.getElementById('modalGeoStrip').style.display='none';
  document.getElementById('modalTagsRow').style.display='none';
  document.getElementById('mStatHits').innerText='\u2014';
  document.getElementById('mStatScore').innerText='\u2014';
  document.getElementById('mStatPaths').innerText='\u2014';
  document.getElementById('mStatClass').innerText='...';
  document.getElementById('mStatClass').className='modal-stat-val';
  document.getElementById('mStatEnrichWrap').style.display='none';
  document.getElementById('mStatEnrich').innerText='\u2014';
  document.getElementById('mStatIpinfoWrap').style.display='none';
  document.getElementById('mStatIpinfo').innerText='\u2014';
  document.getElementById('mStatAbuseWrap').style.display='none';
  document.getElementById('mStatAbuse').innerText='\u2014';
  document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--muted);font-family:var(--mono);font-size:12px;text-align:center">Loading\u2026</div>';
  document.getElementById('modalBg').classList.add('open');
  try{
    var res=await fetch('/api/ip?ip='+encodeURIComponent(ip),{credentials:'same-origin'});
    var j=await res.json();
    if(!res.ok){
      document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center">'+escapeHtml(j.error||'Error')+'</div>';
    } else {
    var g=j.geo||{}, cc=g.country||'', flag=ccFlag(cc);
    var asnRaw=g.asn||'', asnParts=asnRaw.split(' | ');
    var asnNum=asnParts[0]||'', isp=asnParts[1]||asnParts[0]||'';
    var sc=j.score||0, tags=j.tags||[], paths=j.paths||[];

    if(flag) document.getElementById('modalFlag').innerText=flag;
    if(cc&&cc!=='??'){
      var pill=document.getElementById('modalCcPill');
      pill.innerText=cc; pill.style.display='inline-flex';
    }

    // Stat strip
    var scoreEl=document.getElementById('mStatScore');
    scoreEl.innerText=sc;
    scoreEl.className='modal-stat-val '+(sc>=10?'hi':sc>=5?'med':'ok');
    document.getElementById('mStatHits').innerText=(j.hits||0).toLocaleString();
    document.getElementById('mStatPaths').innerText=paths.length;
    var classEl=document.getElementById('mStatClass');
    if(tags.length){
      classEl.innerHTML=tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join(' ');
      classEl.className='modal-stat-val';
    } else {
      classEl.innerText='clean'; classEl.className='modal-stat-val ok';
    }

    // Geo strip
    var geoItems=[];
    if(isp) geoItems.push(['ISP / Org',isp]);
    if(asnNum&&asnNum!==isp) geoItems.push(['ASN',asnNum]);
    if(cc&&cc!=='??') geoItems.push(['Country',cc]);
    if(geoItems.length){
      var gs=document.getElementById('modalGeoStrip');
      gs.innerHTML=geoItems.map(function(item){
        return '<div class="modal-geo-item"><div class="geo-lbl">'+escapeHtml(item[0])+'</div><div class="geo-val" title="'+escapeAttr(item[1])+'">'+escapeHtml(item[1])+'</div></div>';
      }).join('');
      gs.style.display='flex';
    }

    // Tags row
    if(tags.length){
      var tr=document.getElementById('modalTagsRow');
      tr.innerHTML='<span class="modal-tags-lbl">Tags</span>'
        +tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join('');
      tr.style.display='flex';
    }

    // Paths list
    if(!paths.length){
      document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--muted);font-family:var(--mono);font-size:12px;text-align:center">No path data recorded</div>';
    } else {
      var total=paths.reduce(function(s,p){return s+(p[1]||0);},0)||1;
      var maxH=paths[0][1]||1;
      document.getElementById('modalPaths').innerHTML=paths.map(function(p,i){
        var barPct=Math.round(((p[1]||0)/maxH)*100);
        var sharePct=(((p[1]||0)/total)*100).toFixed(1);
        return '<div class="path-row">'
          +'<div class="path-row-bg" style="width:'+barPct+'%"></div>'
          +'<span class="path-row-rank'+(i===0?' r1':'')+'">'+(i+1)+'</span>'
          +'<span class="path-row-text" title="'+escapeAttr(p[0])+'">'+escapeHtml(p[0])+'</span>'
          +'<span class="path-row-hits">'+p[1]+'</span>'
          +'<span class="path-row-pct">'+sharePct+'%</span>'
          +'</div>';
      }).join('');
    }
    } // end else (res.ok)
  }catch(e){
    document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center">Request failed</div>';
  }
  // Shodan InternetDB + IPInfo -- fire-and-forget, does not block modal open
  try{
    var er=await fetch('/api/ipenrich?ip='+encodeURIComponent(ip),{credentials:'same-origin'});
    if(er.ok){
      var ej=await er.json();
      if(ej.ok){
        // Shodan
        var sd=ej.shodan||{};
        var sWrap=document.getElementById('mStatEnrichWrap');
        var sEl=document.getElementById('mStatEnrich');
        if(sWrap&&sEl){
          var sParts=[];
          if(sd.ports&&sd.ports.length) sParts.push(sd.ports.length+' port'+(sd.ports.length===1?'':'s')+': '+sd.ports.slice(0,8).join(', ')+(sd.ports.length>8?'...':''));
          if(sd.vulns&&sd.vulns.length) sParts.push(sd.vulns.length+' CVE'+(sd.vulns.length===1?'':'s')+': '+sd.vulns.slice(0,3).join(', ')+(sd.vulns.length>3?'...':''));
          if(sd.tags&&sd.tags.length) sParts.push('tags: '+sd.tags.join(', '));
          if(sd.hostnames&&sd.hostnames.length) sParts.push(sd.hostnames.slice(0,3).join(', ')+(sd.hostnames.length>3?'...':''));
          if(Object.keys(sd).length){
            sWrap.style.display='';
            sEl.innerText=sParts.length?sParts.join(' | '):'not indexed';
            sEl.className='modal-stat-val '+(sd.vulns&&sd.vulns.length?'hi':'');
          }
        }
        // IPInfo
        var ii=ej.ipinfo||{};
        var iWrap=document.getElementById('mStatIpinfoWrap');
        var iEl=document.getElementById('mStatIpinfo');
        if(iWrap&&iEl){
          var iParts=[];
          if(ii.org) iParts.push(ii.org);
          if(ii.city||ii.region||ii.country) iParts.push([ii.city,ii.region,ii.country].filter(Boolean).join(', '));
          if(ii.timezone) iParts.push(ii.timezone);
          if(ii.abuse_contact) iParts.push('abuse: '+ii.abuse_contact);
          if(iParts.length){
            iWrap.style.display='';
            iEl.innerText=iParts.join(' | ');
            iEl.className='modal-stat-val';
          }
        }
        // AbuseIPDB
        var ab=ej.abuseipdb||{};
        var aWrap=document.getElementById('mStatAbuseWrap');
        var aEl=document.getElementById('mStatAbuse');
        if(aWrap&&aEl&&(ab.abuse_score!=null||ab.total_reports!=null)){
          var abParts=[];
          if(ab.abuse_score!=null) abParts.push('score: '+ab.abuse_score+'%');
          if(ab.total_reports) abParts.push(ab.total_reports+' report'+(ab.total_reports===1?'':'s'));
          if(ab.usage_type) abParts.push(ab.usage_type);
          if(ab.is_whitelisted) abParts.push('whitelisted');
          if(abParts.length){
            aWrap.style.display='';
            aEl.innerText=abParts.join(' | ');
            var sc=ab.abuse_score||0;
            aEl.className='modal-stat-val '+(sc>=75?'hi':sc>=25?'med':'ok');
          }
        }
      }
    }
  }catch(_e){}
}

function setFocus(ip){
  focusIp=ip||'';
  document.getElementById('focusLbl').innerText=focusIp?('[focus: '+focusIp+']'):'';
  document.getElementById('btnClearFocus').style.display=focusIp?'inline-block':'none';
  if(lastPayload) applyRender(lastPayload);
  historyPage=1;
  loadHistoryEvents();
}

function toggleIpFocus(ip){
  if(!ip) return;
  if(focusIp===ip){
    setFocus('');
    closeModal();
    return;
  }
  setFocus(ip);
  openIpModal(ip);
}

function applyRender(d){
  renderIpList(document.getElementById('ips'),d.ips,d.ip_tags||{});
  renderList(document.getElementById('domains'),d.domains);
  renderList(document.getElementById('paths'),d.paths);
  renderList(document.getElementById('refs'),d.referers);
  renderList(document.getElementById('asn'),d.asn);
  renderStatus(document.getElementById('status'),d.status);
  renderAlerts(document.getElementById('alerts'),d.alerts);
  renderThreats(document.getElementById('threats'),d.top_threats);
  renderBotnetCampaigns(document.getElementById('botnets'),d.botnet_campaigns);
  renderSources(document.getElementById('sourcesList'),d.sources,d.log_paths,d.ingest_enabled);
  updateWorldMap(d.countries);
}

/* Main load */
async function load(force){
  if(paused&&!force) return;
  var d;
  try{
    var res=await fetch('/data',{credentials:'same-origin'});
    if(res.status===401){
      document.getElementById('foot').innerText='401: reload and sign in (Basic auth for this origin)';
      return;
    }
    d=await res.json();
  }catch(e){ return; }
  lastPayload=d;
  lastLoadMs=Date.now();

  var ab=document.getElementById('authBadge');
  if(ab) ab.style.display=d.auth_enabled?'inline-flex':'none';

  /* DEFCON posture */
  updateDefcon(d.threat_level||'NORMAL', d.threat_color);

  /* KPI values */
  var rpsV=d.rps||0, peakV=d.peak||0, totalV=d.total||0, uniqV=d.unique_ips||0;
  var errpctV=parseFloat(d.error_rate_pct||0), atkV=d.attack_rps_last_tick||0;
  var clientE=d.client_errors||0, serverE=d.server_errors||0;

  document.getElementById('rps').innerText=rpsV;
  document.getElementById('peak').innerText=peakV;
  document.getElementById('total').innerText=totalV.toLocaleString();
  document.getElementById('uniq').innerText=uniqV;
  document.getElementById('errs').innerText=clientE+' / '+serverE;
  document.getElementById('errpct').innerText=errpctV+'%';
  document.getElementById('atk').innerText=atkV;
  document.getElementById('mutedTotal').innerText=d.muted_total||0;
  document.getElementById('bytesServed').innerText=fmtBytes(d.bytes_served||0);

  /* KPI color thresholds */
  kpiLevel('kpi-rps',    rpsV,    20, 80);
  kpiLevel('kpi-peak',   peakV,   20, 80);
  kpiLevel('kpi-uniq',   uniqV,   50, 200);
  kpiLevel('kpi-errs',   clientE+serverE, 10, 50);
  kpiLevel('kpi-errpct', errpctV, 5,  20);
  kpiLevel('kpi-atk',    atkV,    2,  10);

  /* KPI deltas */
  kpiDelta('delta-rps',    rpsV,    prevKpi.rps);
  kpiDelta('delta-peak',   peakV,   prevKpi.peak);
  kpiDelta('delta-uniq',   uniqV,   prevKpi.uniq);
  kpiDelta('delta-errpct', errpctV, prevKpi.errpct);
  kpiDelta('delta-atk',    atkV,    prevKpi.atk);
  prevKpi={rps:rpsV,peak:peakV,uniq:uniqV,errpct:errpctV,atk:atkV};

  /* Charts */
  if(!historyMode){
    rpsHist.push(rpsV);
    var lastAtk=(d.attack_timeline&&d.attack_timeline.length)?d.attack_timeline[d.attack_timeline.length-1]:0;
    atkHist.push(lastAtk);
    if(rpsHist.length>MAX) rpsHist.shift();
    if(atkHist.length>MAX) atkHist.shift();
    var labels=rpsHist.map(function(_,i){ return i; });
    comboChart.data.labels=labels;
    comboChart.data.datasets[0].data=rpsHist.slice();
    comboChart.data.datasets[1].data=atkHist.slice();
    comboChart.update('none');
  }else{
    applyHistoryChart(historyPoints);
  }
  statusDonut.data.datasets[0].data=statusBuckets(d.status);
  statusDonut.update('none');

  var renderErr=null;
  try{
    applyRender(d);
    renderBanList(d);
  }catch(e){
    renderErr=e;
    console.error('render failure',e);
  }

  /* Alert count / tab title */
  var alertCount=(d.alerts||[]).length;
  if(!isPageVisible&&alertCount>knownAlertCount){
    newAlertsSinceBlur+=alertCount-knownAlertCount;
    document.title='('+newAlertsSinceBlur+') Sentinel | SOC';
  }
  knownAlertCount=alertCount;

  var ih=document.getElementById('iptablesHintP');
  if(ih){ih.textContent=d.iptables_enabled?('iptables DROP on chain '+d.iptables_chain+' enabled.'):('iptables off \u2014 set SENTINEL_IPTABLES=1 to sync rules.');}
  var ihs=document.getElementById('iptablesHintShort');
  if(ihs) ihs.textContent=d.iptables_enabled?'mute + iptables':'mute list';

  var up=d.stream_uptime_s!=null?(' | stream '+d.stream_uptime_s+'s'):'';
  var poll=paused?'paused':(pollMs/1000)+'s';
  var au=d.audit_log?' | audit on':'';
  document.getElementById('foot').innerText='Server '+d.server_time+up+' | poll '+poll+au+(renderErr?' | render error':'');
  initWorldMap();
  refreshHistory();
}

/* Sidebar toggle */
document.getElementById('sbToggle').addEventListener('click',function(){
  sidebarOpen=!sidebarOpen;
  document.getElementById('layout').classList.toggle('sb-hidden',!sidebarOpen);
  document.getElementById('sbToggle').innerHTML=sidebarOpen?'&#9664;':'&#9654;';
});

/* Event wiring */
document.getElementById('btnPause').addEventListener('click',function(){ setPaused(!paused); });
document.querySelectorAll('.poll-opt').forEach(function(b){
  b.addEventListener('click',function(){ setPaused(false); setPoll(+b.dataset.ms); });
});
document.querySelectorAll('.hist-range').forEach(function(b){
  b.addEventListener('click',function(){
    document.querySelectorAll('.hist-range').forEach(function(x){x.classList.remove('on');});
    b.classList.add('on');
    historySelectedDay='';
    var hsel=document.getElementById('histDaySelect');
    if(hsel) hsel.value='';
    historyRangeSec=+b.dataset.sec||2592000;
    historyPage=1;
    refreshHistory();
  });
});
document.getElementById('histDaySelect').addEventListener('change',function(e){
  historySelectedDay=(e.target.value||'').trim();
  historyPage=1;
  refreshHistory();
});
document.getElementById('btnHistMode').addEventListener('click',function(){
  historyMode=!historyMode;
  document.getElementById('btnHistMode').classList.toggle('on',historyMode);
  if(historyMode) applyHistoryChart(historyPoints);
});
document.getElementById('btnHistPrev').addEventListener('click',function(){
  if(historyPage<=1) return;
  historyPage-=1;
  loadHistoryEvents();
});
document.getElementById('btnHistNext').addEventListener('click',function(){
  var nextStart=historyPage*50;
  if(nextStart>=historyTotal) return;
  historyPage+=1;
  loadHistoryEvents();
});
document.getElementById('btnExport').addEventListener('click',exportJson);
document.getElementById('btnClearFocus').addEventListener('click',function(){ setFocus(''); });

function warnIptables(j){
  if(j&&j.iptables&&j.iptables.enabled&&!j.iptables.ok){ alert('iptables: '+(j.iptables.error||'failed')); }
}
async function removeSource(label){
  if(!confirm('Remove source "'+label+'" from the list?')) return;
  try{
    var r=await fetch('/api/source/remove',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:label})});
    if(!r.ok){ alert('Remove failed'); return; }
    await load(true);
  }catch(e){ alert('Remove failed'); }
}
document.getElementById('sourcesList').addEventListener('click',async function(e){
  var btn=e.target.closest('.src-remove-btn');
  if(!btn||!btn.dataset.src) return;
  e.stopPropagation();
  await removeSource(btn.dataset.src);
});
document.getElementById('btnBan').addEventListener('click',async function(){
  var ip=document.getElementById('banIp').value.trim();
  if(!ip) return;
  try{
    var r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Mute failed'); return; }
    warnIptables(j);
    document.getElementById('banIp').value='';
    await load(true);
  }catch(e){ alert('Mute failed'); }
});
document.getElementById('banList').addEventListener('click',async function(e){
  var b=e.target.closest('[data-unban]');
  if(!b||!b.dataset.unban) return;
  var ip=b.dataset.unban;
  try{
    var r=await fetch('/api/unban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Unmute failed'); return; }
    warnIptables(j);
    await load(true);
  }catch(err){ alert('Unmute failed'); }
});
document.getElementById('btnReset').addEventListener('click',async function(){
  if(!confirm('Reset all counters, charts, alerts, and geo cache?')) return;
  try{
    var r=await fetch('/api/reset',{method:'POST',credentials:'same-origin'});
    if(!r.ok) throw new Error('bad');
    lastPayload=null; setFocus(''); closeModal(); seenAlertKeys.clear();
    rpsHist=[]; atkHist=[];
    comboChart.data.labels=[]; comboChart.data.datasets[0].data=[]; comboChart.data.datasets[1].data=[];
    comboChart.update('none');
    statusDonut.data.datasets[0].data=[0,0,0,0,0]; statusDonut.update('none');
    if(worldMap){try{worldMap.series.regions[0].setValues({});}catch(e){}}
    historySelectedDay='';
    historyDaysLoaded=false;
    var hsel=document.getElementById('histDaySelect');
    if(hsel) hsel.value='';
    historyPage=1;
    setPaused(false); await load(true); await refreshHistory();
  }catch(e){ alert('Reset failed'); }
});

document.getElementById('q').addEventListener('input',function(){ if(lastPayload) applyRender(lastPayload); });
document.getElementById('modalBg').addEventListener('click',function(e){ if(e.target.id==='modalBg') closeModal(); });
document.getElementById('modalClose').addEventListener('click',closeModal);
document.getElementById('modalCopy').addEventListener('click',function(){
  if(!modalIp) return;
  if(navigator.clipboard){navigator.clipboard.writeText(modalIp).then(function(){
    var btn=document.getElementById('modalCopy');var orig=btn.innerText;
    btn.innerText='Copied!';btn.style.color='var(--ok)';
    setTimeout(function(){btn.innerText=orig;btn.style.color='';},1500);
  });}
});
document.getElementById('modalExtLink').addEventListener('click',function(e){
  e.preventDefault();
  if(!modalIp) return;
  window.open('https://ipinfo.io/'+encodeURIComponent(modalIp),'_blank','noopener');
});
document.getElementById('modalBan').addEventListener('click',async function(){
  if(!modalIp) return;
  try{
    var r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:modalIp})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Mute failed'); return; }
    warnIptables(j);
    closeModal();
    await load(true);
  }catch(e){ alert('Mute failed'); }
});

document.body.addEventListener('click',function(e){
  var ipRow=e.target.closest('.row-ip');
  if(ipRow&&ipRow.dataset.ip){ toggleIpFocus(ipRow.dataset.ip); return; }
  var th=e.target.closest('.th-row[data-ip]');
  if(th&&th.dataset.ip){ toggleIpFocus(th.dataset.ip); return; }
  var ar=e.target.closest('.alert-row');
  if(ar&&ar.dataset.ip){ toggleIpFocus(ar.dataset.ip); return; }
  var hi=e.target.closest('.hist-ip-link');
  if(hi&&hi.dataset.ip){ toggleIpFocus(hi.dataset.ip); return; }
});

document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){ closeModal(); return; }
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); document.getElementById('q').focus(); }
});

/* Audit log */
var auditPollTimer=null;
var auditLastCount=0;

function renderAudit(entries){
  var el=document.getElementById('auditList');
  if(!el) return;
  if(!entries||!entries.length){
    el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No audit entries yet</span></div>';
    return;
  }
  var ACTION_COLOR={'mute':'var(--danger)','unban':'var(--ok)','reset':'var(--warn)','auth_failed':'#f59e0b','audit_cleared':'#a78bfa','auto_ban':'#ef4444'};
  var html='';
  var shown=entries.slice(-50).reverse();
  for(var i=0;i<shown.length;i++){
    var e=shown[i];
    var ts=e.ts?(e.ts.replace('T',' ').replace(/\\.[0-9]+([+-][0-9][0-9]:[0-9][0-9]|Z)?$/,'').replace('+00:00','')+' UTC'):'';
    var col=ACTION_COLOR[e.action]||'var(--accent)';
    var targetIp=(e.detail&&e.detail.ip)||(e.action==='auth_failed'?(e.remote||''):'');
    var banBtn=targetIp
      ? '<button type="button" class="toolbtn danger audit-ban-btn" data-ip="'+escapeAttr(targetIp)+'" style="font-size:9px;padding:2px 7px;flex-shrink:0;margin-left:4px">Ban</button>'
      : '';
    html+='<div class="list-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:5px 10px">'
      +'<div style="display:flex;gap:6px;width:100%;align-items:center">'
      +'<span style="color:'+col+';font-weight:700;text-transform:uppercase;font-size:10px;flex-shrink:0">'+escapeHtml(e.action||'')+'</span>'
      +'<span style="color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(e.user||'')+'</span>'
      +'<span style="color:var(--muted);font-size:10px;flex-shrink:0">'+escapeHtml(e.remote||'')+'</span>'
      +banBtn
      +'</div>'
      +'<div style="color:var(--muted);font-size:10px;display:flex;gap:6px;flex-wrap:wrap">'
      +'<span>'+escapeHtml(ts)+'</span>'
      +(targetIp?'<span style="color:var(--accent)">\u2192 <span class="hist-ip-link" data-ip="'+escapeAttr(targetIp)+'" style="cursor:pointer;text-decoration:underline;text-decoration-style:dotted" title="Click to drill down">'+escapeHtml(targetIp)+'</span></span>':'')
      +'</div>'
      +'</div>';
  }
  el.innerHTML=html;
}

async function loadAudit(force){
  var card=document.getElementById('auditCard');
  if(!card) return;
  try{
    var r=await fetch('/api/audit?limit=50',{credentials:'same-origin'});
    if(!r.ok) return;
    var j=await r.json();
    if(!j.audit_enabled){ card.style.display='none'; return; }
    card.style.display='';
    if(force||j.entries.length!==auditLastCount){
      auditLastCount=j.entries.length;
      renderAudit(j.entries);
    }
  }catch(e){}
}

function startAuditPoll(){
  loadAudit();
  auditPollTimer=setInterval(loadAudit,5000);
}

document.addEventListener('click',async function(e){
  /* Ban from audit log row */
  var banBtn=e.target.closest('.audit-ban-btn');
  if(banBtn&&banBtn.dataset.ip){
    var ip=banBtn.dataset.ip;
    if(!confirm('Mute '+ip+'?')) return;
    try{
      var r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
      var j=await r.json().catch(function(){return{};});
      if(!r.ok){alert(j.error||'Mute failed');return;}
      warnIptables(j);
      await load(true);
      await loadAudit(true);
    }catch(err){alert('Mute failed');}
    return;
  }
});

document.getElementById('btnClearAudit').addEventListener('click',async function(){
  if(!confirm('Clear all audit log entries? This cannot be undone.')) return;
  try{
    var r=await fetch('/api/audit',{method:'DELETE',credentials:'same-origin'});
    var j=await r.json().catch(function(){return{};});
    if(!r.ok){alert(j.error||'Clear failed');return;}
    auditLastCount=0;
    await loadAudit(true);
  }catch(err){alert('Clear failed');}
});

startAuditPoll();

setPoll(1500);
load();
refreshHistory();
</script>
</body>
</html>
"""


# ========================
# START
# ========================
_ensure_state_dir()
_ensure_audit_file()
_load_bans()
_load_parsed_state()
_load_behavior_state()
_load_history_buckets()
_prune_history_event_files()

if __name__ == "__main__":
    _sync_iptables_bans()
    for _ in range(GEO_WORKERS):
        threading.Thread(target=geo_worker, daemon=True).start()
    for _log_path in _effective_log_paths():
        threading.Thread(target=stream, kwargs={"path": _log_path}, daemon=True).start()
    threading.Thread(target=reset, daemon=True).start()
    threading.Thread(target=botnet_detection_worker, daemon=True).start()
    threading.Thread(target=_state_flush_worker, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)