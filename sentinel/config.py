# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/config.py -- All configuration from environment variables.
Imports only stdlib; no Flask, no package imports.
"""
import os

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

_SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))

# Persistent data root outside the app tree.
STATE_DIR = os.environ.get("SENTINEL_STATE_DIR", "").strip().rstrip("/\\")

# Optional: persist muted-IP list as JSON array of strings.
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

# Remote ingest: Bearer key for POST /api/ingest. Empty = no key required.
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
BOTNET_MIN_SUBNETS = 2      # minimum distinct /24 subnets
BOTNET_MIN_ASNS = 2         # minimum distinct ASNs
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
    SSH_HISTORY_BUCKETS_PATH = os.path.join(STATE_DIR, "ssh-history-buckets.json")
    SSH_HISTORY_EVENTS_DIR = os.path.join(STATE_DIR, "ssh-history-events")
else:
    BEHAVIOR_STATE_PATH = ""
    PARSED_STATE_PATH = ""
    HISTORY_BUCKETS_PATH = ""
    HISTORY_EVENTS_DIR = ""
    SSH_HISTORY_BUCKETS_PATH = ""
    SSH_HISTORY_EVENTS_DIR = ""

PLACEHOLDER_CC = "..."
PLACEHOLDER_ASN = "Resolving..."

# GreyNoise community API key (optional; empty = skip GreyNoise enrichment).
GREYNOISE_KEY = os.environ.get("SENTINEL_GREYNOISE_KEY", "").strip()

# Minimum accumulated score before an IP is auto-enqueued for reputation enrichment.
REPUTATION_ENRICH_THRESHOLD = int(os.environ.get("SENTINEL_REPUTATION_THRESHOLD", "10") or "10")
# How many background reputation-worker threads to run.
REPUTATION_WORKERS = int(os.environ.get("SENTINEL_REPUTATION_WORKERS", "2") or "2")
# How long (seconds) before the same IP may be re-enriched. Default 1 hour.
REPUTATION_TTL = int(os.environ.get("SENTINEL_REPUTATION_TTL", "3600") or "3600")

# UA impersonation burst: flag when same UA is used by this many distinct IPs ...
UA_BURST_THRESHOLD = int(os.environ.get("SENTINEL_UA_BURST_THRESHOLD", "20") or "20")
# ... within this many seconds.
UA_BURST_WINDOW_S = int(os.environ.get("SENTINEL_UA_BURST_WINDOW_S", "60") or "60")

# TLS/JA3 fingerprint sharing: flag fingerprint when seen across this many distinct IPs.
TLS_FP_SHARED_THRESHOLD = int(os.environ.get("SENTINEL_TLS_FP_THRESHOLD", "5") or "5")

# SSH KEX fingerprint sharing: flag when same cipher/KEX suite seen from this many distinct IPs.
SSH_KEX_SHARED_THRESHOLD = int(os.environ.get("SENTINEL_SSH_KEX_SHARED_THRESHOLD", "3") or "3")

# SSH source-port entropy threshold: tag low_port_entropy when Shannon bits fall below this.
# Random ephemeral ports ~16 bits; botnet with 10 fixed ports ~3.3 bits.
SSH_PORT_ENTROPY_LOW = float(os.environ.get("SENTINEL_SSH_PORT_ENTROPY_LOW", "4.0") or "4.0")

# Slow-and-low: minimum hours active before the pattern is considered deliberate.
SLOW_LOW_MIN_HOURS = float(os.environ.get("SENTINEL_SLOW_LOW_MIN_HOURS", "2") or "2")
# Minimum unique non-static paths visited before flagging.
SLOW_LOW_MIN_PATHS = int(os.environ.get("SENTINEL_SLOW_LOW_MIN_PATHS", "15") or "15")

# Scanner detection thresholds.
SCANNER_MIN_PATHS  = int(os.environ.get("SENTINEL_SCANNER_MIN_PATHS",  "20")  or "20")
SCANNER_MAX_REQS   = int(os.environ.get("SENTINEL_SCANNER_MAX_REQS",   "60")  or "60")
SCANNER_WINDOW_S   = int(os.environ.get("SENTINEL_SCANNER_WINDOW_S",   "180") or "180")

# Brute-force detection thresholds.
BRUTEFORCE_MIN_HITS = int(os.environ.get("SENTINEL_BRUTEFORCE_MIN_HITS", "8")   or "8")
BRUTEFORCE_WINDOW_S = int(os.environ.get("SENTINEL_BRUTEFORCE_WINDOW_S", "240") or "240")

# Error probe: minimum requests and 4xx rate to fire.
ERROR_PROBE_MIN_REQS  = int(os.environ.get("SENTINEL_ERROR_PROBE_MIN_REQS",  "15") or "15")
ERROR_PROBE_4XX_RATE  = float(os.environ.get("SENTINEL_ERROR_PROBE_4XX_RATE", "0.6") or "0.6")

# Flood: >= N requests inside a sliding window.
FLOOD_REQ_THRESHOLD = int(os.environ.get("SENTINEL_FLOOD_REQ_THRESHOLD", "200") or "200")
FLOOD_WINDOW_S      = int(os.environ.get("SENTINEL_FLOOD_WINDOW_S",      "60")  or "60")

# Headless automation: minimum requests before no-referer rate is checked.
HEADLESS_MIN_REQS    = int(os.environ.get("SENTINEL_HEADLESS_MIN_REQS",    "30")  or "30")
HEADLESS_NO_REF_RATE = float(os.environ.get("SENTINEL_HEADLESS_NO_REF_RATE", "0.7") or "0.7")

# Multi-host scan: minimum distinct virtual hosts from one IP.
MULTI_HOST_THRESHOLD = int(os.environ.get("SENTINEL_MULTI_HOST_THRESHOLD", "4") or "4")

# Empty UA: minimum requests before the tag fires.
EMPTY_UA_MIN_REQS = int(os.environ.get("SENTINEL_EMPTY_UA_MIN_REQS", "10") or "10")

# Shared UA: minimum IPs sharing the same user-agent string.
SHARED_UA_MIN_IPS = int(os.environ.get("SENTINEL_SHARED_UA_MIN_IPS", "8") or "8")

# UA rotation: minimum switches, max reqs, and window.
UA_ROTATION_MIN_SWITCHES = int(os.environ.get("SENTINEL_UA_ROTATION_MIN_SWITCHES", "6")   or "6")
UA_ROTATION_MAX_REQS     = int(os.environ.get("SENTINEL_UA_ROTATION_MAX_REQS",     "80")  or "80")
UA_ROTATION_WINDOW_S     = int(os.environ.get("SENTINEL_UA_ROTATION_WINDOW_S",     "300") or "300")

# Server error probe: minimum requests and 5xx rate.
SERVER_ERROR_MIN_REQS  = int(os.environ.get("SENTINEL_SERVER_ERROR_MIN_REQS",  "10")  or "10")
SERVER_ERROR_5XX_RATE  = float(os.environ.get("SENTINEL_SERVER_ERROR_5XX_RATE", "0.3") or "0.3")
