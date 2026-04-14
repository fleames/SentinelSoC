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
else:
    BEHAVIOR_STATE_PATH = ""
    PARSED_STATE_PATH = ""
    HISTORY_BUCKETS_PATH = ""
    HISTORY_EVENTS_DIR = ""

PLACEHOLDER_CC = "..."
PLACEHOLDER_ASN = "Resolving..."

# TLS/JA3 fingerprint sharing: flag fingerprint when seen across this many distinct IPs.
TLS_FP_SHARED_THRESHOLD = int(os.environ.get("SENTINEL_TLS_FP_THRESHOLD", "5") or "5")

# Slow-and-low: minimum hours active before the pattern is considered deliberate.
SLOW_LOW_MIN_HOURS = float(os.environ.get("SENTINEL_SLOW_LOW_MIN_HOURS", "2") or "2")
# Minimum unique non-static paths visited before flagging.
SLOW_LOW_MIN_PATHS = int(os.environ.get("SENTINEL_SLOW_LOW_MIN_PATHS", "15") or "15")
