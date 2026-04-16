# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/config.py -- Central configuration (env-driven, SOC-grade)
"""

import os

# ========================
# HELPERS
# ========================
def _bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y")


def _int(v, default):
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _float(v, default):
    try:
        return float(str(v).strip())
    except Exception:
        return default


# ========================
# LOG INPUT
# ========================
def _effective_log_paths():
    raw = os.environ.get("LOG_PATH", "/var/log/caddy/all-access.log").strip()
    if not raw:
        raw = "/var/log/caddy/all-access.log"
    return [p.strip() for p in raw.split(",") if p.strip()]


LOG_PATHS = _effective_log_paths()
LOG_PATH = LOG_PATHS[0]

LOG_FROM_START = _bool(os.environ.get("LOG_FROM_START"), False)

# ========================
# STATE PATHS
# ========================
_SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("SENTINEL_STATE_DIR", "").strip().rstrip("/\\")

def _state_file(name):
    return os.path.join(STATE_DIR, name) if STATE_DIR else ""

# ========================
# STORAGE FILES
# ========================
BAN_LIST_PATH = (
    os.environ.get("SENTINEL_BAN_LIST", "").strip()
    or _state_file("bans.json")
)

AUDIT_DISABLED = _bool(os.environ.get("SENTINEL_AUDIT_DISABLE"))
AUDIT_LOG_PATH = (
    "" if AUDIT_DISABLED else
    os.environ.get("SENTINEL_AUDIT_LOG", "").strip()
    or _state_file("audit.jsonl")
    or os.path.join(_SENTINEL_DIR, "sentinel-audit.jsonl")
)

BEHAVIOR_STATE_PATH = _state_file("behavior-state.json")
PARSED_STATE_PATH = _state_file("parsed-state.json")
PATH_WHITELIST_PATH = _state_file("path-whitelist.json")
HISTORY_BUCKETS_PATH = _state_file("history-buckets.json")
HISTORY_EVENTS_DIR = os.path.join(STATE_DIR, "history-events") if STATE_DIR else ""
SSH_HISTORY_BUCKETS_PATH = _state_file("ssh-history-buckets.json")
SSH_HISTORY_EVENTS_DIR = os.path.join(STATE_DIR, "ssh-history-events") if STATE_DIR else ""

# ========================
# NETWORK / SECURITY
# ========================
IPTABLES_ENABLED = _bool(os.environ.get("SENTINEL_IPTABLES"))
IPTABLES_CHAIN = os.environ.get("SENTINEL_IPTABLES_CHAIN", "INPUT").strip() or "INPUT"

SENTINEL_EXPECT_CF = _bool(os.environ.get("SENTINEL_EXPECT_CF"))

# ========================
# AUTH
# ========================
AUTH_USER = os.environ.get("SENTINEL_AUTH_USER", "").strip()
AUTH_PASSWORD = os.environ.get("SENTINEL_AUTH_PASSWORD", "")
AUTH_ENABLED = bool(AUTH_USER and AUTH_PASSWORD)

# ========================
# API / INGEST
# ========================
INGEST_KEY = os.environ.get("SENTINEL_INGEST_KEY", "").strip()

# Rate limit ingest (protect API)
INGEST_RATE_LIMIT = _int(os.environ.get("SENTINEL_INGEST_RATE", 200), 200)

# ========================
# THREAT INTEL
# ========================
IPINFO_TOKEN = os.environ.get("SENTINEL_IPINFO_TOKEN", "").strip()
ABUSEIPDB_KEY = os.environ.get("SENTINEL_ABUSEIPDB_KEY", "").strip()
GREYNOISE_KEY = os.environ.get("SENTINEL_GREYNOISE_KEY", "").strip()

# ========================
# PORT SCAN DETECTION (NEW)
# ========================
PORTSCAN_WINDOW_S = _int(os.environ.get("SENTINEL_PORTSCAN_WINDOW", 10), 10)

PORTSCAN_HORIZONTAL_MEDIUM = _int(os.environ.get("SENTINEL_PORTSCAN_H_MED", 20), 20)
PORTSCAN_HORIZONTAL_HIGH = _int(os.environ.get("SENTINEL_PORTSCAN_H_HIGH", 50), 50)

PORTSCAN_VERTICAL_MEDIUM = _int(os.environ.get("SENTINEL_PORTSCAN_V_MED", 20), 20)
PORTSCAN_VERTICAL_HIGH = _int(os.environ.get("SENTINEL_PORTSCAN_V_HIGH", 50), 50)

# dedup window (avoid spam)
PORTSCAN_DEDUP_WINDOW = _int(os.environ.get("SENTINEL_PORTSCAN_DEDUP", 30), 30)

# ========================
# SCORING ENGINE (NEW)
# ========================
SCORE_ALERT_THRESHOLD = _int(os.environ.get("SENTINEL_SCORE_ALERT", 5), 5)

SCORE_PORTSCAN_LOW = 2
SCORE_PORTSCAN_MED = 5
SCORE_PORTSCAN_HIGH = 10

SCORE_BRUTEFORCE = 8
SCORE_EXPLOIT_ATTEMPT = 10

# auto-ban threshold
AUTO_BAN_SCORE = _int(os.environ.get("SENTINEL_AUTO_BAN_SCORE", 25), 25)

# ========================
# CORRELATION
# ========================
CORRELATION_WINDOW = _int(os.environ.get("SENTINEL_CORRELATION_WINDOW", 60), 60)

# ========================
# BEHAVIOR DETECTION
# ========================
SCANNER_MIN_PATHS  = _int(os.environ.get("SENTINEL_SCANNER_MIN_PATHS", 20), 20)
SCANNER_MAX_REQS   = _int(os.environ.get("SENTINEL_SCANNER_MAX_REQS", 60), 60)
SCANNER_WINDOW_S   = _int(os.environ.get("SENTINEL_SCANNER_WINDOW_S", 180), 180)

BRUTEFORCE_MIN_HITS = _int(os.environ.get("SENTINEL_BRUTEFORCE_MIN_HITS", 8), 8)
BRUTEFORCE_WINDOW_S = _int(os.environ.get("SENTINEL_BRUTEFORCE_WINDOW_S", 240), 240)

FLOOD_REQ_THRESHOLD = _int(os.environ.get("SENTINEL_FLOOD_REQ_THRESHOLD", 200), 200)
FLOOD_WINDOW_S      = _int(os.environ.get("SENTINEL_FLOOD_WINDOW_S", 60), 60)

# ========================
# BOTNET DETECTION
# ========================
BOTNET_WINDOW_S = _int(os.environ.get("SENTINEL_BOTNET_WINDOW", 300), 300)
BOTNET_MIN_IPS = _int(os.environ.get("SENTINEL_BOTNET_MIN_IPS", 3), 3)
BOTNET_MIN_SUBNETS = _int(os.environ.get("SENTINEL_BOTNET_MIN_SUBNETS", 2), 2)
BOTNET_MIN_ASNS = _int(os.environ.get("SENTINEL_BOTNET_MIN_ASNS", 2), 2)

# ========================
# REPUTATION
# ========================
REPUTATION_ENRICH_THRESHOLD = _int(os.environ.get("SENTINEL_REPUTATION_THRESHOLD", 10), 10)
REPUTATION_TTL = _int(os.environ.get("SENTINEL_REPUTATION_TTL", 3600), 3600)

# ========================
# MISC
# ========================
ALERT_QUEUE_MAX = _int(os.environ.get("SENTINEL_ALERT_QUEUE", 200), 200)

PLACEHOLDER_CC = "..."
PLACEHOLDER_ASN = "Resolving..."

# Fallback audit log path used when the configured path is read-only.
_DEFAULT_AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel-audit.jsonl")

# ========================
# HISTORY
# ========================
HISTORY_BUCKET_S = _int(os.environ.get("SENTINEL_HISTORY_BUCKET_S", 60), 60)
HISTORY_RETENTION_DAYS = _int(os.environ.get("SENTINEL_HISTORY_RETENTION_DAYS", 30), 30)
HISTORY_RETENTION_S = HISTORY_RETENTION_DAYS * 86400
HISTORY_EVENT_PAGE_MAX = _int(os.environ.get("SENTINEL_HISTORY_PAGE_MAX", 200), 200)
HISTORY_EVENT_MAX_SCAN = _int(os.environ.get("SENTINEL_HISTORY_MAX_SCAN", 100000), 100000)

# ========================
# BEHAVIOR DETECTION (extended)
# ========================
PERSISTENT_THREAT_DAYS = _int(os.environ.get("SENTINEL_PERSISTENT_DAYS", 3), 3)
AUTH_FAIL_BAN_THRESHOLD = _int(os.environ.get("SENTINEL_AUTH_FAIL_BAN", 10), 10)

TLS_FP_SHARED_THRESHOLD = _int(os.environ.get("SENTINEL_TLS_FP_THRESHOLD", 5), 5)
UA_BURST_THRESHOLD = _int(os.environ.get("SENTINEL_UA_BURST_THRESHOLD", 20), 20)
UA_BURST_WINDOW_S = _int(os.environ.get("SENTINEL_UA_BURST_WINDOW_S", 60), 60)

ERROR_PROBE_MIN_REQS = _int(os.environ.get("SENTINEL_ERROR_PROBE_MIN_REQS", 15), 15)
ERROR_PROBE_4XX_RATE = _float(os.environ.get("SENTINEL_ERROR_PROBE_4XX_RATE", 0.6), 0.6)

SHARED_UA_MIN_IPS = _int(os.environ.get("SENTINEL_SHARED_UA_MIN_IPS", 8), 8)

UA_ROTATION_MIN_SWITCHES = _int(os.environ.get("SENTINEL_UA_ROTATION_MIN_SWITCHES", 6), 6)
UA_ROTATION_MAX_REQS = _int(os.environ.get("SENTINEL_UA_ROTATION_MAX_REQS", 80), 80)
UA_ROTATION_WINDOW_S = _int(os.environ.get("SENTINEL_UA_ROTATION_WINDOW_S", 300), 300)

SERVER_ERROR_MIN_REQS = _int(os.environ.get("SENTINEL_SERVER_ERROR_MIN_REQS", 10), 10)
SERVER_ERROR_5XX_RATE = _float(os.environ.get("SENTINEL_SERVER_ERROR_5XX_RATE", 0.3), 0.3)

HEADLESS_MIN_REQS = _int(os.environ.get("SENTINEL_HEADLESS_MIN_REQS", 30), 30)
HEADLESS_NO_REF_RATE = _float(os.environ.get("SENTINEL_HEADLESS_NO_REF_RATE", 0.7), 0.7)

MULTI_HOST_THRESHOLD = _int(os.environ.get("SENTINEL_MULTI_HOST_THRESHOLD", 4), 4)
EMPTY_UA_MIN_REQS = _int(os.environ.get("SENTINEL_EMPTY_UA_MIN_REQS", 10), 10)

SLOW_LOW_MIN_HOURS = _float(os.environ.get("SENTINEL_SLOW_LOW_MIN_HOURS", 2.0), 2.0)
SLOW_LOW_MIN_PATHS = _int(os.environ.get("SENTINEL_SLOW_LOW_MIN_PATHS", 15), 15)

# ========================
# SSH DETECTION
# ========================
SSH_KEX_SHARED_THRESHOLD = _int(os.environ.get("SENTINEL_SSH_KEX_SHARED_THRESHOLD", 3), 3)
SSH_PORT_ENTROPY_LOW = _float(os.environ.get("SENTINEL_SSH_PORT_ENTROPY_LOW", 1.5), 1.5)

# ========================
# BOTNET (extended)
# ========================
BOTNET_CHECK_INTERVAL = _int(os.environ.get("SENTINEL_BOTNET_CHECK_INTERVAL", 10), 10)
BOTNET_EXPIRY_S = _int(os.environ.get("SENTINEL_BOTNET_EXPIRY_S", 1800), 1800)

# ========================
# WORKERS
# ========================
GEO_WORKERS = _int(os.environ.get("SENTINEL_GEO_WORKERS", 2), 2)
REPUTATION_WORKERS = _int(os.environ.get("SENTINEL_REPUTATION_WORKERS", 1), 1)


def _effective_log_path():
    return LOG_PATHS[0] if LOG_PATHS else ""


def _effective_log_from_start():
    return _bool(os.environ.get("LOG_FROM_START"), False)