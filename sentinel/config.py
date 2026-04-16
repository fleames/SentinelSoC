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