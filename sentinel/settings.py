# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/settings.py -- Runtime-mutable settings with persistence.

Settings override sentinel/config.py module attributes in-process.
Because all other modules read config.ATTR at call-time (not import-time),
setattr(config, key, value) takes effect immediately everywhere.

Persisted to {STATE_DIR}/settings.json so changes survive restarts.
"""
import json
import os
import threading

from sentinel import config

_lock = threading.Lock()
_overrides = {}   # key -> overridden value (for tracking what changed)

# ---------------------------------------------------------------------------
# Schema
# Each entry: type, min/max (for numbers), label, description, group.
# "attr" is the config module attribute to read/write.
# "derived" lists other attrs to recompute when this one changes.
# ---------------------------------------------------------------------------
SCHEMA = {
    # --- Detection ---
    "SCORE_ALERT_THRESHOLD": {
        "type": "int", "min": 1, "max": 100,
        "label": "Alert score threshold",
        "desc": "Minimum per-event score to add an entry to the alert feed.",
        "group": "Detection",
    },
    "PERSISTENT_THREAT_DAYS": {
        "type": "int", "min": 1, "max": 30,
        "label": "Persistent threat days",
        "desc": "Number of distinct UTC days an IP must appear before it is tagged 'persistent'.",
        "group": "Detection",
    },
    "AUTH_FAIL_BAN_THRESHOLD": {
        "type": "int", "min": 0, "max": 100,
        "label": "Auth fail auto-ban (0 = off)",
        "desc": "Auto-mute IPs that fail HTTP Basic Auth this many consecutive times.",
        "group": "Detection",
    },
    "SENTINEL_EXPECT_CF": {
        "type": "bool",
        "label": "Expect Cloudflare headers",
        "desc": "Flag requests missing CF-Ray as origin-bypass attempts.",
        "group": "Detection",
    },
    # --- Behavior signals ---
    "UA_BURST_THRESHOLD": {
        "type": "int", "min": 5, "max": 200,
        "label": "UA burst IP threshold",
        "desc": "Number of distinct IPs using the same UA within the burst window before flagging.",
        "group": "Behavior",
    },
    "UA_BURST_WINDOW_S": {
        "type": "int", "min": 10, "max": 600,
        "label": "UA burst window (seconds)",
        "desc": "Sliding window duration for UA impersonation burst detection.",
        "group": "Behavior",
    },
    "TLS_FP_SHARED_THRESHOLD": {
        "type": "int", "min": 2, "max": 50,
        "label": "Shared TLS fingerprint threshold",
        "desc": "Number of distinct IPs sharing a TLS/JA3 fingerprint before scoring.",
        "group": "Behavior",
    },
    "SLOW_LOW_MIN_HOURS": {
        "type": "float", "min": 0.25, "max": 48.0,
        "label": "Slow-and-low min active hours",
        "desc": "Minimum hours an IP must be active before the slow-and-low signal fires.",
        "group": "Behavior",
    },
    "SLOW_LOW_MIN_PATHS": {
        "type": "int", "min": 3, "max": 200,
        "label": "Slow-and-low min unique paths",
        "desc": "Minimum unique non-static paths visited before slow-and-low is considered.",
        "group": "Behavior",
    },
    # --- Botnet ---
    "BOTNET_WINDOW_S": {
        "type": "int", "min": 60, "max": 3600,
        "label": "Campaign detection window (seconds)",
        "desc": "Sliding time window used to group hits into a botnet campaign.",
        "group": "Botnet",
    },
    "BOTNET_CHECK_INTERVAL": {
        "type": "int", "min": 5, "max": 300,
        "label": "Campaign check interval (seconds)",
        "desc": "How often the botnet worker re-evaluates the hit buffer.",
        "group": "Botnet",
    },
    "BOTNET_MIN_IPS": {
        "type": "int", "min": 2, "max": 50,
        "label": "Campaign min distinct IPs",
        "desc": "Minimum distinct source IPs required to open a campaign.",
        "group": "Botnet",
    },
    "BOTNET_MIN_SUBNETS": {
        "type": "int", "min": 1, "max": 20,
        "label": "Campaign min distinct /24 subnets",
        "desc": "Minimum distinct /24 subnets required to open a campaign.",
        "group": "Botnet",
    },
    "BOTNET_MIN_ASNS": {
        "type": "int", "min": 1, "max": 20,
        "label": "Campaign min distinct ASNs",
        "desc": "Minimum distinct ASNs required to open a campaign.",
        "group": "Botnet",
    },
    "BOTNET_EXPIRY_S": {
        "type": "int", "min": 60, "max": 86400,
        "label": "Campaign expiry silence (seconds)",
        "desc": "Drop a campaign after this many seconds with no new hits.",
        "group": "Botnet",
    },
    # --- Enrichment ---
    "REPUTATION_ENRICH_THRESHOLD": {
        "type": "int", "min": 1, "max": 200,
        "label": "Auto-enrich score threshold",
        "desc": "Enqueue an IP for background reputation enrichment once its score reaches this.",
        "group": "Enrichment",
    },
    "REPUTATION_TTL": {
        "type": "int", "min": 60, "max": 86400,
        "label": "Reputation cache TTL (seconds)",
        "desc": "Minimum seconds before the same IP may be re-enriched.",
        "group": "Enrichment",
    },
    # --- History ---
    "HISTORY_RETENTION_DAYS": {
        "type": "int", "min": 1, "max": 365,
        "label": "History retention (days)",
        "desc": "How many days of local history to keep on disk.",
        "group": "History",
        "_derived": ["HISTORY_RETENTION_S"],
    },
    # --- Alerts ---
    "ALERT_QUEUE_MAX": {
        "type": "int", "min": 50, "max": 2000,
        "label": "Alert feed buffer size",
        "desc": "Maximum number of alerts held in the in-memory alert feed.",
        "group": "Alerts",
    },
}


def _path():
    if config.STATE_DIR:
        return os.path.join(config.STATE_DIR, "settings.json")
    return ""


def _coerce(key, raw):
    """Parse and validate raw value against schema. Returns coerced value or raises ValueError."""
    meta = SCHEMA.get(key)
    if not meta:
        raise ValueError(f"Unknown setting: {key}")
    t = meta["type"]
    if t == "int":
        v = int(raw)
        if v < meta["min"] or v > meta["max"]:
            raise ValueError(f"{key} must be {meta['min']}..{meta['max']}, got {v}")
        return v
    if t == "float":
        v = float(raw)
        if v < meta["min"] or v > meta["max"]:
            raise ValueError(f"{key} must be {meta['min']}..{meta['max']}, got {v}")
        return v
    if t == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on", "y")
    raise ValueError(f"Unknown type {t}")


def _apply(key, value):
    """Write value to config module, handling derived fields."""
    setattr(config, key, value)
    meta = SCHEMA.get(key, {})
    for derived in meta.get("_derived", []):
        if derived == "HISTORY_RETENTION_S":
            setattr(config, "HISTORY_RETENTION_S", max(1, value) * 86400)


def get_all():
    """Return list of dicts describing every setting and its current value."""
    groups = {}
    for key, meta in SCHEMA.items():
        current = getattr(config, key)
        entry = {
            "key":   key,
            "label": meta["label"],
            "desc":  meta["desc"],
            "group": meta["group"],
            "type":  meta["type"],
            "value": current,
            "default": _get_env_default(key),
        }
        if meta["type"] in ("int", "float"):
            entry["min"] = meta["min"]
            entry["max"] = meta["max"]
        groups.setdefault(meta["group"], []).append(entry)
    # Return as ordered list of {group, settings}
    order = ["Detection", "Behavior", "Botnet", "Enrichment", "History", "Alerts"]
    result = []
    for g in order:
        if g in groups:
            result.append({"group": g, "settings": groups[g]})
    return result


def _get_env_default(key):
    """Re-read the environment-variable default for a key (for 'reset' display)."""
    # We re-parse the env var to show what the original env value would be.
    # This is best-effort; some keys have no direct 1:1 env var.
    env_map = {
        "SCORE_ALERT_THRESHOLD":       None,   # no env var; hardcoded default is 5
        "PERSISTENT_THREAT_DAYS":      ("SENTINEL_PERSISTENT_DAYS", "3", int),
        "AUTH_FAIL_BAN_THRESHOLD":     ("SENTINEL_AUTH_FAIL_BAN", "10", int),
        "SENTINEL_EXPECT_CF":          ("SENTINEL_EXPECT_CF", "0", lambda v: v.lower() in ("1","true","yes")),
        "UA_BURST_THRESHOLD":          ("SENTINEL_UA_BURST_THRESHOLD", "20", int),
        "UA_BURST_WINDOW_S":           ("SENTINEL_UA_BURST_WINDOW_S", "60", int),
        "TLS_FP_SHARED_THRESHOLD":     ("SENTINEL_TLS_FP_THRESHOLD", "5", int),
        "SLOW_LOW_MIN_HOURS":          ("SENTINEL_SLOW_LOW_MIN_HOURS", "2", float),
        "SLOW_LOW_MIN_PATHS":          ("SENTINEL_SLOW_LOW_MIN_PATHS", "15", int),
        "BOTNET_WINDOW_S":             None,
        "BOTNET_CHECK_INTERVAL":       None,
        "BOTNET_MIN_IPS":              None,
        "BOTNET_MIN_SUBNETS":          None,
        "BOTNET_MIN_ASNS":             None,
        "BOTNET_EXPIRY_S":             None,
        "REPUTATION_ENRICH_THRESHOLD": ("SENTINEL_REPUTATION_THRESHOLD", "10", int),
        "REPUTATION_TTL":              ("SENTINEL_REPUTATION_TTL", "3600", int),
        "HISTORY_RETENTION_DAYS":      ("SENTINEL_HISTORY_RETENTION_DAYS", "30", int),
        "ALERT_QUEUE_MAX":             None,
    }
    spec = env_map.get(key)
    if spec is None:
        # Return the module-level default (what config.py hardcoded)
        defaults = {
            "SCORE_ALERT_THRESHOLD": 5,
            "BOTNET_WINDOW_S": 300, "BOTNET_CHECK_INTERVAL": 10,
            "BOTNET_MIN_IPS": 3, "BOTNET_MIN_SUBNETS": 2,
            "BOTNET_MIN_ASNS": 2, "BOTNET_EXPIRY_S": 1800,
            "ALERT_QUEUE_MAX": 200,
        }
        return defaults.get(key)
    env_key, default_str, coerce = spec
    raw = os.environ.get(env_key, default_str)
    try:
        return coerce(raw)
    except Exception:
        return None


def apply_one(key, raw_value):
    """
    Validate, coerce, apply, and persist one setting.
    Returns the coerced value.
    Raises ValueError on bad input.
    """
    value = _coerce(key, raw_value)
    with _lock:
        _overrides[key] = value
    _apply(key, value)
    _persist()
    return value


def reset_one(key):
    """Reset a single setting to its environment/default value."""
    default = _get_env_default(key)
    if default is None:
        return
    with _lock:
        _overrides.pop(key, None)
    _apply(key, default)
    _persist()


def reset_all():
    """Reset every setting to its environment/default value."""
    with _lock:
        _overrides.clear()
    for key in SCHEMA:
        default = _get_env_default(key)
        if default is not None:
            _apply(key, default)
    _persist()


def _persist():
    path = _path()
    if not path:
        return
    try:
        with _lock:
            data = dict(_overrides)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load():
    """Load persisted overrides from disk and apply them to config."""
    path = _path()
    if not path or not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for key, value in data.items():
            if key in SCHEMA:
                coerced = _coerce(key, value)
                with _lock:
                    _overrides[key] = coerced
                _apply(key, coerced)
    except Exception:
        pass
