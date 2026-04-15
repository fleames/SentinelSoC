# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/state.py -- All shared mutable state objects.
Imports only sentinel.config and stdlib.
"""
import threading
from collections import Counter, defaultdict, deque

from sentinel import config

# ========================
# COUNTERS (replaces bare scalar globals)
# ========================
counters = {
    "rps": 0,
    "total": 0,
    "current_second": 0,
    "peak_rps": 0,
    "attack_counter": 0,
    "client_err": 0,
    "server_err": 0,
    "bytes_served": 0,
    "stream_started_at": None,
}

# ========================
# DATA STRUCTURES
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
ip_hosts = defaultdict(set)   # ip -> set of virtual hosts seen
asn_ips = defaultdict(set)

rps_timeline = []
attack_timeline = []

geo_cache = {}
recent_alerts = deque(maxlen=config.ALERT_QUEUE_MAX)
geo_queue = deque()
geo_lock = threading.Lock()

# Requests seen before ipinfo returns: fold into real ASN/country on resolve.
pending_geo_hits = defaultdict(int)

lock = threading.Lock()
audit_lock = threading.Lock()

# Tail thread only; exposed in /data for debugging parse path vs dashboard total.
stream_parse_debug = {
    "text_lines": 0,
    "json_roots": 0,
    "dicts_yielded": 0,
    "buffer_overflows": 0,
}

# Manual "mute": excluded from dashboard stats.
banned_ips = set()
muted_hits = Counter()

# Botnet campaign tracking
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
        "no_ref_hits": 0,
    }
)
ip_recent_paths = defaultdict(lambda: deque(maxlen=4))
ip_days_seen = defaultdict(set)   # ip -> set of "YYYY-MM-DD" UTC day strings
auth_fail_counts = Counter()      # ip -> consecutive auth failures (cleared on ban)
ipenrich_cache   = {}             # ip -> Shodan InternetDB result cached 1h
ipinfo_cache     = {}             # ip -> ipinfo.io result cached 1h
abuseipdb_cache  = {}             # ip -> AbuseIPDB result cached 1h
sources = Counter()               # source label -> total events ingested
ssh_ips = Counter()               # ip -> SSH auth failure hit count (separate from HTTP ips)
ssh_total = 0                     # total SSH auth failure events ingested
ssh_usernames = Counter()         # username -> total attempts across all IPs
ssh_ip_users = defaultdict(Counter)  # ip -> username -> attempt count
ssh_countries = Counter()         # country -> SSH hit count
ssh_asns = Counter()              # ASN -> SSH hit count
ssh_timeline = []                 # list of per-tick SSH event counts (last 180 ticks)
ssh_recent_alerts = deque(maxlen=config.ALERT_QUEUE_MAX)   # SSH-only alert feed
ssh_history_events = deque(maxlen=500)                     # SSH recent events for history table
ssh_ip_auth_methods = defaultdict(Counter)  # ip -> Counter(password=N, publickey=M, scanner=K)
ssh_auth_method_totals = Counter()          # global totals: password / publickey / scanner
ssh_ip_wordlist_fp = {}                     # ip -> 16-char hex fingerprint of credential set
ssh_wordlist_campaigns = defaultdict(set)   # fingerprint -> set(ips) using same credential list
ssh_key_fps = Counter()                     # "RSA SHA256:xxx" -> total attempts (LogLevel VERBOSE)
ssh_ip_key_fps = defaultdict(set)           # ip -> set of SSH public key fingerprints tried
ssh_key_fp_ips = defaultdict(set)           # key_fp -> set of IPs using that key
ssh_actor_labels = {}                       # actor_id ("wordlist:fp" | "key:fp" | "kex:fp") -> user label
# SSH KEX / cipher-suite fingerprint (LogLevel VERBOSE kex: lines)
ssh_kex_fps = Counter()                     # kex_fp -> total occurrences across all IPs
ssh_ip_kex_fp = {}                          # ip -> most recent 16-char kex fingerprint
ssh_kex_fp_ips = defaultdict(set)           # kex_fp -> set of IPs sharing that cipher/KEX suite
# SSH source-port entropy
ssh_ip_src_ports = defaultdict(lambda: deque(maxlen=200))  # ip -> recent source ports (capped)
ssh_ip_port_entropy = {}                    # ip -> Shannon entropy in bits (updated per 10 new ports)
ip_notes = {}                               # ip -> freeform analyst note (persisted, not cleared on reset)
ip_categories = {}                          # ip -> category string e.g. "botnet", "scanner", "apt", custom
behavior_signal_counts = Counter()
history_buckets = {}
history_lock = threading.Lock()

# TLS / JA3 fingerprint correlation
tls_fp_to_ips = defaultdict(set)   # fingerprint string -> set of IPs that used it
ip_tls_fp = {}                     # ip -> most recent TLS fingerprint value

# UA impersonation burst: per-UA sliding 60-second window
ua_burst_window = {}               # ua_norm -> {"ts_start": float, "ips": set}

# Async reputation enrichment queue
reputation_queue = deque()
reputation_seen = {}               # ip -> last_enriched_ts (throttle re-enrichment)
reputation_lock = threading.Lock()
greynoise_cache = {}               # ip -> GreyNoise result + "ts"
