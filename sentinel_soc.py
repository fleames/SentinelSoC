# ASCII-only source: valid UTF-8 on all platforms (avoids Windows-1252 byte 0x97 issues).
"""
Sentinel - SOC-oriented live log dashboard (Caddy JSON access log, local tail).
"""
import errno
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
def _effective_log_path():
    return os.environ.get("LOG_PATH", "/var/log/caddy/all-access.log").strip() or "/var/log/caddy/all-access.log"


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

rps_timeline = []
attack_timeline = []

geo_cache = {}
recent_alerts = deque(maxlen=ALERT_QUEUE_MAX)
geo_queue = deque()
geo_lock = threading.Lock()

# Requests seen before ip-api returns: fold into real ASN/country on resolve (no stuck "Resolving..." row).
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
        return
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
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
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,as,isp",
            timeout=2,
            allow_redirects=False,
        )
        r.raise_for_status()
        d = r.json()
        if d.get("status") != "success":
            raise ValueError(d.get("message", "ip-api lookup failed"))
        geo_cache[ip] = {
            "country": d.get("countryCode", "??"),
            "asn": f"{d.get('as', '?')} | {d.get('isp', '?')}",
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
# SCORING
# ========================
def score(ip, uri, ua, asn):
    s = 0
    if "cloudflare" in asn.lower():
        return 0
    u = uri.lower()
    if any(
        x in u
        for x in (
            ".env",
            ".git",
            "wp-admin",
            "xmlrpc",
            "phpmyadmin",
            "adminer",
            ".aws",
            "credentials",
            "shell",
            "eval-stdin",
            "boaform",
            "cgi-bin",
        )
    ):
        s += 10
    ul = ua.lower()
    if any(x in ul for x in ("bot", "curl", "python", "wget", "scanner", "nikto", "sqlmap")):
        s += 3
    if not ua or ua == "-":
        s += 2
    return s


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


def stream():
    global stream_started_at, total, current_second, attack_counter, client_err, server_err

    stream_started_at = time.time()
    log_path = _effective_log_path()
    from_start = _effective_log_from_start()
    print(
        f"[sentinel] log tail path={log_path!r} LOG_FROM_START={from_start}",
        file=sys.stderr,
        flush=True,
    )
    objects_seen = 0
    no_request = 0
    ingested = 0
    diag_issued = False
    try:
        for data in iter_caddy_log_objects(log_path, from_start=from_start):
            if not isinstance(data, dict):
                continue
            objects_seen += 1

            req, status = _parse_caddy_access_line(data)
            if not req:
                no_request += 1
                if no_request <= 2:
                    print(
                        f"[sentinel] skip non-access JSON object; sample keys={list(data.keys())[:25]}",
                        file=sys.stderr,
                        flush=True,
                    )
                continue
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
                continue

            ip = nip if nip is not None else ip_raw

            host = extract_request_host(req, headers)
            ref = _header_first(headers, "Referer", "referer") or "-"
            uri = req.get("uri", "/")
            ua = _header_first(headers, "User-Agent", "user-agent") or ""

            geo = get_geo(ip)
            asn = geo["asn"]
            country = geo.get("country", "??")

            s = score(ip, uri, ua, asn)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            with lock:
                total += 1
                current_second += 1

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

                ip_scores[ip] += s
                if s > 0:
                    attack_counter += 1

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
                        }
                    )

            if country_u == PLACEHOLDER_CC or asn_u == PLACEHOLDER_ASN:
                enqueue_geo(ip)

            ingested += 1
            if from_start and ingested > 0 and ingested % 25000 == 0:
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


def reset_dashboard_state():
    """Clear all counters, timelines, geo cache, and alerts. Log reader thread keeps running."""
    global rps, total, current_second, peak_rps, attack_counter, client_err, server_err, stream_started_at
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
        rps_timeline.clear()
        attack_timeline.clear()
        stream_started_at = time.time()
        muted_hits.clear()
        stream_parse_debug["text_lines"] = 0
        stream_parse_debug["json_roots"] = 0
        stream_parse_debug["dicts_yielded"] = 0
        stream_parse_debug["buffer_overflows"] = 0


# ========================
# API
# ========================
@app.before_request
def _sentinel_auth_gate():
    if not AUTH_ENABLED:
        return None
    if request.path == "/health":
        return None
    auth = request.authorization
    if not auth or auth.username != AUTH_USER or not _password_matches(auth.password, AUTH_PASSWORD):
        _audit_write("auth_failed", "anonymous", {"path": request.path, "method": request.method})
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
        uniq = len(ips)
        te = client_err + server_err
        err_rate = round(100.0 * te / total, 2) if total else 0.0
        top_ip_n = ips.most_common(1)
        top_share = round(100.0 * top_ip_n[0][1] / total, 1) if total and top_ip_n else 0.0
        attack_rps = attack_timeline[-1] if attack_timeline else 0
        level, level_color = threat_level_label(attack_rps, err_rate, top_share)

        top_threats = sorted(ip_scores.items(), key=lambda x: -x[1])[:20]
        threats_enriched = []
        for tip, sc in top_threats:
            if sc <= 0:
                continue
            g = ip_geo.get(tip, {})
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
        muted_total = int(sum(muted_hits.values()))
        banned_sorted = sorted(banned_ips)
        muted_dict = {k: int(muted_hits[k]) for k in banned_sorted}
        ip_tags_payload = {k: sorted(v) for k, v in ip_tags.items() if v}

        return jsonify(
            {
                "rps": rps,
                "peak": peak_rps,
                "total": total,
                "unique_ips": uniq,
                "client_errors": client_err,
                "server_errors": server_err,
                "error_rate_pct": err_rate,
                "threat_level": level,
                "threat_color": level_color,
                "attack_rps_last_tick": attack_rps,
                "stream_uptime_s": uptime_s,
                "ips": ips.most_common(15),
                "domains": domains.most_common(10),
                "referers": referers.most_common(10),
                "paths": paths.most_common(10),
                "status": dict(status_codes),
                "asn": asn_counts.most_common(10),
                "countries": countries.most_common(12),
                "scores": dict(ip_scores),
                "geo": ip_geo,
                "top_threats": threats_enriched,
                "alerts": alerts_list,
                "rps_timeline": rps_timeline,
                "attack_timeline": attack_timeline,
                "server_time": datetime.now(timezone.utc).isoformat(),
                "banned_ips": banned_sorted,
                "muted_hits": muted_dict,
                "muted_total": muted_total,
                "iptables_enabled": IPTABLES_ENABLED,
                "iptables_chain": IPTABLES_CHAIN,
                "auth_enabled": AUTH_ENABLED,
                "audit_log": bool(AUDIT_LOG_PATH),
                "audit_path": AUDIT_LOG_PATH,
                "state_dir": STATE_DIR,
                "ban_list_path": BAN_LIST_PATH,
                "log_path": _effective_log_path(),
                "log_from_start": _effective_log_from_start(),
                "stream_parse_debug": dict(stream_parse_debug),
                "ip_tags": ip_tags_payload,
            }
        )


@app.route("/api/reset", methods=["POST"])
def api_reset():
    reset_dashboard_state()
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
  --bg:#060a10; --surface:rgba(10,16,28,0.82); --surface-solid:#0a101c;
  --border:rgba(255,255,255,0.06); --border-bright:rgba(0,212,255,0.2);
  --muted:#4a5568; --text:#e2e8f0; --text-dim:#94a3b8;
  --accent:#00d4ff; --accent-glow:rgba(0,212,255,0.2); --accent-dim:rgba(0,212,255,0.07);
  --warn:#f59e0b; --warn-glow:rgba(245,158,11,0.2);
  --danger:#ef4444; --danger-glow:rgba(239,68,68,0.2);
  --ok:#22c55e; --ok-glow:rgba(34,197,94,0.2);
  --focus:#7c3aed;
  --mono:'JetBrains Mono',ui-monospace,monospace;
  --sans:'Inter',system-ui,sans-serif;
  --radius:10px; --transition:0.18s cubic-bezier(0.4,0,0.2,1);
}
*,*::before,*::after{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;}
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(rgba(0,212,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.025) 1px,transparent 1px);
  background-size:48px 48px;
  animation:gridDrift 24s linear infinite;
}
@keyframes gridDrift{from{background-position:0 0;}to{background-position:0 48px;}}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse at 50% 0%,transparent 40%,rgba(6,10,16,0.7) 100%);}
header,.toolbar,.kpi-row,.layout,footer,.modal-backdrop{position:relative;z-index:1;}
#postureStrip{position:fixed;top:0;left:0;right:0;height:2px;background:var(--ok);transition:background 0.6s,box-shadow 0.6s;z-index:200;box-shadow:0 0 12px var(--ok);}
/* Live dot */
@keyframes livePulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.5)}}
@keyframes sonarRing{0%{transform:scale(1);opacity:.6}100%{transform:scale(3.5);opacity:0}}
.live-dot{position:relative;width:8px;height:8px;border-radius:50%;background:var(--ok);flex-shrink:0;animation:livePulse 2s ease-in-out infinite;}
.live-dot::after{content:'';position:absolute;inset:0;border-radius:50%;background:var(--ok);animation:sonarRing 2s ease-out infinite;}
.live-dot.stale{background:var(--warn);animation-duration:3.5s;}
.live-dot.stale::after{background:var(--warn);}
/* Header */
header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;padding:14px 24px;margin-top:2px;background:rgba(6,10,16,0.92);border-bottom:1px solid var(--border);backdrop-filter:blur(20px);}
.brand{display:flex;align-items:center;gap:12px;}
.brand-logo{font-size:1.1rem;font-weight:700;letter-spacing:.14em;background:linear-gradient(90deg,#fff 0%,var(--accent) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.brand-sub{color:var(--muted);font-size:11px;margin-top:1px;}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:5px;font-weight:700;font-size:10px;letter-spacing:.1em;border:1px solid var(--border-bright);color:var(--accent);background:var(--accent-dim);font-family:var(--mono);}
.badge.frozen{border-color:rgba(245,158,11,0.3);color:var(--warn);background:rgba(245,158,11,0.07);}
/* DEFCON */
.posture-area{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.defcon-wrap{display:flex;flex-direction:column;align-items:center;gap:5px;}
.defcon-label{font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-family:var(--mono);}
.defcon-blocks{display:flex;gap:4px;}
.defcon-block{width:20px;height:34px;border-radius:4px;background:#0d1522;border:1px solid rgba(255,255,255,0.06);transition:background var(--transition),box-shadow var(--transition),border-color var(--transition);}
.defcon-block.lit{border-color:transparent;}
@keyframes defPulse{0%,100%{opacity:1}50%{opacity:.4}}
.defcon-block.blk-pulse{animation:defPulse 1s ease-in-out infinite;}
/* Toolbar */
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 24px;background:rgba(8,12,22,0.88);border-bottom:1px solid var(--border);backdrop-filter:blur(12px);}
.toolbar input[type="search"]{flex:1;min-width:180px;max-width:360px;padding:7px 12px;border-radius:7px;border:1px solid var(--border);background:rgba(255,255,255,0.04);color:var(--text);font-family:var(--mono);font-size:12px;transition:border-color var(--transition),box-shadow var(--transition);outline:none;}
.toolbar input[type="search"]:focus{border-color:var(--border-bright);box-shadow:0 0 0 3px var(--accent-dim);}
.toolbar-sep{width:1px;height:20px;background:var(--border);flex-shrink:0;}
.toolbtn{padding:6px 13px;border-radius:7px;border:1px solid var(--border);background:rgba(255,255,255,0.03);color:var(--text-dim);font-size:11px;font-family:var(--mono);cursor:pointer;white-space:nowrap;transition:border-color var(--transition),color var(--transition),box-shadow var(--transition),transform 0.1s;outline:none;}
.toolbtn:hover{border-color:var(--accent);color:var(--accent);box-shadow:0 0 10px var(--accent-glow);}
.toolbtn:active{transform:scale(0.96);}
.toolbtn.on{border-color:var(--accent);background:var(--accent-dim);color:var(--accent);}
.toolbtn.danger:hover{border-color:var(--danger);color:var(--danger);box-shadow:0 0 10px var(--danger-glow);}
.poll-seg{display:flex;border:1px solid var(--border);border-radius:7px;overflow:hidden;}
.poll-seg .poll-opt{border:none;border-radius:0;background:transparent;border-right:1px solid var(--border);padding:6px 11px;}
.poll-seg .poll-opt:last-child{border-right:none;}
.poll-seg .poll-opt.on{background:var(--accent-dim);color:var(--accent);box-shadow:none;}
.poll-seg .poll-opt:hover:not(.on){background:rgba(255,255,255,0.04);box-shadow:none;border-color:transparent;}
/* KPI row */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;padding:16px 24px;}
.kpi{background:var(--surface);border:1px solid var(--border);border-left:2px solid transparent;border-radius:var(--radius);padding:12px 14px;backdrop-filter:blur(12px);transition:border-left-color .5s,box-shadow .5s;}
.kpi.ok    {border-left-color:var(--ok);    box-shadow:0 0 22px rgba(34,197,94,0.08), inset 0 0 40px rgba(34,197,94,0.03);}
.kpi.warn  {border-left-color:var(--warn);  box-shadow:0 0 22px rgba(245,158,11,0.08),inset 0 0 40px rgba(245,158,11,0.03);}
.kpi.danger{border-left-color:var(--danger);box-shadow:0 0 22px rgba(239,68,68,0.08), inset 0 0 40px rgba(239,68,68,0.03);}
.kpi-hd{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;}
.kpi .label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;font-weight:500;}
.kpi .val{font-family:var(--mono);font-size:1.4rem;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.01em;}
.kpi.ok .val    {text-shadow:0 0 16px rgba(34,197,94,0.4);}
.kpi.warn .val  {text-shadow:0 0 16px rgba(245,158,11,0.4);}
.kpi.danger .val{text-shadow:0 0 16px rgba(239,68,68,0.4);}
.delta{font-size:9px;font-family:var(--mono);padding:2px 5px;border-radius:4px;font-weight:700;flex-shrink:0;}
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
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:14px;overflow:hidden;backdrop-filter:blur(12px);box-shadow:0 4px 24px rgba(0,0,0,0.35),inset 0 1px 0 rgba(0,212,255,0.05);}
.card h2{margin:0;padding:11px 14px;font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);border-bottom:1px solid var(--border);font-weight:600;background:rgba(0,0,0,0.15);}
.card .hint{font-weight:400;text-transform:none;letter-spacing:0;color:#334155;margin-left:8px;}
.card .body{padding:8px 10px;max-height:290px;overflow:auto;}
.card .body::-webkit-scrollbar{width:4px;}
.card .body::-webkit-scrollbar-track{background:transparent;}
.card .body::-webkit-scrollbar-thumb{background:#1e293b;border-radius:2px;}
/* List rows */
.row{display:flex;justify-content:space-between;gap:10px;padding:7px 8px;border-bottom:1px solid rgba(255,255,255,0.03);font-family:var(--mono);font-size:12px;border-radius:6px;margin:0 -2px 1px;transition:background var(--transition),transform var(--transition);cursor:default;}
.row:last-child{border-bottom:none;}
.row .k{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;color:#cbd5e1;}
.row.row-ip .k{white-space:normal;display:flex;flex-wrap:wrap;align-items:center;gap:4px;min-width:0;}
.row .v{color:var(--accent);flex-shrink:0;font-weight:600;}
.row.danger .k{color:var(--danger);}
.row:hover{background:rgba(255,255,255,0.03);transform:translateX(3px);}
.row.row-ip{cursor:pointer;}
.row.row-ip:hover{background:rgba(0,212,255,0.04);}
.row.row-ip:active{background:rgba(0,212,255,0.08);}
.row.hl-focus{box-shadow:inset 0 0 0 1px rgba(124,58,237,0.5);background:rgba(124,58,237,0.07);}
/* Tags */
.tag{font-size:9px;text-transform:uppercase;letter-spacing:.06em;padding:1px 5px;border-radius:3px;font-weight:600;flex-shrink:0;font-family:var(--sans);}
.tag-bot    {background:rgba(12,39,68,0.8);  color:#7dd3fc;border:1px solid rgba(30,73,118,0.6);}
.tag-crawler{background:rgba(42,31,61,0.8);  color:#d8b4fe;border:1px solid rgba(76,29,149,0.5);}
/* Charts */
.charts-dual{display:grid;grid-template-columns:1fr 190px;gap:12px;}
@media(max-width:900px){.charts-dual{grid-template-columns:1fr;}}
.chart-wrap{padding:12px;height:210px;position:relative;}
/* World map */
#worldMapWrap{padding:8px 10px;height:310px;position:relative;}
.jvm-tooltip{background:var(--surface-solid) !important;border:1px solid var(--border-bright) !important;color:var(--text) !important;font-family:var(--mono) !important;font-size:11px !important;padding:5px 10px !important;border-radius:6px !important;box-shadow:0 4px 20px rgba(0,0,0,0.5) !important;}
/* Alert feed */
.alert-row{border-left:3px solid var(--danger);padding:9px 10px;margin-bottom:7px;background:rgba(6,10,16,0.6);border-radius:6px;font-size:11px;font-family:var(--mono);cursor:pointer;transition:background var(--transition),box-shadow var(--transition);box-shadow:-3px 0 10px rgba(239,68,68,0.15);}
.alert-row:hover{background:rgba(255,255,255,0.03);}
.alert-row.sev-med{border-left-width:4px;border-left-color:#f97316;box-shadow:-4px 0 12px rgba(249,115,22,0.2);}
.alert-row.sev-hi {border-left-width:5px;border-left-color:#dc2626;box-shadow:-5px 0 16px rgba(220,38,38,0.3);}
.alert-row.hl-focus{border-left-color:var(--focus);box-shadow:-3px 0 12px rgba(124,58,237,0.3);}
.alert-hd{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:5px;}
.alert-time{color:var(--muted);font-size:10px;margin-left:auto;flex-shrink:0;}
.score-pill{display:inline-flex;align-items:center;justify-content:center;min-width:28px;height:17px;border-radius:9px;font-size:9px;font-family:var(--mono);font-weight:700;padding:0 6px;flex-shrink:0;}
.score-pill.lo {background:rgba(12,39,68,0.8); color:#7dd3fc;border:1px solid rgba(30,73,118,0.6);}
.score-pill.med{background:rgba(49,32,8,0.8);  color:#fbbf24;border:1px solid rgba(120,53,15,0.6);}
.score-pill.hi {background:rgba(45,10,10,0.8); color:#f87171;border:1px solid rgba(127,29,29,0.6);}
.alert-row .uri{color:#f87171;word-break:break-all;}
.alert-row .ua {color:var(--muted);font-size:10px;margin-top:4px;}
@keyframes newFlash{0%{opacity:1;transform:scale(1.1)}100%{opacity:0;transform:scale(1)}}
.new-badge{font-size:8px;font-family:var(--mono);font-weight:700;letter-spacing:.1em;padding:1px 5px;border-radius:3px;background:var(--accent-dim);color:var(--accent);border:1px solid var(--border-bright);animation:newFlash 3s ease-out forwards;}
/* Threat board */
.th-grid{display:grid;grid-template-columns:22px 1fr 72px 54px 34px;gap:6px;padding:7px 10px;font-size:10px;font-family:var(--mono);color:var(--muted);border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.06em;}
.th-row{display:grid;grid-template-columns:22px 1fr 72px 54px 34px;gap:6px;padding:7px 10px;font-family:var(--mono);font-size:11px;border-bottom:1px solid rgba(255,255,255,0.03);align-items:center;cursor:pointer;border-radius:5px;margin:0 2px;transition:background var(--transition),transform var(--transition);}
.th-row:hover{background:rgba(0,212,255,0.04);transform:translateX(2px);}
.th-row.rank1{box-shadow:inset 0 0 0 1px rgba(239,68,68,0.25);}
.th-row.hl-focus{box-shadow:inset 0 0 0 1px rgba(124,58,237,0.4);}
.th-row .rank{color:var(--muted);font-size:10px;text-align:center;}
.th-row .rank.r1{color:var(--danger);}
.th-row .ip{color:var(--accent);overflow:hidden;min-width:0;display:flex;flex-wrap:wrap;align-items:center;gap:3px;}
.th-row .hits{text-align:right;color:var(--text-dim);}
.th-row .cc{text-align:center;}
.sc-segs{display:flex;gap:2px;align-items:center;justify-content:flex-end;}
.sc-seg{width:8px;height:14px;border-radius:2px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.06);transition:background var(--transition),box-shadow var(--transition);}
.sc-seg.lit{border-color:transparent;}
.sc-num{font-size:10px;color:var(--warn);min-width:22px;text-align:right;font-weight:700;}
/* Modal */
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;align-items:flex-start;justify-content:center;padding:20px;overflow:auto;backdrop-filter:blur(6px);}
.modal-backdrop.open{display:flex;}
@keyframes modalIn{from{opacity:0;transform:translateY(22px) scale(0.97);}to{opacity:1;transform:none;}}
.modal{width:100%;max-width:680px;background:#080d18;border:1px solid var(--border-bright);border-radius:16px;box-shadow:0 32px 80px rgba(0,0,0,.7),0 0 60px rgba(0,212,255,0.06);margin:auto;animation:modalIn .22s cubic-bezier(0.4,0,0.2,1);overflow:hidden;}
/* Header banner */
.modal-banner{padding:20px 22px 16px;position:relative;overflow:hidden;border-bottom:1px solid var(--border);}
.modal-banner::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,212,255,0.07) 0%,transparent 60%);pointer-events:none;}
.modal-banner-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:12px;}
.modal-ip-line{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.modal-flag{font-size:26px;line-height:1;-webkit-text-fill-color:initial;}
.modal-ip{font-family:var(--mono);font-size:1.25rem;font-weight:700;color:var(--accent);letter-spacing:-.01em;text-shadow:0 0 20px rgba(0,212,255,0.4);}
.modal-cc-pill{font-size:10px;font-family:var(--mono);font-weight:700;letter-spacing:.1em;padding:2px 8px;border-radius:4px;background:rgba(0,212,255,0.1);color:var(--accent);border:1px solid var(--border-bright);}
.modal-actions{display:flex;gap:6px;flex-wrap:wrap;flex-shrink:0;}
/* Stat strip */
.modal-stats{display:flex;gap:0;border:1px solid var(--border);border-radius:9px;overflow:hidden;background:rgba(0,0,0,0.3);}
.modal-stat{flex:1;padding:8px 14px;border-right:1px solid var(--border);min-width:0;}
.modal-stat:last-child{border-right:none;}
.modal-stat-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:3px;font-weight:500;}
.modal-stat-val{font-family:var(--mono);font-size:1rem;font-weight:700;font-variant-numeric:tabular-nums;color:var(--text);}
.modal-stat-val.hi{color:var(--danger);text-shadow:0 0 10px rgba(239,68,68,0.5);}
.modal-stat-val.med{color:var(--warn);text-shadow:0 0 10px rgba(245,158,11,0.5);}
.modal-stat-val.ok{color:var(--ok);text-shadow:0 0 10px rgba(34,197,94,0.5);}
/* Geo strip */
.modal-geo-strip{display:flex;gap:24px;flex-wrap:wrap;padding:14px 22px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.2);}
.modal-geo-item{display:flex;flex-direction:column;gap:2px;min-width:0;}
.geo-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);font-weight:500;}
.geo-val{font-family:var(--mono);font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
/* Tags row */
.modal-tags{display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:10px 22px;border-bottom:1px solid var(--border);min-height:40px;}
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
/* Muted IPs */
.ban-inp{flex:1;min-width:0;padding:7px 11px;border-radius:7px;border:1px solid var(--border);background:rgba(255,255,255,0.04);color:var(--text);font-family:var(--mono);font-size:12px;outline:none;transition:border-color var(--transition),box-shadow var(--transition);}
.ban-inp:focus{border-color:var(--border-bright);box-shadow:0 0 0 3px var(--accent-dim);}
.ban-actions{display:flex;gap:8px;margin-bottom:10px;align-items:stretch;}
.ban-row{display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid rgba(255,255,255,0.03);font-family:var(--mono);font-size:11px;}
.ban-row .kip{flex:1;overflow:hidden;text-overflow:ellipsis;color:#cbd5e1;}
.ban-row .cnt{color:var(--warn);flex-shrink:0;}
footer{padding:8px 24px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);font-family:var(--mono);position:relative;z-index:1;}
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
      <h2>Origin countries &mdash; world map</h2>
      <div id="worldMapWrap"><div id="worldMap" style="width:100%;height:100%"></div></div>
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
let seenAlertKeys=new Set();
let modalIp='';

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
const comboChart=new Chart(document.getElementById('comboChart'),{
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
});

const statusDonut=new Chart(document.getElementById('statusDonut'),{
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
});

// ── World map ──
function initWorldMap(){
  if(worldMap||typeof jsVectorMap==='undefined') return;
  try{
    worldMap=new jsVectorMap({
      selector:'#worldMap',map:'world',
      backgroundColor:'transparent',zoomOnScroll:false,
      regionStyle:{
        initial:{fill:'#0d1522',stroke:'#06080f',strokeWidth:0.4},
        hover:{fill:'#1e293b',cursor:'pointer'}
      },
      onRegionTooltipShow:function(e,tooltip,code){
        if(!lastPayload) return;
        var pair=(lastPayload.countries||[]).find(function(p){return p[0]===code;});
        tooltip.text(code+(pair?' \u2014 '+pair[1]+' req':''),true);
      },
      series:{regions:[{
        attribute:'fill',
        scale:{min:'#0a2a44',max:'#00d4ff'},
        normalizeFunction:'polynomial',
        values:{}
      }]}
    });
  }catch(e){
    document.getElementById('worldMapWrap').innerHTML='<div style="color:var(--muted);text-align:center;padding:80px 0;font-family:var(--mono);font-size:12px">Map unavailable (CDN)</div>';
  }
}
function updateWorldMap(countries){
  if(!worldMap) return;
  try{
    var vals={};
    (countries||[]).forEach(function(p){vals[p[0]]=p[1];});
    worldMap.series.regions[0].setValues(vals);
  }catch(e){}
}

/* Helpers */
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

function row(k,v,danger,ipClick,tags){
  var d=danger?' danger':'';
  var ip=(ipClick&&k)?' row-ip':'';
  var hl=(focusIp&&String(k)===focusIp)?' hl-focus':'';
  var dataIp=ipClick?' data-ip="'+escapeAttr(k)+'"':'';
  var pills=(ipClick&&tags&&tags.length)
    ? ' '+tags.map(function(t){ return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>'; }).join('')
    : '';
  return '<div class="row'+d+ip+hl+'"'+dataIp+'><span class="k" title="'+escapeAttr(k)+'">'+escapeHtml(k)+pills+'</span><span class="v">'+v+'</span></div>';
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
  var html='';
  pf.forEach(function(p){ var tags=(tagMap&&tagMap[p[0]])||[]; html+=row(p[0],p[1],false,true,tags); });
  el.innerHTML=html||'<div class="row"><span class="k">No matches</span></div>';
}
function renderList(el,data,flag,ipCol){
  var q=document.getElementById('q').value;
  var pairs=filterPairs(data,q);
  var html='';
  pairs.forEach(function(p){ html+=row(p[0],p[1],flag&&p[1]>100,ipCol); });
  el.innerHTML=html||'<div class="row"><span class="k">No matches</span></div>';
}
function renderStatus(el,obj){
  var q=document.getElementById('q').value;
  var keys=Object.keys(obj||{}).sort(function(a,b){ return obj[b]-obj[a]; });
  if(q&&q.trim()){ var t=q.toLowerCase(); keys=keys.filter(function(k){ return String(k).toLowerCase().includes(t); }); }
  var html='';
  keys.slice(0,20).forEach(function(k){
    var n=obj[k];
    html+=row(k+'',n,parseInt(k,10)>=400,false);
  });
  el.innerHTML=html||'<div class="row"><span class="k">No matches</span></div>';
}

function renderAlerts(el,alerts){
  var q=document.getElementById('q').value;
  var arr=alerts||[];
  if(focusIp) arr=arr.filter(function(a){return a.ip===focusIp;});
  if(q&&q.trim()){var t=q.toLowerCase();arr=arr.filter(function(a){return String(a.ip+a.uri+(a.asn||'')+(a.country||'')+(a.tags||[]).join(' ')).toLowerCase().includes(t);});}
  if(!arr.length){el.innerHTML='<div class="row"><span class="k" style="color:var(--muted)">'+(focusIp?'No alerts for focus IP':'No alerts in buffer')+'</span></div>';return;}
  el.innerHTML=arr.map(function(a){
    var hl=(focusIp&&a.ip===focusIp)?' hl-focus':'';
    var sc=a.score||0,sevCls=sc>=10?' sev-hi':sc>=5?' sev-med':'',pillCls=scorePillCls(sc);
    var ap=(a.tags&&a.tags.length)?' '+a.tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join(''):'';
    var flag=ccFlag(a.country||'');
    var key=a.ip+'|'+a.ts,isNew=!seenAlertKeys.has(key);
    seenAlertKeys.add(key);
    return '<div class="alert-row'+hl+sevCls+'" data-ip="'+escapeAttr(a.ip)+'">'
      +'<div class="alert-hd"><span class="score-pill '+pillCls+'">+'+sc+'</span>'
      +'<span style="color:#f87171;text-shadow:0 0 8px rgba(248,113,113,0.5)">'+escapeHtml(a.ip)+'</span>'
      +(flag?'<span style="font-size:14px">'+flag+'</span>':'')
      +'<span style="color:var(--muted);font-size:10px">'+escapeHtml(a.country||'?')+'</span>'
      +ap+(isNew?'<span class="new-badge">NEW</span>':'')
      +'<span class="alert-time">'+timeAgo(a.ts)+'</span></div>'
      +'<div class="uri">'+escapeHtml(a.uri)+'</div>'
      +'<div class="ua">'+escapeHtml(a.asn||'')+(a.ua?' \u2022 '+escapeHtml(a.ua):'')+'</div>'
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

function renderBanList(d){
  var el=document.getElementById('banList');
  var bans=d.banned_ips||[];
  var mh=d.muted_hits||{};
  if(!bans.length){ el.innerHTML='<div class="row"><span class="k">No muted IPs</span></div>'; return; }
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
  document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--muted);font-family:var(--mono);font-size:12px;text-align:center">Loading\u2026</div>';
  document.getElementById('modalBg').classList.add('open');
  try{
    var res=await fetch('/api/ip?ip='+encodeURIComponent(ip),{credentials:'same-origin'});
    var j=await res.json();
    if(!res.ok){
      document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center">'+escapeHtml(j.error||'Error')+'</div>';
      return;
    }
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
  }catch(e){
    document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center">Request failed</div>';
  }
}

function setFocus(ip){
  focusIp=ip||'';
  document.getElementById('focusLbl').innerText=focusIp?('[focus: '+focusIp+']'):'';
  document.getElementById('btnClearFocus').style.display=focusIp?'inline-block':'none';
  if(lastPayload) applyRender(lastPayload);
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
  statusDonut.data.datasets[0].data=statusBuckets(d.status);
  statusDonut.update('none');

  applyRender(d);
  renderBanList(d);

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
  document.getElementById('foot').innerText='Server '+d.server_time+up+' | poll '+poll+au;
  initWorldMap();
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
document.getElementById('btnExport').addEventListener('click',exportJson);
document.getElementById('btnClearFocus').addEventListener('click',function(){ setFocus(''); });

function warnIptables(j){
  if(j&&j.iptables&&j.iptables.enabled&&!j.iptables.ok){ alert('iptables: '+(j.iptables.error||'failed')); }
}
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
    setPaused(false); await load(true);
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
  window.open('http://ip-api.com/json/'+encodeURIComponent(modalIp),'_blank','noopener');
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
  if(ipRow&&ipRow.dataset.ip){ setFocus(ipRow.dataset.ip); openIpModal(ipRow.dataset.ip); return; }
  var th=e.target.closest('.th-row[data-ip]');
  if(th&&th.dataset.ip){ setFocus(th.dataset.ip); openIpModal(th.dataset.ip); return; }
  var ar=e.target.closest('.alert-row');
  if(ar&&ar.dataset.ip){ setFocus(ar.dataset.ip); openIpModal(ar.dataset.ip); return; }
});

document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){ closeModal(); return; }
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); document.getElementById('q').focus(); }
});

setPoll(1500);
load();
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

if __name__ == "__main__":
    _sync_iptables_bans()
    for _ in range(GEO_WORKERS):
        threading.Thread(target=geo_worker, daemon=True).start()
    threading.Thread(target=stream, daemon=True).start()
    threading.Thread(target=reset, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
