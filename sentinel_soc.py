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
            f"http://ip-api.com/json/{ip}?fields=countryCode,as,isp",
            timeout=2,
        )
        d = r.json()
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
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg:#070b12; --panel:#0d1320; --border:#1e293b; --muted:#64748b;
  --text:#e2e8f0; --accent:#38bdf8; --warn:#f59e0b; --danger:#ef4444; --ok:#22c55e;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: system-ui, Segoe UI, Roboto, sans-serif;
  --focus:#7c3aed;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); font-size:13px; }
header {
  display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;
  padding:12px 20px; border-bottom:1px solid var(--border);
  background:linear-gradient(180deg,#0a1020 0%,var(--bg) 100%);
}
header h1 { margin:0; font-size:1.05rem; font-weight:600; letter-spacing:.04em; }
header .sub { color:var(--muted); font-size:12px; margin-top:2px; }
.badge {
  display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:6px;
  font-weight:700; font-size:11px; letter-spacing:.08em;
  border:1px solid var(--border); font-family:var(--mono);
}
.toolbar {
  display:flex; flex-wrap:wrap; align-items:center; gap:8px; padding:10px 20px;
  background:#080c14; border-bottom:1px solid var(--border);
}
.toolbar input[type="search"] {
  flex:1; min-width:180px; max-width:420px; padding:8px 10px; border-radius:6px;
  border:1px solid var(--border); background:#0d1320; color:var(--text); font-family:var(--mono); font-size:12px;
}
.toolbtn {
  padding:6px 12px; border-radius:6px; border:1px solid var(--border); background:#111827;
  color:var(--text); font-size:11px; font-family:var(--mono); cursor:pointer;
}
.toolbtn:hover { border-color:var(--accent); color:var(--accent); }
.toolbtn.on { border-color:var(--accent); background:#0c1929; color:var(--accent); }
.toolbtn.danger:hover { border-color:var(--danger); color:var(--danger); }
.kpi-row {
  display:grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr)); gap:10px;
  padding:14px 20px;
}
.kpi {
  background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 12px;
}
.kpi .label { color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:.1em; }
.kpi .val { font-family:var(--mono); font-size:1.35rem; margin-top:4px; }
.layout {
  display:grid; grid-template-columns: 1fr 400px; gap:14px; padding:0 20px 20px;
  max-width:1680px; margin:0 auto;
}
@media (max-width:1100px) { .layout { grid-template-columns:1fr; } }
.card {
  background:var(--panel); border:1px solid var(--border); border-radius:10px; margin-bottom:14px;
  overflow:hidden;
}
.card h2 {
  margin:0; padding:10px 12px; font-size:11px; text-transform:uppercase; letter-spacing:.12em;
  color:var(--muted); border-bottom:1px solid var(--border); font-weight:600;
}
.card .hint { font-weight:400; text-transform:none; letter-spacing:0; color:#475569; margin-left:8px; }
.card .body { padding:8px 10px; max-height:280px; overflow:auto; }
.row {
  display:flex; justify-content:space-between; gap:10px; padding:6px 4px;
  border-bottom:1px solid #111827; font-family:var(--mono); font-size:12px;
  cursor:default; border-radius:4px; margin:0 -2px; padding-left:6px; padding-right:6px;
}
.row:last-child { border-bottom:none; }
.row .k { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; color:#cbd5e1; }
.row.row-ip .k { white-space:normal; display:flex; flex-wrap:wrap; align-items:center; gap:4px; min-width:0; }
.tag {
  font-size:9px; text-transform:uppercase; letter-spacing:.06em; padding:2px 5px; border-radius:3px;
  font-weight:600; flex-shrink:0; font-family:var(--sans);
}
.tag-bot { background:#0c2744; color:#7dd3fc; border:1px solid #1e4976; }
.tag-crawler { background:#2a1f3d; color:#d8b4fe; border:1px solid #4c1d95; }
.row .v { color:var(--accent); flex-shrink:0; }
.row.danger .k { color:var(--danger); }
.row.row-ip { cursor:pointer; }
.row.row-ip:hover { background:#111827; }
.row.row-ip:active { background:#1e293b; }
.row.hl-focus { box-shadow:inset 0 0 0 1px var(--focus); background:#13081f; }
.charts { display:grid; grid-template-columns:1fr 1fr 220px; gap:10px; }
@media (max-width:900px) { .charts { grid-template-columns:1fr; } }
.chart-wrap { padding:10px; height:200px; position:relative; }
.chart-wrap.sm { height:200px; }
.alert-row {
  border-left:3px solid var(--danger); padding:8px 10px; margin-bottom:8px;
  background:#0c0f18; border-radius:4px; font-size:11px; font-family:var(--mono);
  cursor:pointer;
}
.alert-row:hover { background:#121722; }
.alert-row.hl-focus { border-left-color:var(--focus); box-shadow:inset 3px 0 0 var(--focus); }
.alert-row .meta { color:var(--muted); margin-bottom:4px; }
.alert-row .uri { color:#f87171; word-break:break-all; }
.th-grid { display:grid; grid-template-columns: 1fr 48px 56px 40px; gap:6px;
  padding:6px 8px; font-size:11px; font-family:var(--mono); color:var(--muted);
  border-bottom:1px solid var(--border); text-transform:uppercase; letter-spacing:.06em;
}
.th-row {
  display:grid; grid-template-columns: 1fr 48px 56px 40px; gap:6px;
  padding:6px 8px; font-family:var(--mono); font-size:11px; border-bottom:1px solid #111827;
  align-items:start; cursor:pointer; border-radius:4px; margin:0 2px;
}
.th-row:hover { background:#111827; }
.th-row.hl-focus { box-shadow:inset 0 0 0 1px var(--focus); }
.th-row .ip { color:var(--accent); overflow:hidden; min-width:0; display:flex; flex-wrap:wrap; align-items:center; gap:4px; }
.th-row .sc { color:var(--warn); text-align:right; }
.th-row .hits { text-align:right; color:#94a3b8; }
.th-row .cc { text-align:center; }
.modal-backdrop {
  display:none; position:fixed; inset:0; background:rgba(0,0,0,.65); z-index:100;
  align-items:flex-start; justify-content:center; padding:24px; overflow:auto;
}
.modal-backdrop.open { display:flex; }
.modal {
  width:100%; max-width:640px; background:var(--panel); border:1px solid var(--border);
  border-radius:12px; box-shadow:0 20px 50px rgba(0,0,0,.5); margin:auto;
}
.modal-hd {
  display:flex; align-items:center; justify-content:space-between; gap:10px;
  padding:12px 16px; border-bottom:1px solid var(--border);
}
.modal-hd h3 { margin:0; font-size:14px; font-family:var(--mono); }
.modal-bd { padding:12px 16px 16px; max-height:70vh; overflow:auto; }
.modal-meta { font-family:var(--mono); font-size:11px; color:var(--muted); margin-bottom:12px; line-height:1.5; }
.path-table { width:100%; border-collapse:collapse; font-family:var(--mono); font-size:11px; }
.path-table th, .path-table td { text-align:left; padding:6px 8px; border-bottom:1px solid #1e293b; }
.path-table th { color:var(--muted); font-weight:600; }
.path-table td:last-child { text-align:right; color:var(--accent); }
footer { padding:8px 20px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); }
kbd { font-family:var(--mono); font-size:10px; padding:2px 5px; border:1px solid var(--border); border-radius:4px; background:#111827; }
.ban-inp {
  flex:1; min-width:0; padding:8px 10px; border-radius:6px; border:1px solid var(--border);
  background:#0d1320; color:var(--text); font-family:var(--mono); font-size:12px;
}
.ban-row { display:flex; align-items:center; gap:8px; padding:6px 4px; border-bottom:1px solid #111827; font-family:var(--mono); font-size:11px; }
.ban-row .kip { flex:1; overflow:hidden; text-overflow:ellipsis; color:#cbd5e1; }
.ban-row .cnt { color:var(--warn); flex-shrink:0; }
.ban-actions { display:flex; gap:6px; margin-bottom:10px; align-items:stretch; }
</style>
</head>
<body>
<header>
  <div>
    <h1>SENTINEL</h1>
    <div class="sub">Live Caddy access telemetry | correlation view</div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
    <span class="badge" id="freezeBadge" style="display:none">FROZEN</span>
    <span class="badge" id="authBadge" style="display:none" title="HTTP Basic Auth enabled">AUTH</span>
    <span class="badge" id="lvl">POSTURE: -</span>
  </div>
</header>

<div class="toolbar">
  <input type="search" id="q" placeholder="Filter lists (paths, ASN, IP...)" autocomplete="off"/>
  <button type="button" class="toolbtn" id="btnPause" title="Pause polling">Pause</button>
  <span style="color:var(--muted);font-size:11px;">Poll:</span>
  <button type="button" class="toolbtn poll-opt" data-ms="1000">1s</button>
  <button type="button" class="toolbtn poll-opt on" data-ms="1500">1.5s</button>
  <button type="button" class="toolbtn poll-opt" data-ms="3000">3s</button>
  <button type="button" class="toolbtn poll-opt" data-ms="5000">5s</button>
  <button type="button" class="toolbtn" id="btnExport" title="Download last /data JSON">Export JSON</button>
  <button type="button" class="toolbtn danger" id="btnClearFocus" title="Clear IP focus">Clear focus</button>
  <button type="button" class="toolbtn danger" id="btnReset" title="Clear all metrics (tail keeps running)">Reset dashboard</button>
  <span style="color:var(--muted);font-size:11px;font-family:var(--mono);"><kbd>/</kbd> search <kbd>Esc</kbd> close</span>
</div>

<div class="kpi-row">
  <div class="kpi"><div class="label">Requests / sec</div><div class="val" id="rps">0</div></div>
  <div class="kpi"><div class="label">Peak RPS</div><div class="val" id="peak">0</div></div>
  <div class="kpi"><div class="label">Total events</div><div class="val" id="total">0</div></div>
  <div class="kpi"><div class="label">Unique IPs</div><div class="val" id="uniq">0</div></div>
  <div class="kpi"><div class="label">4xx / 5xx</div><div class="val" id="errs">0 / 0</div></div>
  <div class="kpi"><div class="label">Error rate</div><div class="val" id="errpct">0%</div></div>
  <div class="kpi"><div class="label">Susp. hits / s</div><div class="val" id="atk">0</div></div>
  <div class="kpi"><div class="label">Muted hits (excl.)</div><div class="val" id="mutedTotal">0</div></div>
</div>

<div class="layout">
  <div>
    <div class="card">
      <h2>Throughput &amp; suspicious activity <span class="hint">click IP anywhere for drill-down</span></h2>
      <div class="charts">
        <div class="chart-wrap"><canvas id="rpsChart"></canvas></div>
        <div class="chart-wrap"><canvas id="atkChart"></canvas></div>
        <div class="chart-wrap sm"><canvas id="statusDonut"></canvas></div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div class="card"><h2>Top source IPs <span class="hint" id="focusLbl"></span></h2><div class="body" id="ips"></div></div>
      <div class="card"><h2>Hosts (virtual)</h2><div class="body" id="domains"></div></div>
      <div class="card"><h2>Requested paths</h2><div class="body" id="paths"></div></div>
      <div class="card"><h2>Referers</h2><div class="body" id="refs"></div></div>
      <div class="card"><h2>ASN / org (enriched)</h2><div class="body" id="asn"></div></div>
      <div class="card"><h2>Country (enriched)</h2><div class="body" id="countries"></div></div>
    </div>
  </div>
  <div>
    <div class="card">
      <h2>Alert feed (score &gt;= threshold) <span class="hint">click row = focus + drill-down</span></h2>
      <div class="body" style="max-height:360px" id="alerts"></div>
    </div>
    <div class="card">
      <h2>Top scored sources (threat board)</h2>
      <div class="body" style="max-height:none;padding:0">
        <div class="th-grid"><span>Source</span><span class="sc">Score</span><span class="hits">Hits</span><span class="cc">CC</span></div>
        <div id="threats"></div>
      </div>
    </div>
    <div class="card"><h2>HTTP status mix</h2><div class="body" id="status"></div></div>
    <div class="card">
      <h2>Muted IPs <span class="hint" id="iptablesHintShort">mute list</span></h2>
      <div class="body" style="max-height:none">
        <p id="iptablesHintP" style="margin:0 0 8px;font-size:11px;color:var(--muted);line-height:1.4">Excluded from main stats. iptables sync is optional (see env).</p>
        <div class="ban-actions">
          <input type="text" id="banIp" class="ban-inp" placeholder="IPv4 / IPv6" autocomplete="off"/>
          <button type="button" class="toolbtn danger" id="btnBan">Mute</button>
        </div>
        <div id="banList"></div>
      </div>
    </div>
  </div>
</div>
<footer id="foot">Server time -</footer>

<div class="modal-backdrop" id="modalBg" aria-hidden="true">
  <div class="modal" role="dialog" aria-labelledby="modalTitle">
    <div class="modal-hd">
      <h3 id="modalTitle">Host detail</h3>
      <div>
        <button type="button" class="toolbtn" id="modalCopy">Copy IP</button>
        <button type="button" class="toolbtn danger" id="modalBan">Mute IP</button>
        <button type="button" class="toolbtn" id="modalClose">Close</button>
      </div>
    </div>
    <div class="modal-bd">
      <div class="modal-meta" id="modalMeta"></div>
      <table class="path-table">
        <thead><tr><th>Path</th><th>Hits</th></tr></thead>
        <tbody id="modalPaths"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const MAX=60;
let rpsHist=[], atkHist=[];
let lastPayload=null;
let focusIp='';
let pollMs=1500;
let pollTimer=null;
let paused=false;

const chartOpts={
  responsive:true, maintainAspectRatio:false,
  plugins:{ legend:{display:false} },
  scales:{
    x:{ display:false, grid:{display:false} },
    y:{ beginAtZero:true, grid:{ color:'#1e293b' }, ticks:{ color:'#64748b', font:{size:10} } }
  }
};

const rpsChart=new Chart(document.getElementById('rpsChart'),{
  type:'line',
  data:{ labels:[], datasets:[{ label:'RPS', data:[], borderColor:'#38bdf8', backgroundColor:'rgba(56,189,248,0.08)', fill:true, tension:0.35, pointRadius:0 }] },
  options:{...chartOpts, plugins:{...chartOpts.plugins, tooltip:{enabled:true, mode:'index', intersect:false}}}
});
const atkChart=new Chart(document.getElementById('atkChart'),{
  type:'line',
  data:{ labels:[], datasets:[{ label:'Susp / s', data:[], borderColor:'#f87171', backgroundColor:'rgba(248,113,113,0.08)', fill:true, tension:0.35, pointRadius:0 }] },
  options:{...chartOpts, plugins:{...chartOpts.plugins, tooltip:{enabled:true, mode:'index', intersect:false}}}
});

const donutOpts={
  responsive:true, maintainAspectRatio:false,
  plugins:{
    legend:{ position:'bottom', labels:{ color:'#94a3b8', boxWidth:10, font:{size:9} } },
    tooltip:{callbacks:{label(c){ const sum=c.dataset.data.reduce((a,b)=>a+b,0)||1; const pct=((c.raw/sum)*100).toFixed(1); return c.label+': '+c.raw+' ('+pct+'%)'; }}}
  }
};
const statusDonut=new Chart(document.getElementById('statusDonut'),{
  type:'doughnut',
  data:{
    labels:['2xx','3xx','4xx','5xx','other'],
    datasets:[{ data:[0,0,0,0,0], backgroundColor:['#22c55e','#38bdf8','#f59e0b','#ef4444','#64748b'], borderWidth:0 }]
  },
  options:donutOpts
});

function escapeHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escapeAttr(s){ return escapeHtml(s).replace(/'/g,'&#39;'); }

function filterPairs(pairs,q){
  let a=pairs||[];
  if(q&&q.trim()){ const t=q.toLowerCase(); a=a.filter(([k])=>String(k).toLowerCase().includes(t)); }
  return a;
}

function row(k,v,danger,ipClick,tags){
  const d=danger?' danger':'';
  const ip=(ipClick&&k)?' row-ip':'';
  const hl=(focusIp&&String(k)===focusIp)?' hl-focus':'';
  const dataIp=ipClick?` data-ip="${escapeAttr(k)}"`:'';
  const pills=(ipClick&&tags&&tags.length)
    ? ' '+tags.map(t=>`<span class="tag tag-${escapeAttr(t)}">${escapeHtml(t)}</span>`).join('')
    : '';
  return `<div class="row${d}${ip}${hl}"${dataIp}><span class="k" title="${escapeAttr(k)}">${escapeHtml(k)}${pills}</span><span class="v">${v}</span></div>`;
}

function renderIpList(el,pairs,tagMap){
  const q=document.getElementById('q').value;
  const pairsFiltered=filterPairs(pairs,q);
  let html='';
  pairsFiltered.forEach(([k,v])=>{
    const tags=(tagMap&&tagMap[k])||[];
    html+=row(k,v,false,true,tags);
  });
  el.innerHTML=html||'<div class="row"><span class="k">No matches</span></div>';
}

function renderList(el,data,flag,ipCol){
  const q=document.getElementById('q').value;
  const pairs=filterPairs(data,q);
  let html='';
  pairs.forEach(([k,v])=>{ html+=row(k,v,flag&&v>100,ipCol); });
  el.innerHTML=html||'<div class="row"><span class="k">No matches</span></div>';
}

function renderStatus(el,obj){
  const q=document.getElementById('q').value;
  let keys=Object.keys(obj||{}).sort((a,b)=>obj[b]-obj[a]);
  if(q&&q.trim()){ const t=q.toLowerCase(); keys=keys.filter(k=>String(k).toLowerCase().includes(t)); }
  let html='';
  keys.slice(0,20).forEach(k=>{
    const n=obj[k];
    const danger=parseInt(k,10)>=400;
    html+=row(k+'',n,danger,false);
  });
  el.innerHTML=html||'<div class="row"><span class="k">No matches</span></div>';
}

function renderAlerts(el,alerts){
  const q=document.getElementById('q').value;
  let arr=alerts||[];
  if(focusIp) arr=arr.filter(a=>a.ip===focusIp);
  if(q&&q.trim()){ const t=q.toLowerCase(); arr=arr.filter(a=>
    String(a.ip+a.uri+(a.asn||'')+(a.country||'')+(a.tags||[]).join(' ')).toLowerCase().includes(t)); }
  if(!arr.length){
    el.innerHTML='<div class="row"><span class="k">'+(focusIp?'No alerts for focus':'No alerts in buffer')+'</span></div>';
    return;
  }
  el.innerHTML=arr.map(a=>{
    const hl=(focusIp&&a.ip===focusIp)?' hl-focus':'';
    const ap=(a.tags&&a.tags.length)?' '+a.tags.map(t=>`<span class="tag tag-${escapeAttr(t)}">${escapeHtml(t)}</span>`).join(''):'';
    return `<div class="alert-row${hl}" data-ip="${escapeAttr(a.ip)}">
      <div class="meta">${escapeHtml(a.ts)} | ${escapeHtml(a.ip)} | ${escapeHtml(a.country||'?')} | st ${a.status} | +${a.score}${ap}</div>
      <div class="uri">${escapeHtml(a.uri)}</div>
      <div class="meta">${escapeHtml(a.asn||'')} | UA: ${escapeHtml(a.ua||'')}</div>
    </div>`;
  }).join('');
}

function renderThreats(el,rows){
  const q=document.getElementById('q').value;
  let r=rows||[];
  if(q&&q.trim()){ const t=q.toLowerCase(); r=r.filter(tw=>
    String(tw.ip+tw.asn+tw.top_path+(tw.country||'')+(tw.tags||[]).join(' ')).toLowerCase().includes(t)); }
  if(focusIp) r=r.filter(tw=>tw.ip===focusIp);
  if(!r.length){
    el.innerHTML='<div class="th-row"><span class="ip">'+(focusIp?'No threats for focus':'No scored sources yet')+'</span></div>';
    return;
  }
  el.innerHTML=r.map(t=>{
    const hl=(focusIp&&t.ip===focusIp)?' hl-focus':'';
    const tp=(t.tags&&t.tags.length)?t.tags.map(x=>`<span class="tag tag-${escapeAttr(x)}">${escapeHtml(x)}</span>`).join(''):'';
    return `<div class="th-row${hl}" data-ip="${escapeAttr(t.ip)}" title="${escapeAttr(t.asn+' '+t.top_path)}">
      <span class="ip">${escapeHtml(t.ip)}${tp?(' '+tp):''}</span>
      <span class="sc">${t.score}</span>
      <span class="hits">${t.hits}</span>
      <span class="cc">${escapeHtml(t.country||'?')}</span>
    </div>`;
  }).join('');
}

function statusBuckets(st){
  const a=[0,0,0,0,0];
  for(const k of Object.keys(st||{})){
    const v=+st[k], c=parseInt(k,10);
    if(c>=200&&c<300) a[0]+=v;
    else if(c>=300&&c<400) a[1]+=v;
    else if(c>=400&&c<500) a[2]+=v;
    else if(c>=500&&c<600) a[3]+=v;
    else a[4]+=v;
  }
  return a;
}

function setPoll(ms){
  pollMs=ms;
  document.querySelectorAll('.poll-opt').forEach(b=>{
    b.classList.toggle('on',+b.dataset.ms===ms);
  });
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
  const blob=new Blob([JSON.stringify(lastPayload,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='sentinel-snapshot.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

let modalIp='';
function closeModal(){
  document.getElementById('modalBg').classList.remove('open');
}
async function openIpModal(ip){
  if(!ip) return;
  modalIp=ip;
  document.getElementById('modalTitle').innerText=ip;
  document.getElementById('modalMeta').innerText='Loading...';
  document.getElementById('modalPaths').innerHTML='';
  document.getElementById('modalBg').classList.add('open');
  try{
    const r=await fetch('/api/ip?ip='+encodeURIComponent(ip),{credentials:'same-origin'});
    const j=await r.json();
    if(!r.ok){ document.getElementById('modalMeta').innerText=j.error||'Error'; return; }
    const g=j.geo||{};
    const mt=(j.tags&&j.tags.length)?(' '+j.tags.map(t=>`<span class="tag tag-${escapeAttr(t)}">${escapeHtml(t)}</span>`).join('')):'';
    document.getElementById('modalMeta').innerHTML=
      'Hits: '+j.hits+' | Score: '+j.score+mt+'<br/>'+
      escapeHtml((g.country||'?')+' | '+(g.asn||''));
    document.getElementById('modalPaths').innerHTML=(j.paths||[]).map(([p,c])=>
      '<tr><td>'+escapeHtml(p)+'</td><td>'+c+'</td></tr>').join('')||'<tr><td colspan="2">No paths</td></tr>';
  }catch(e){
    document.getElementById('modalMeta').innerText='Request failed';
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
  renderList(document.getElementById('countries'),d.countries);
  renderStatus(document.getElementById('status'),d.status);
  renderAlerts(document.getElementById('alerts'),d.alerts);
  renderThreats(document.getElementById('threats'),d.top_threats);
}

function renderBanList(d){
  const el=document.getElementById('banList');
  const bans=d.banned_ips||[];
  const mh=d.muted_hits||{};
  if(!bans.length){
    el.innerHTML='<div class="row"><span class="k">No muted IPs</span></div>';
    return;
  }
  el.innerHTML=bans.map(ip=>{
    const c=mh[ip]||0;
    return `<div class="ban-row"><span class="kip" title="${escapeAttr(ip)}">${escapeHtml(ip)}</span><span class="cnt">${c} excl.</span><button type="button" class="toolbtn" data-unban="${escapeAttr(ip)}">Unmute</button></div>`;
  }).join('');
}

async function load(force){
  if(paused && !force) return;
  let d;
  try{
    const res=await fetch('/data',{credentials:'same-origin'});
    if(res.status===401){
      document.getElementById('foot').innerText='401: reload and sign in (Basic auth for this origin)';
      return;
    }
    d=await res.json();
  }catch(e){ return; }
  lastPayload=d;

  const ab=document.getElementById('authBadge');
  if(ab){ ab.style.display=d.auth_enabled?'inline-flex':'none'; }

  document.getElementById('rps').innerText=d.rps;
  document.getElementById('peak').innerText=d.peak;
  document.getElementById('total').innerText=d.total.toLocaleString();
  document.getElementById('uniq').innerText=d.unique_ips;
  document.getElementById('errs').innerText=(d.client_errors||0)+' / '+(d.server_errors||0);
  document.getElementById('errpct').innerText=(d.error_rate_pct||0)+'%';
  document.getElementById('atk').innerText=d.attack_rps_last_tick||0;

  const lvl=document.getElementById('lvl');
  lvl.innerText='POSTURE: '+(d.threat_level||'-');
  lvl.style.borderColor=d.threat_color||'#334155';
  lvl.style.color=d.threat_color||'#e2e8f0';

  rpsHist.push(d.rps);
  const lastAtk=(d.attack_timeline&&d.attack_timeline.length)?d.attack_timeline[d.attack_timeline.length-1]:0;
  atkHist.push(lastAtk);
  if(rpsHist.length>MAX) rpsHist.shift();
  if(atkHist.length>MAX) atkHist.shift();

  const labels=rpsHist.map((_,i)=>i);
  rpsChart.data.labels=labels;
  rpsChart.data.datasets[0].data=rpsHist;
  rpsChart.update('none');

  atkChart.data.labels=labels;
  atkChart.data.datasets[0].data=atkHist;
  atkChart.update('none');

  const buck=statusBuckets(d.status);
  statusDonut.data.datasets[0].data=buck;
  statusDonut.update('none');

  applyRender(d);

  document.getElementById('mutedTotal').innerText=d.muted_total||0;
  renderBanList(d);

  const ih=document.getElementById('iptablesHintP');
  if(ih){
    ih.textContent=d.iptables_enabled
      ? ('Also applying iptables DROP on chain '+d.iptables_chain+' (app must run as root).')
      : ('iptables off. Set env SENTINEL_IPTABLES=1 to add DROP rules; optional SENTINEL_IPTABLES_CHAIN (default INPUT).');
  }
  const ihs=document.getElementById('iptablesHintShort');
  if(ihs){ ihs.textContent=d.iptables_enabled?'mute + iptables':'mute list'; }

  const up=d.stream_uptime_s!=null?(' | stream '+d.stream_uptime_s+'s'):'';
  const poll=paused?'paused':(pollMs/1000)+'s';
  const au=d.audit_log?' | audit log on':'';
  document.getElementById('foot').innerText='Server '+d.server_time+up+' | poll '+poll+au;
}

document.getElementById('btnPause').addEventListener('click',()=>setPaused(!paused));
document.querySelectorAll('.poll-opt').forEach(b=>b.addEventListener('click',()=>{ setPaused(false); setPoll(+b.dataset.ms); }));
document.getElementById('btnExport').addEventListener('click',exportJson);
document.getElementById('btnClearFocus').addEventListener('click',()=>{ setFocus(''); });
function warnIptables(j){
  if(j&&j.iptables&&j.iptables.enabled&&!j.iptables.ok){
    alert('iptables: '+(j.iptables.error||'failed'));
  }
}
document.getElementById('btnBan').addEventListener('click',async ()=>{
  const ip=document.getElementById('banIp').value.trim();
  if(!ip){ return; }
  try{
    const r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok){ alert(j.error||'Mute failed'); return; }
    warnIptables(j);
    document.getElementById('banIp').value='';
    await load(true);
  }catch(e){ alert('Mute failed'); }
});
document.getElementById('banList').addEventListener('click',async e=>{
  const b=e.target.closest('[data-unban]');
  if(!b||!b.dataset.unban) return;
  const ip=b.dataset.unban;
  try{
    const r=await fetch('/api/unban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok){ alert(j.error||'Unmute failed'); return; }
    warnIptables(j);
    await load(true);
  }catch(err){ alert('Unmute failed'); }
});
document.getElementById('btnReset').addEventListener('click',async ()=>{
  if(!confirm('Reset all dashboard counters, charts, alerts, and geo cache?')) return;
  try{
    const r=await fetch('/api/reset',{method:'POST',credentials:'same-origin'});
    if(!r.ok) throw new Error('bad status');
    lastPayload=null;
    setFocus('');
    closeModal();
    rpsHist=[];
    atkHist=[];
    rpsChart.data.labels=[];
    rpsChart.data.datasets[0].data=[];
    rpsChart.update('none');
    atkChart.data.labels=[];
    atkChart.data.datasets[0].data=[];
    atkChart.update('none');
    statusDonut.data.datasets[0].data=[0,0,0,0,0];
    statusDonut.update('none');
    setPaused(false);
    await load(true);
  }catch(e){
    alert('Reset failed');
  }
});
document.getElementById('q').addEventListener('input',()=>{ if(lastPayload) applyRender(lastPayload); });

document.getElementById('modalBg').addEventListener('click',e=>{ if(e.target.id==='modalBg') closeModal(); });
document.getElementById('modalClose').addEventListener('click',closeModal);
document.getElementById('modalCopy').addEventListener('click',()=>{
  if(modalIp&&navigator.clipboard) navigator.clipboard.writeText(modalIp);
});
document.getElementById('modalBan').addEventListener('click',async ()=>{
  if(!modalIp) return;
  try{
    const r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:modalIp})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok){ alert(j.error||'Mute failed'); return; }
    warnIptables(j);
    closeModal();
    await load(true);
  }catch(e){ alert('Mute failed'); }
});

document.body.addEventListener('click',e=>{
  const ipRow=e.target.closest('.row-ip');
  if(ipRow&&ipRow.dataset.ip){ setFocus(ipRow.dataset.ip); openIpModal(ipRow.dataset.ip); return; }
  const th=e.target.closest('.th-row[data-ip]');
  if(th&&th.dataset.ip){ setFocus(th.dataset.ip); openIpModal(th.dataset.ip); return; }
  const ar=e.target.closest('.alert-row');
  if(ar&&ar.dataset.ip){ setFocus(ar.dataset.ip); openIpModal(ar.dataset.ip); return; }
});

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){ closeModal(); return; }
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); document.getElementById('q').focus(); }
});

document.getElementById('btnClearFocus').style.display='none';
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
