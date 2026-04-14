# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/rules.py -- Detection rules engine.
"""
import re
from urllib.parse import unquote_plus

from sentinel import config
from sentinel.helpers import _is_static_asset

# ---------------------------------------------------------------------------
# Pre-compiled patterns for SQLi and XSS detection
# Compiled once at import; matched against URL-decoded URI.
# ---------------------------------------------------------------------------

_SQLI_RE = re.compile(
    r"union[\s\+%09\-/\*]+select"           # UNION SELECT (with spaces/comments)
    r"|select[\s\+%09]+.{0,40}from[\s\+%09]"  # SELECT ... FROM
    r"|insert[\s\+%09]+into[\s\+%09]"
    r"|drop[\s\+%09]+table"
    r"|(?:exec|execute)\s*\("
    r"|(?:load_file|into\s+outfile|into\s+dumpfile)\s*\("
    r"|(?:concat|group_concat|char|ascii|hex|unhex|substr|mid)\s*\("
    r"|(?:sleep|benchmark|pg_sleep|waitfor[\s\+]+delay)\s*\("
    r"|information_schema"
    r"|0x[0-9a-fA-F]{8,}"                   # long hex blob
    r"|(?:--|#|%23)[\s\+]"                   # SQL comment markers
    r"|'\s*(?:or|and)\s*'?\d"               # ' OR '1, ' AND 1
    r"|(?:or|and)\s+1\s*=\s*1"              # OR 1=1
    r"|(?:or|and)\s+'[^']*'\s*=\s*'[^']*'" # OR 'a'='a'
    r"|xp_cmdshell"
    r"|sys\.(?:tables|columns|objects)",
    re.IGNORECASE,
)

_XSS_RE = re.compile(
    r"<\s*script"                            # <script
    r"|<\s*/\s*script"                       # </script
    r"|<\s*iframe"                           # <iframe
    r"|<\s*img[^>]+onerror"                  # <img onerror=
    r"|javascript\s*:"                        # javascript:
    r"|vbscript\s*:"                          # vbscript:
    r"|on(?:error|load|click|mouseover|focus|blur|keyup|keydown|submit|change)\s*=" # event handlers
    r"|(?:eval|setTimeout|setInterval|Function)\s*\("
    r"|document\s*\.\s*(?:cookie|write|location|createElement)"
    r"|window\s*\.\s*(?:location|open|alert)"
    r"|(?:innerHTML|outerHTML|insertAdjacentHTML)"
    r"|expression\s*\("                       # CSS expression() injection
    r"|&#x[0-9a-fA-F]+;"                     # hex HTML entities
    r"|&#\d{2,5};",                           # decimal HTML entities (suspicious in URI)
    re.IGNORECASE,
)


def _decode_uri(uri):
    """URL-decode a URI string twice to catch double-encoded payloads."""
    try:
        once = unquote_plus(uri or "")
        twice = unquote_plus(once)
        return twice
    except Exception:
        return uri or ""

# ========================
# DETECTION RULES ENGINE
# ========================
# Each rule: name, match(event_dict)->bool, score int.
# "skip" rules short-circuit scoring entirely (e.g. trusted infra).
# event_dict keys: uri, ua, path, status, asn, country, cf_ray, cf_ip.
DETECTION_RULES = [
    # -- Trusted infra (short-circuit) --
    {
        "name": "cloudflare_trusted",
        "skip": True,
        "match": lambda e: "cloudflare" in (e.get("asn") or "").lower(),
        "score": 0,
    },
    # -- Static assets (short-circuit) --
    {
        "name": "static_asset",
        "skip": True,
        "match": lambda e: _is_static_asset((e.get("uri") or "").split("?")[0]),
        "score": 0,
    },
    # -- High-value paths --
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
    # -- Suspicious user-agents --
    {
        "name": "scanner_ua",
        "match": lambda e: any(x in (e.get("ua") or "").lower() for x in (
            "bot", "curl", "python", "wget", "scanner", "nikto", "sqlmap",
            "masscan", "zgrab", "nmap", "dirbuster", "gobuster", "wfuzz",
            "nuclei", "hydra", "metasploit",
        )),
        "score": 3,
    },
    # -- Missing / empty UA --
    {
        "name": "empty_ua",
        "match": lambda e: not (e.get("ua") or "").strip() or (e.get("ua") or "-").strip() == "-",
        "score": 2,
    },
    # -- Credential stuffing / brute-force --
    {
        "name": "credential_stuffing",
        "match": lambda e: (e.get("path") or "").lower() in (
            "/login", "/wp-login.php", "/signin", "/auth/login",
            "/account/login", "/user/login", "/admin/login",
        ) and e.get("status") in (401, 403),
        "score": 6,
    },
    # -- Origin-bypass (direct-to-origin when CF expected) --
    {
        "name": "origin_bypass",
        "match": lambda e: config.SENTINEL_EXPECT_CF and not e.get("cf_ray"),
        "score": 5,
    },
    # -- SQL injection patterns --
    {
        "name": "sqli",
        "match": lambda e: bool(_SQLI_RE.search(_decode_uri(e.get("uri") or ""))),
        "score": 12,
    },
    # -- XSS patterns --
    {
        "name": "xss",
        "match": lambda e: bool(_XSS_RE.search(_decode_uri(e.get("uri") or ""))),
        "score": 10,
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
