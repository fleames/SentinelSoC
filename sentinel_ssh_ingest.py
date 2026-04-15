#!/usr/bin/env python3
# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel_ssh_ingest.py -- Forward SSH auth failures to Sentinel's /api/ingest
endpoint as synthetic Caddy-format HTTP events.

Two source modes (auto-detected, or forced via SSH_SOURCE env var):
  journal   -- read from systemd journal via `journalctl` (no auth.log needed,
               works even when rsyslog is down or disk is full writing logs)
  file      -- tail SSH_LOG_PATH (default: /var/log/auth.log)

Auto-detection: uses journal mode if journalctl is available AND auth.log is
missing or SSH_SOURCE=journal is set; otherwise falls back to file mode.

Each SSH failure becomes a flat Caddy-format JSON event:
  - remote_ip / client_ip = attacker IP
  - uri = /ssh, status = 401
  - User-Agent = SSH-client/<username> (for UA-based signals)

Environment variables:
  SENTINEL_URL          Base URL of Sentinel (default: http://127.0.0.1:5000)
  SENTINEL_INGEST_KEY   Bearer token (must match SENTINEL_INGEST_KEY in Sentinel)
  SSH_SOURCE            Force source mode: "journal" or "file"
  SSH_LOG_PATH          Log to tail in file mode (default: /var/log/auth.log)
  SSH_BATCH_SIZE        Max events per POST request (default: 20)
  SSH_FLUSH_INTERVAL    Seconds between batch flushes (default: 5)
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

SENTINEL_URL    = os.environ.get("SENTINEL_URL",         "http://127.0.0.1:5000").rstrip("/")
INGEST_KEY      = os.environ.get("SENTINEL_INGEST_KEY",  "").strip()
LOG_PATH        = os.environ.get("SSH_LOG_PATH",         "/var/log/auth.log")
BATCH_SIZE      = int(os.environ.get("SSH_BATCH_SIZE",   "20"))
FLUSH_INTERVAL  = float(os.environ.get("SSH_FLUSH_INTERVAL", "5"))
SSH_SOURCE      = os.environ.get("SSH_SOURCE", "").strip().lower()  # "journal" | "file" | ""


# ---------------------------------------------------------------------------
# SSH log line patterns — returns (ip, user_or_None, auth_method, src_port_or_None)
# auth_method: "password" | "publickey" | "scanner" | ""
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Patterns — INFO level (always available)
# ---------------------------------------------------------------------------
# Returns (ip, user_or_None, auth_method, src_port_or_None, key_fp_or_None)
# auth_method: "password" | "publickey" | "scanner" | ""
# key_fp: e.g. "RSA SHA256:abcde..." — only from LogLevel VERBOSE

# VERBOSE: publickey failure WITH key fingerprint (must check before _FAILED_RE)
_FAILED_PK_FP_RE = re.compile(
    r"Failed publickey for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?"
    r"[^\n]*?ssh2:\s*(\S+\s+SHA256:\S+)"
)
# VERBOSE: "Postponed publickey" — attacker presenting a key (before final verdict)
_POSTPONED_PK_RE = re.compile(
    r"Postponed publickey for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?"
    r"[^\n]*?ssh2:\s*(\S+\s+SHA256:\S+)"
)

# INFO: generic Failed password / publickey (no fingerprint)
_FAILED_RE   = re.compile(r"Failed (password|publickey) for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_INVALID_RE  = re.compile(r"Invalid user (\S+) from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_DISCON_RE   = re.compile(r"Disconnected from (?:invalid user |authenticating user )?(\S+) ([\da-fA-F:.]+) port (\d+)")
_CLOSED_RE   = re.compile(r"Connection closed by (?:invalid user |authenticating user )?(\S+) ([\da-fA-F:.]+) port (\d+)")
_MAXAUTH_RE  = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_KEX_RE      = re.compile(r"kex_exchange_identification.*from (\S+)@([\da-fA-F:.]+)")

_NO_IDENT_RE = re.compile(r"Did not receive identification string from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_BAD_VER_RE  = re.compile(r"Bad protocol version identification .{0,80} from ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_NO_NEG_RE   = re.compile(r"Unable to negotiate with ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_RESET_RE    = re.compile(r"Connection reset by (?:invalid user )?\S+ ([\da-fA-F:.]+)(?:\s+port\s+(\d+))?")
_RECV_RE     = re.compile(r"Received disconnect from ([\da-fA-F:.]+) port (\d+).*\[preauth\]")

# ---------------------------------------------------------------------------
# KEX fingerprinting (LogLevel VERBOSE) — PID-correlated accumulation
# ---------------------------------------------------------------------------
_PID_RE         = re.compile(r"sshd\[(\d+)\]")
_KEX_ALGO_RE    = re.compile(r"kex: algorithm: (\S+)")
_KEX_CIPHER_RE  = re.compile(r"kex: client->server cipher: (\S+)")
_KEX_HKEY_RE    = re.compile(r"kex: host key algorithm: (\S+)")

# PID -> {'algo': str, 'cipher': str, 'hkey': str}
_pending_kex = {}


def _kex_fp_from_pid(pid):
    """Pop and hash the accumulated kex fields for a PID. Returns fp or None."""
    if not pid:
        return None
    kex = _pending_kex.pop(pid, None)
    if not kex:
        return None
    parts = ":".join(filter(None, [
        kex.get("algo", ""),
        kex.get("cipher", ""),
        kex.get("hkey", ""),
    ]))
    return hashlib.sha256(parts.encode()).hexdigest()[:16] if parts else None


def _parse_line(line):
    """Return (ip, user, auth_method, src_port, key_fp, kex_fp) or None."""
    if "sshd" not in line and "ssh" not in line.lower():
        return None

    # Extract PID for kex correlation (present in file mode; synthesised in journal mode)
    pid_m = _PID_RE.search(line)
    pid = pid_m.group(1) if pid_m else None

    # VERBOSE: accumulate kex fields keyed by PID — do not emit an event
    if pid:
        m = _KEX_ALGO_RE.search(line)
        if m:
            _pending_kex.setdefault(pid, {})["algo"] = m.group(1)
            # Prune if table grows too large (stale PIDs from sessions with no auth event)
            if len(_pending_kex) > 500:
                for old in list(_pending_kex)[:250]:
                    del _pending_kex[old]
            return None
        m = _KEX_CIPHER_RE.search(line)
        if m:
            _pending_kex.setdefault(pid, {})["cipher"] = m.group(1)
            return None
        m = _KEX_HKEY_RE.search(line)
        if m:
            _pending_kex.setdefault(pid, {})["hkey"] = m.group(1)
            return None

    # VERBOSE: publickey with fingerprint — check before generic _FAILED_RE
    m = _FAILED_PK_FP_RE.search(line)
    if m:
        return m.group(2), m.group(1), "publickey", int(m.group(3)) if m.group(3) else None, m.group(4), _kex_fp_from_pid(pid)

    # VERBOSE: postponed publickey (key presented but not yet accepted/rejected)
    m = _POSTPONED_PK_RE.search(line)
    if m:
        return m.group(2), m.group(1), "publickey", int(m.group(3)) if m.group(3) else None, m.group(4), _kex_fp_from_pid(pid)

    # INFO: generic Failed password / publickey
    m = _FAILED_RE.search(line)
    if m:
        return m.group(3), m.group(2), m.group(1), int(m.group(4)) if m.group(4) else None, None, _kex_fp_from_pid(pid)

    m = _INVALID_RE.search(line)
    if m:
        return m.group(2), m.group(1), "password", int(m.group(3)) if m.group(3) else None, None, _kex_fp_from_pid(pid)

    m = _DISCON_RE.search(line)
    if m:
        return m.group(2), m.group(1), "password", int(m.group(3)), None, _kex_fp_from_pid(pid)

    m = _CLOSED_RE.search(line)
    if m:
        return m.group(2), m.group(1), "password", int(m.group(3)), None, _kex_fp_from_pid(pid)

    m = _MAXAUTH_RE.search(line)
    if m:
        return m.group(2), m.group(1), "password", int(m.group(3)) if m.group(3) else None, None, _kex_fp_from_pid(pid)

    m = _KEX_RE.search(line)
    if m:
        return m.group(2), m.group(1), "scanner", None, None, _kex_fp_from_pid(pid)

    m = _NO_IDENT_RE.search(line)
    if m:
        return m.group(1), None, "scanner", int(m.group(2)) if m.group(2) else None, None, _kex_fp_from_pid(pid)

    m = _BAD_VER_RE.search(line)
    if m:
        return m.group(1), None, "scanner", int(m.group(2)) if m.group(2) else None, None, _kex_fp_from_pid(pid)

    m = _NO_NEG_RE.search(line)
    if m:
        return m.group(1), None, "scanner", int(m.group(2)) if m.group(2) else None, None, _kex_fp_from_pid(pid)

    m = _RESET_RE.search(line)
    if m:
        return m.group(1), None, "scanner", int(m.group(2)) if m.group(2) else None, None, _kex_fp_from_pid(pid)

    m = _RECV_RE.search(line)
    if m:
        return m.group(1), None, "scanner", int(m.group(2)), None, _kex_fp_from_pid(pid)

    return None


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def _make_event(ip, user=None, auth_method="", src_port=None, key_fp=None, kex_fp=None):
    ua = f"SSH-client/{user}" if user else "SSH-client"
    hdrs = {"User-Agent": [ua]}
    if auth_method:
        hdrs["X-SSH-Auth-Method"] = [auth_method]
    if src_port:
        hdrs["X-SSH-Src-Port"] = [str(src_port)]
    if key_fp:
        hdrs["X-SSH-Key-Fp"] = [key_fp[:100]]
    if kex_fp:
        hdrs["X-SSH-Kex-Fp"] = [kex_fp[:16]]
    return {
        "msg":       "handled request",
        "ts":        datetime.now(timezone.utc).isoformat(),
        "remote_ip": ip,
        "client_ip": ip,
        "host":      "ssh",
        "uri":       "/ssh",
        "method":    "SSH",
        "status":    401,
        "size":      0,
        "headers":   hdrs,
    }


# ---------------------------------------------------------------------------
# HTTP posting
# ---------------------------------------------------------------------------

def _post_batch(events):
    if not events:
        return
    body = "\n".join(json.dumps(e) for e in events).encode("utf-8")
    req = urllib.request.Request(
        f"{SENTINEL_URL}/api/ingest",
        data=body,
        method="POST",
        headers={
            "Content-Type":      "application/x-ndjson",
            "X-Sentinel-Source": "ssh",
        },
    )
    if INGEST_KEY:
        req.add_header("Authorization", f"Bearer {INGEST_KEY}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            ingested = result.get("ingested", "?")
            print(f"[ssh-ingest] flushed {len(events)} events ({ingested} ingested)", flush=True)
    except urllib.error.URLError as exc:
        print(f"[ssh-ingest] POST failed: {exc}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"[ssh-ingest] unexpected error: {exc}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Source: journalctl (no auth.log needed)
# ---------------------------------------------------------------------------

def _lines_from_journal():
    """Yield SSH log lines from systemd journal. Requires journalctl."""
    print("[ssh-ingest] reading from systemd journal (journalctl mode)", flush=True)
    cmd = ["journalctl", "-u", "sshd", "-u", "ssh", "-f", "-o", "json", "-n", "0"]
    while True:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            for raw in proc.stdout:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                    msg = entry.get("MESSAGE") or ""
                    if isinstance(msg, list):
                        msg = "".join(chr(b) if isinstance(b, int) else b for b in msg)
                    if msg:
                        # Synthesise "sshd[PID]:" prefix so _parse_line can
                        # correlate kex: lines with auth events by PID.
                        pid = entry.get("_PID") or entry.get("SYSLOG_PID") or ""
                        if pid:
                            yield f"sshd[{pid}]: {msg}"
                        else:
                            yield msg
                except (json.JSONDecodeError, ValueError):
                    continue
            proc.wait()
        except FileNotFoundError:
            print("[ssh-ingest] journalctl not found, switching to file mode", file=sys.stderr, flush=True)
            return
        except Exception as exc:
            print(f"[ssh-ingest] journal error: {exc}", file=sys.stderr, flush=True)
        time.sleep(3)


# ---------------------------------------------------------------------------
# Source: auth.log file tail (handles rotation via inode check)
# ---------------------------------------------------------------------------

def _lines_from_file(path):
    """Yield lines from a growing log file. Re-opens on rotation."""
    f = None
    inode = None
    pos = 0

    def _open():
        nonlocal f, inode, pos
        if f:
            try:
                f.close()
            except OSError:
                pass
        while True:
            try:
                f = open(path, "r", encoding="utf-8", errors="replace")
                st = os.stat(path)
                inode = st.st_ino
                f.seek(0, 2)
                pos = f.tell()
                print(f"[ssh-ingest] tailing {path} (inode={inode}, size={st.st_size})", flush=True)
                return
            except FileNotFoundError:
                print(f"[ssh-ingest] waiting for {path} ...", file=sys.stderr, flush=True)
                time.sleep(2)

    _open()
    while True:
        line = f.readline()
        if line:
            pos += len(line.encode("utf-8", errors="replace"))
            yield line.rstrip("\n")
            continue

        time.sleep(0.2)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            _open()
            continue

        if st.st_ino != inode or st.st_size < pos:
            _open()


# ---------------------------------------------------------------------------
# Source selection
# ---------------------------------------------------------------------------

def _choose_source():
    if SSH_SOURCE == "journal":
        return "journal"
    if SSH_SOURCE == "file":
        return "file"
    # Auto-detect: prefer journal if auth.log is missing
    if not os.path.exists(LOG_PATH):
        import shutil
        if shutil.which("journalctl"):
            return "journal"
    return "file"


def _line_source(mode):
    if mode == "journal":
        return _lines_from_journal()
    return _lines_from_file(LOG_PATH)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    mode = _choose_source()
    print(
        f"[ssh-ingest] starting  mode={mode}  sentinel={SENTINEL_URL}"
        f"  batch={BATCH_SIZE}  flush_interval={FLUSH_INTERVAL}s",
        flush=True,
    )
    batch = []
    last_flush = time.time()

    for line in _line_source(mode):
        parsed = _parse_line(line)
        if parsed:
            ip, user, auth_method, src_port, key_fp, kex_fp = parsed
            batch.append(_make_event(ip, user, auth_method, src_port, key_fp, kex_fp))
            if len(batch) >= BATCH_SIZE:
                _post_batch(batch)
                batch = []
                last_flush = time.time()

        now = time.time()
        if batch and (now - last_flush) >= FLUSH_INTERVAL:
            _post_batch(batch)
            batch = []
            last_flush = now


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[ssh-ingest] stopped", flush=True)
