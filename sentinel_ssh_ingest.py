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
# SSH log line patterns (used for both file and journal MESSAGE field)
# ---------------------------------------------------------------------------

_FAIL_RE = [
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)"),
    re.compile(r"Invalid user (\S+) from ([\da-fA-F:.]+)"),
    re.compile(r"Disconnected from (?:invalid user |authenticating user )?(\S+) ([\da-fA-F:.]+) port"),
    re.compile(r"Connection closed by (?:invalid user |authenticating user )?(\S+) ([\da-fA-F:.]+) port"),
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)"),
    re.compile(r"kex_exchange_identification.*from (\S+)@([\da-fA-F:.]+)"),
]

_IP_ONLY_RE = [
    re.compile(r"Did not receive identification string from ([\da-fA-F:.]+)"),
    re.compile(r"Bad protocol version identification .{0,80} from ([\da-fA-F:.]+)"),
    re.compile(r"Unable to negotiate with ([\da-fA-F:.]+)"),
    re.compile(r"Connection reset by (?:invalid user )?\S+ ([\da-fA-F:.]+)"),
    re.compile(r"Received disconnect from ([\da-fA-F:.]+) port \d+:.*\[preauth\]"),
]


def _parse_line(line):
    """Return (ip, user_or_None) for SSH failure lines, None otherwise."""
    if "sshd" not in line and "ssh" not in line.lower():
        return None
    for pat in _FAIL_RE:
        m = pat.search(line)
        if m:
            return m.group(2), m.group(1)
    for pat in _IP_ONLY_RE:
        m = pat.search(line)
        if m:
            return m.group(1), None
    return None


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def _make_event(ip, user=None):
    ua = f"SSH-client/{user}" if user else "SSH-client"
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
        "headers": {
            "User-Agent": [ua],
        },
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
            ip, user = parsed
            batch.append(_make_event(ip, user))
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
