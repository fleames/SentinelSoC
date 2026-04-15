#!/usr/bin/env python3
# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel_ssh_ingest.py -- Tail /var/log/auth.log and forward SSH auth
failures to Sentinel's /api/ingest endpoint as synthetic HTTP events.

Each SSH failure becomes a flat Caddy-format JSON event:
  - remote_ip / client_ip = attacker IP
  - uri = /ssh, status = 401
  - User-Agent = SSH-client/<username> (for UA-based signals)

This feeds the existing scoring rules:
  - ssh_bruteforce rule: +8 per event
  - bruteforce tag: fires after BRUTEFORCE_MIN_HITS failures in window
  - error_probe tag: fires when 4xx rate is high
  - scanner / persistent tags: fire as normal

Environment variables:
  SENTINEL_URL          Base URL of Sentinel (default: http://127.0.0.1:5000)
  SENTINEL_INGEST_KEY   Bearer token (must match SENTINEL_INGEST_KEY in Sentinel)
  SSH_LOG_PATH          Log to tail (default: /var/log/auth.log)
  SSH_BATCH_SIZE        Max events per POST request (default: 20)
  SSH_FLUSH_INTERVAL    Seconds between batch flushes (default: 5)
"""
import json
import os
import re
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

# ---------------------------------------------------------------------------
# Auth.log patterns
# ---------------------------------------------------------------------------

# Lines that include both a username and an IP address.
_FAIL_RE = [
    # Failed password for [invalid user] <user> from <ip> port <port> ssh2
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)"),
    # Invalid user <user> from <ip>
    re.compile(r"Invalid user (\S+) from ([\da-fA-F:.]+)"),
    # Disconnected from [invalid|authenticating] user <user> <ip> port
    re.compile(r"Disconnected from (?:invalid user |authenticating user )?(\S+) ([\da-fA-F:.]+) port"),
    # Connection closed by [invalid|authenticating] user <user> <ip> port
    re.compile(r"Connection closed by (?:invalid user |authenticating user )?(\S+) ([\da-fA-F:.]+) port"),
    # maximum authentication attempts exceeded for [invalid user] <user> from <ip>
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)"),
    # error: kex_exchange_identification: ... from <user>@<ip>
    re.compile(r"kex_exchange_identification.*from (\S+)@([\da-fA-F:.]+)"),
]

# Lines that only expose an IP (no username).
_IP_ONLY_RE = [
    re.compile(r"Did not receive identification string from ([\da-fA-F:.]+)"),
    re.compile(r"Bad protocol version identification .{0,80} from ([\da-fA-F:.]+)"),
    re.compile(r"Unable to negotiate with ([\da-fA-F:.]+)"),
    re.compile(r"Connection reset by (?:invalid user )?\S+ ([\da-fA-F:.]+)"),
    re.compile(r"Received disconnect from ([\da-fA-F:.]+) port \d+:.*\[preauth\]"),
]


def _parse_line(line):
    """
    Return (ip, username_or_None) for SSH failure lines, None otherwise.
    Only processes lines containing 'sshd'.
    """
    if "sshd" not in line:
        return None
    for pat in _FAIL_RE:
        m = pat.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            return ip, user
    for pat in _IP_ONLY_RE:
        m = pat.search(line)
        if m:
            return m.group(1), None
    return None


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def _make_event(ip, user=None):
    """
    Build a synthetic flat Caddy-format event for one SSH auth failure.
    Accepted by _parse_caddy_access_line's flat-format path (msg='handled request').
    """
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
            "Content-Type":     "application/x-ndjson",
            "X-Sentinel-Source": "ssh",
        },
    )
    if INGEST_KEY:
        req.add_header("Authorization", f"Bearer {INGEST_KEY}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            ingested = result.get("ingested", "?")
            print(f"[ssh-ingest] flushed {len(events)} events ({ingested} ingested)", flush=True)
    except urllib.error.URLError as exc:
        print(f"[ssh-ingest] POST failed: {exc}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"[ssh-ingest] unexpected error: {exc}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Log tailer (handles rotation via inode check)
# ---------------------------------------------------------------------------

def _tail(path):
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
# Main loop
# ---------------------------------------------------------------------------

def main():
    print(
        f"[ssh-ingest] starting  log={LOG_PATH}  sentinel={SENTINEL_URL}"
        f"  batch={BATCH_SIZE}  flush_interval={FLUSH_INTERVAL}s",
        flush=True,
    )
    batch = []
    last_flush = time.time()

    for line in _tail(LOG_PATH):
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
