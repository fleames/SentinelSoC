#!/usr/bin/env python3
"""
sentinel_push.py — lightweight log push agent for remote Sentinel sources.

Tails a local log file and POSTs each line to a Sentinel /api/ingest endpoint.
Designed to run as a systemd service on servers that cannot mount the log
directory directly to the Sentinel host.

Environment variables:
  PUSH_LOG_PATH        Path to the log file to tail (default: /var/log/caddy/access.log)
  SENTINEL_URL         Full URL of the ingest endpoint (default: http://localhost:5000/api/ingest)
  SENTINEL_INGEST_KEY  Bearer token to authenticate with Sentinel (optional)
  PUSH_SOURCE          Source label sent via X-Sentinel-Source header (default: hostname)
  PUSH_BATCH           Max lines per POST request (default: 50)
  PUSH_INTERVAL        Seconds to wait when no new lines are available (default: 2)
"""

import os
import time
import requests

LOG_PATH  = os.environ.get("PUSH_LOG_PATH",  "/var/log/caddy/access.log")
SENTINEL  = os.environ.get("SENTINEL_URL",   "http://localhost:5000/api/ingest")
KEY       = os.environ.get("SENTINEL_INGEST_KEY", "")
SOURCE    = os.environ.get("PUSH_SOURCE",    os.uname().nodename)
BATCH     = int(os.environ.get("PUSH_BATCH",    "50"))
INTERVAL  = float(os.environ.get("PUSH_INTERVAL", "2"))

headers = {"X-Sentinel-Source": SOURCE, "Content-Type": "application/x-ndjson"}
if KEY:
    headers["Authorization"] = f"Bearer {KEY}"


def push(lines):
    body = "\n".join(lines).encode()
    try:
        r = requests.post(SENTINEL, data=body, headers=headers, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"push error: {e}", flush=True)


def tail(path):
    with open(path) as f:
        f.seek(0, 2)  # start at EOF — only forward new events
        buf = []
        while True:
            line = f.readline()
            if line:
                buf.append(line.strip())
                if len(buf) >= BATCH:
                    push(buf)
                    buf.clear()
            else:
                if buf:
                    push(buf)
                    buf.clear()
                time.sleep(INTERVAL)


if __name__ == "__main__":
    print(f"Pushing {LOG_PATH} -> {SENTINEL} as '{SOURCE}'", flush=True)
    tail(LOG_PATH)
