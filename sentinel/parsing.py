# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/parsing.py -- Log file parsing: iter_log_lines, iter_caddy_log_objects,
_parse_caddy_access_line.
"""
import json
import os
import sys
import time

from sentinel import state
from sentinel.helpers import _coerce_http_status, _normalize_caddy_headers


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
    if isinstance(req, dict) and req:
        return req, status

    hdrs = _normalize_caddy_headers(data.get("headers"))

    msg_l = str(data.get("msg") or "").lower()
    logger_l = str(data.get("logger") or "").lower()
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
    Yield one dict per log record. Uses a three-layer approach to keep the parse
    buffer well below its ceiling in all conditions:

    1. Fast-path per line: try json.loads(line) first. Caddy writes NDJSON so
       this succeeds for ~99 % of lines with zero buffer involvement.
    2. Per-line length cap (512 KB): lines longer than this are dropped before
       touching the shared buffer, preventing a single enormous record from
       causing an overflow.
    3. Buffer prefix trim: after a failed raw_decode, advance past any leading
       non-JSON bytes to the next '{' or '[' instead of letting garbage
       accumulate until the 8 MB safety ceiling is hit.
    """
    dec = json.JSONDecoder()
    buf = ""
    max_buf = 8 * 1024 * 1024      # last-resort guard (should never be hit)
    max_line = 512 * 1024           # per-line cap: skip lines longer than 512 KB

    def _emit_obj(obj):
        if isinstance(obj, dict):
            state.stream_parse_debug["dicts_yielded"] += 1
            yield obj
        elif isinstance(obj, list):
            for x in obj:
                if isinstance(x, dict):
                    state.stream_parse_debug["dicts_yielded"] += 1
                    yield x

    for line in iter_log_lines(path, from_start=from_start):
        if not buf:
            line = line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped:
            continue
        state.stream_parse_debug["text_lines"] += 1

        # -- Layer 1: fast-path for NDJSON (one complete object per line) --
        if stripped.startswith(("{", "[")):
            try:
                obj = json.loads(stripped)
                state.stream_parse_debug["json_roots"] += 1
                yield from _emit_obj(obj)
                continue
            except json.JSONDecodeError:
                pass

        # -- Layer 2: per-line length cap --
        if len(line) > max_line:
            state.stream_parse_debug["buffer_overflows"] += 1
            print(
                f"[sentinel] skipping oversized line ({len(line)} bytes > {max_line}); "
                "not a valid single-line JSON record",
                file=sys.stderr,
                flush=True,
            )
            continue

        buf += line + "\n"

        # -- Last-resort ceiling --
        if len(buf) > max_buf:
            state.stream_parse_debug["buffer_overflows"] += 1
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
                # -- Layer 3: prefix trim --
                next_start = -1
                for ch in ("{", "["):
                    idx = buf.find(ch, 1)
                    if idx != -1 and (next_start == -1 or idx < next_start):
                        next_start = idx
                if next_start != -1:
                    buf = buf[next_start:]
                break
            buf = buf[end:]
            state.stream_parse_debug["json_roots"] += 1
            yield from _emit_obj(obj)

    buf = buf.lstrip()
    if buf:
        try:
            obj, end = dec.raw_decode(buf, 0)
            state.stream_parse_debug["json_roots"] += 1
            yield from _emit_obj(obj)
        except json.JSONDecodeError:
            pass


def iter_log_lines(path, from_start=False):
    """
    Follow a growing log file (tail -f). Uses binary reads + UTF-8 decode so file
    position matches os.stat().st_size on Windows and Linux.
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
