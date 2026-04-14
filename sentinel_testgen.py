"""
Synthetic Caddy-style log generator for Sentinel testing.

Writes NDJSON access records that match Sentinel's flat-access parser shape:
- logger includes "log.access"
- msg includes "handled request"
- remote_ip/status/duration/bytes_read fields are present

Use this to exercise:
- basic dashboards and top lists
- behavior scoring (scan/bruteforce/error probing)
- fingerprint + UA clustering
- botnet campaign correlation
- history/day drilldown endpoints
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_LOG_PATH = "/var/log/caddy/all-access.log"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rand_ip() -> str:
    # Keep addresses in routable-looking ranges for UI realism.
    return f"{random.randint(23, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}"


def _line(
    ip: str,
    host: str,
    uri: str,
    status: int,
    ua: str,
    method: str = "GET",
    accept: str = "*/*",
    ja3: str = "",
    tls_cipher: str = "",
    tls_version: str = "",
) -> dict:
    headers: dict = {
        "Host": [host],
        "User-Agent": [ua],
        "Accept": [accept],
        "Referer": ["-"],
    }
    if ja3:
        headers["CF-HTTP-Fingerprint"] = [ja3]
    obj: dict = {
        "level": "info",
        "ts": _now_iso(),
        "logger": "http.log.access.synthetic",
        "msg": "handled request",
        "request_id": f"syn-{random.randrange(1_000_000_000):09d}",
        "remote_ip": ip,
        "host": host,
        "method": method,
        "uri": uri,
        "proto": "HTTP/1.1",
        "status": int(status),
        "bytes_read": random.randint(120, 2048),
        "duration": round(random.uniform(0.002, 0.140), 6),
        "size": random.randint(180, 6400),
        "headers": headers,
    }
    if tls_cipher or tls_version:
        obj["tls"] = {"cipher_suite": tls_cipher, "version": tls_version}
    return obj


def _emit(fh, obj: dict, delay_s: float) -> None:
    fh.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=True) + "\n")
    if delay_s > 0:
        time.sleep(delay_s)


def _get_json(
    url: str, timeout_s: float = 30.0, auth_user: str = "", auth_password: str = ""
) -> tuple[dict | None, str]:
    """
    GET JSON from Sentinel. Returns (obj, "") on success, or (None, short reason) on failure.
    """
    try:
        req = Request(url, method="GET")
        if auth_user:
            token = base64.b64encode(f"{auth_user}:{auth_password}".encode("utf-8")).decode("ascii")
            req.add_header("Authorization", f"Basic {token}")
        with urlopen(req, timeout=timeout_s) as r:
            raw = r.read().decode("utf-8", errors="replace")
        return json.loads(raw), ""
    except HTTPError as e:
        hint = ""
        if e.code == 401:
            hint = " - use --auth-user / --auth-password (or SENTINEL_AUTH_USER / SENTINEL_AUTH_PASSWORD)"
        return None, f"HTTP {e.code} {e.reason}{hint}"
    except URLError as e:
        return None, f"URL error: {e.reason!r}"
    except TimeoutError:
        return None, f"timeout after {timeout_s}s (try --verify-timeout or wait for server load to drop)"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def generate(log_path: str, host: str, total_events: int, burst_events: int, delay_ms: int) -> None:
    delay_s = max(0.0, delay_ms / 1000.0)
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    normal_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    scanner_uas = [
        "curl/8.5.0",
        "python-requests/2.32.3",
        "sqlmap/1.8.2#stable",
        "Nikto/2.5.0",
    ]
    suspicious_paths = [
        "/.env",
        "/.git/config",
        "/wp-admin/install.php",
        "/xmlrpc.php",
        "/phpmyadmin/index.php",
        "/cgi-bin/luci",
        "/adminer.php",
    ]
    normal_paths = ["/", "/pricing", "/docs", "/contact", "/about", "/api/health", "/blog/latest"]

    shared_bot_ua = "Mozilla/5.0 zgrab/0.x masscan-bot synthetic-cluster"
    shared_ips = [_rand_ip() for _ in range(18)]
    rotate_ip = _rand_ip()

    # TLS FP scenario: two clusters of IPs sharing a JA3-style fingerprint.
    # Cluster A uses a CF-HTTP-Fingerprint header (JA3 path).
    # Cluster B uses tls.cipher+version (fallback composite path).
    tls_ja3_fp = "771,4865-4867-4866-49196-49195-52393-49200-49199-158-49188-49187-107-49162-49161-103-49172-49171-57-156-61-53-47-255,0-11-10-13172-16-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"
    tls_cluster_a_ips = [_rand_ip() for _ in range(10)]
    tls_cluster_b_ips = [_rand_ip() for _ in range(10)]
    tls_cipher = "TLS_AES_256_GCM_SHA384"
    tls_ver = "tls1.3"

    rotating_uas = [
        "curl/7.64.1",
        "python-requests/2.28.2",
        "Wget/1.21.4",
        "Go-http-client/1.1",
        "aiohttp/3.9.3",
        "Mozilla/5.0 custom-bot",
    ]
    scanner_ip = _rand_ip()
    brute_ip = _rand_ip()
    probe_ip = _rand_ip()

    emitted = 0
    with open(log_path, "a", encoding="utf-8") as fh:
        # 1) Baseline traffic.
        baseline = max(50, total_events // 3)
        for _ in range(baseline):
            ip = _rand_ip()
            uri = random.choice(normal_paths)
            status = random.choices([200, 201, 204, 301, 304, 404], weights=[55, 8, 6, 10, 8, 13])[0]
            _emit(fh, _line(ip, host, uri, status, random.choice(normal_uas), accept="text/html,*/*"), delay_s)
            emitted += 1

        # 2) Scanner behavior: many unique paths quickly.
        for i in range(max(80, total_events // 8)):
            uri = f"/scan-{i:03d}/" if i % 3 else random.choice(suspicious_paths)
            _emit(fh, _line(scanner_ip, host, uri, 404, random.choice(scanner_uas)), delay_s)
            emitted += 1

        # 3) Bruteforce behavior.
        login_targets = ["/login", "/wp-login.php", "/admin", "/admin/login"]
        for i in range(max(60, total_events // 10)):
            tgt = login_targets[i % len(login_targets)]
            status = 401 if i % 4 else 403
            _emit(fh, _line(brute_ip, host, tgt, status, "Mozilla/5.0 BruteProbe/1.0", method="POST"), delay_s)
            emitted += 1

        # 4) Error probing.
        for i in range(max(100, total_events // 7)):
            uri = f"/ghost-{i:04d}" if i % 2 else random.choice(suspicious_paths)
            _emit(fh, _line(probe_ip, host, uri, 404, random.choice(scanner_uas)), delay_s)
            emitted += 1

        # 5) Same IP rotating UA quickly (evasion).
        for i in range(max(70, total_events // 9)):
            ua = rotating_uas[i % len(rotating_uas)]
            uri = random.choice(["/api/private", "/internal/health", "/admin", "/wp-admin/install.php"])
            status = 200 if i % 6 else 404
            _emit(fh, _line(rotate_ip, host, uri, status, ua), delay_s)
            emitted += 1

        # 6) Botnet-like coordinated burst: same URI + shared UA across many IPs.
        burst_uri = "/wp-admin/install.php?step=1"
        for _ in range(max(120, burst_events)):
            ip = random.choice(shared_ips)
            st = 404 if random.random() < 0.8 else 200
            _emit(fh, _line(ip, host, burst_uri, st, shared_bot_ua), delay_s)
            emitted += 1

        # 7) TLS fingerprint cluster A: 10 different IPs, same JA3 fingerprint header.
        #    Each IP hits several paths so they score enough to appear on the threat board.
        tls_paths = ["/api/v1/users", "/api/v1/admin", "/.env", "/config.json", "/api/keys"]
        for i, ip in enumerate(tls_cluster_a_ips):
            for path in tls_paths:
                st = 200 if i % 3 else 403
                _emit(fh, _line(ip, host, path, st, "python-requests/2.32.3",
                                ja3=tls_ja3_fp), delay_s)
                emitted += 1

        # 8) TLS fingerprint cluster B: 10 different IPs, same cipher+version composite FP.
        for i, ip in enumerate(tls_cluster_b_ips):
            for path in tls_paths:
                st = 200 if i % 4 else 404
                _emit(fh, _line(ip, host, path, st, "Go-http-client/2.0",
                                tls_cipher=tls_cipher, tls_version=tls_ver), delay_s)
                emitted += 1

        # 9) Fill to requested total if needed.
        while emitted < total_events:
            ip = _rand_ip()
            uri = random.choice(normal_paths + suspicious_paths)
            status = random.choices([200, 301, 404, 500], weights=[65, 10, 20, 5])[0]
            ua = random.choice(normal_uas + scanner_uas)
            _emit(fh, _line(ip, host, uri, status, ua), delay_s)
            emitted += 1

        fh.flush()

    print(f"[testgen] wrote {emitted} synthetic access events to: {log_path}")
    print("[testgen] scenarios: baseline, scan, bruteforce, error-probe, UA-rotation, botnet-burst, tls-fp-cluster-a (JA3), tls-fp-cluster-b (cipher+version)")
    print(f"[testgen] tls-fp | cluster-A ips={len(tls_cluster_a_ips)} ja3={tls_ja3_fp[:32]}...")
    print(f"[testgen] tls-fp | cluster-B ips={len(tls_cluster_b_ips)} cipher={tls_cipher} version={tls_ver}")


def verify(
    base_url: str,
    auth_user: str = "",
    auth_password: str = "",
    retries: int = 8,
    retry_delay_s: float = 1.0,
    settle_ms: float = 0.0,
    timeout_s: float = 30.0,
) -> None:
    base = base_url.rstrip("/")
    data = None
    series = None
    events = None
    last_data_err = ""
    tries = max(1, int(retries))
    for i in range(tries):
        d, err = _get_json(base + "/data", timeout_s=timeout_s, auth_user=auth_user, auth_password=auth_password)
        if err:
            last_data_err = err
        data = d
        series, _ = _get_json(
            base + "/api/history/series", timeout_s=timeout_s, auth_user=auth_user, auth_password=auth_password
        )
        events, _ = _get_json(
            base + "/api/history/events?page_size=5", timeout_s=timeout_s, auth_user=auth_user, auth_password=auth_password
        )
        if data:
            dbg = data.get("stream_parse_debug", {}) if isinstance(data, dict) else {}
            if int(data.get("total", 0) or 0) >= 10 or int(dbg.get("dicts_yielded", 0) or 0) >= 10:
                break
        if i < tries - 1:
            time.sleep(max(0.1, retry_delay_s))
    # First snapshot may be early (verify breaks as soon as total/dicts >= 10). Optional wait
    # so dicts/total in the printed summary match a large appended batch.
    if data and isinstance(data, dict) and settle_ms > 0:
        time.sleep(max(0.0, settle_ms / 1000.0))
        settled, err = _get_json(base + "/data", timeout_s=timeout_s, auth_user=auth_user, auth_password=auth_password)
        if err:
            last_data_err = err
        if settled:
            data = settled
    if not data:
        auth_note = " (with Basic auth)" if auth_user else ""
        print(f"[testgen] verify failed: cannot read {base}/data{auth_note}")
        if last_data_err:
            print(f"[testgen] reason: {last_data_err}")
        if last_data_err and "401" in last_data_err and not auth_user.strip():
            print(
                "[testgen] hint: export SENTINEL_AUTH_USER and SENTINEL_AUTH_PASSWORD in this shell, "
                "or pass --auth-user / --auth-password (must match the Sentinel process)."
            )
        return
    botnets = len(data.get("botnet_campaigns", []))
    fp = data.get("fingerprint_stats", {})
    beh = data.get("behavior_stats", {})
    dbg = data.get("stream_parse_debug", {})
    tls_shared = data.get("tls_fp_shared", [])
    beh_signals = beh.get("signals", {}) if isinstance(beh, dict) else {}
    ip_tags = data.get("ip_tags", {})
    shared_tls_tagged = [ip for ip, tags in ip_tags.items() if "shared_tls_fp" in tags]

    print(
        "[testgen] source | "
        f"log_path={data.get('log_path', '?')} "
        f"log_from_start={data.get('log_from_start', '?')} "
        f"workers={data.get('background_workers_started', '?')} "
        f"dicts={dbg.get('dicts_yielded', 0)} json_roots={dbg.get('json_roots', 0)}"
    )
    print(
        "[testgen] /data ok | "
        f"total={data.get('total', 0)} "
        f"unique_ips={data.get('unique_ips', 0)} "
        f"botnet_campaigns={botnets} "
        f"fp_unique={fp.get('unique', 0)} "
        f"behavior_tracked_ips={beh.get('tracked_ips', 0)}"
    )

    # TLS fingerprint results
    tls_signal = int(beh_signals.get("shared_tls_fp", 0))
    if tls_shared:
        print(f"[testgen] tls-fp ok | shared_clusters={len(tls_shared)} signal_count={tls_signal} tagged_ips={len(shared_tls_tagged)}")
        for entry in tls_shared[:3]:
            fp_val, ip_count = entry if isinstance(entry, (list, tuple)) and len(entry) == 2 else (str(entry), "?")
            print(f"[testgen]   fp={str(fp_val)[:48]}...  ips={ip_count}")
    else:
        hint = " (Sentinel may still be ingesting -- try --verify-settle-ms 3000)" if tls_signal == 0 else ""
        print(f"[testgen] tls-fp | no shared clusters visible yet{hint} signal_count={tls_signal} tagged_ips={len(shared_tls_tagged)}")

    if series and series.get("ok"):
        print(f"[testgen] /api/history/series ok | points={len(series.get('points', []))}")
    else:
        print("[testgen] /api/history/series not available")
    if events and events.get("ok"):
        print(f"[testgen] /api/history/events ok | rows={len(events.get('rows', []))} total={events.get('total', 0)}")
    else:
        print("[testgen] /api/history/events not available")


def main() -> None:
    p = argparse.ArgumentParser(description="Generate synthetic Caddy access logs for Sentinel testing.")
    p.add_argument("--log-path", default=os.environ.get("LOG_PATH", DEFAULT_LOG_PATH), help="Caddy access log path to append to.")
    p.add_argument("--host", default="example.test", help="Host value for generated requests.")
    p.add_argument("--events", type=int, default=1800, help="Approximate total events to write.")
    p.add_argument("--burst-events", type=int, default=300, help="Additional coordinated burst events.")
    p.add_argument("--delay-ms", type=int, default=0, help="Delay between events in milliseconds.")
    p.add_argument("--seed", type=int, default=1337, help="Random seed for repeatable runs.")
    p.add_argument("--verify-url", default="", help="Optional Sentinel base URL (e.g. http://127.0.0.1:5000) for post-run checks.")
    p.add_argument("--auth-user", default=os.environ.get("SENTINEL_AUTH_USER", ""), help="Optional Basic auth user for --verify-url requests.")
    p.add_argument("--auth-password", default=os.environ.get("SENTINEL_AUTH_PASSWORD", ""), help="Optional Basic auth password for --verify-url requests.")
    p.add_argument("--verify-retries", type=int, default=10, help="How many verify retries to allow while Sentinel ingests new lines.")
    p.add_argument("--verify-delay-ms", type=int, default=1000, help="Delay between verify retries in milliseconds.")
    p.add_argument(
        "--verify-settle-ms",
        type=int,
        default=0,
        help="After verify succeeds, wait this many ms and re-fetch /data once for a fuller dict/total count (large batches).",
    )
    p.add_argument(
        "--verify-timeout",
        type=float,
        default=30.0,
        help="HTTP timeout (seconds) for verify requests. Large /data payloads may need 30s+.",
    )
    args = p.parse_args()

    random.seed(args.seed)
    generate(
        log_path=args.log_path,
        host=args.host,
        total_events=max(100, args.events),
        burst_events=max(20, args.burst_events),
        delay_ms=max(0, args.delay_ms),
    )
    if args.verify_url:
        verify(
            args.verify_url,
            auth_user=args.auth_user,
            auth_password=args.auth_password,
            retries=max(1, args.verify_retries),
            retry_delay_s=max(0.1, args.verify_delay_ms / 1000.0),
            settle_ms=max(0, args.verify_settle_ms),
            timeout_s=max(1.0, float(args.verify_timeout)),
        )


if __name__ == "__main__":
    main()
