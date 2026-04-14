# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/persistence.py -- Load/save state to disk, iptables integration,
audit file setup, history event file management.
"""
import errno
import json
import os
import subprocess
import sys
import time
import ipaddress
from collections import Counter
from datetime import datetime, timezone

from sentinel import config, state
from sentinel.helpers import (
    _normalize_client_ip,
    _history_bucket,
    _history_bucket_to_json,
    _prune_runtime_state,
)


# ========================
# IPTABLES
# ========================
def _iptables_drop(ip_normalized, add):
    """
    Insert or remove INPUT DROP for one IP. Uses iptables / ip6tables as list args (no shell).
    Returns (ok, error_message_or_None).
    """
    if not config.IPTABLES_ENABLED:
        return True, None
    try:
        ip = ipaddress.ip_address(ip_normalized)
    except ValueError:
        return False, "invalid ip"
    ip_s = ip.compressed if ip.version == 6 else str(ip)
    bin_name = "ip6tables" if ip.version == 6 else "iptables"
    chain = config.IPTABLES_CHAIN
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
    if not config.IPTABLES_ENABLED:
        return
    with state.lock:
        lst = sorted(state.banned_ips)
    for ip in lst:
        _iptables_drop(ip, True)


# ========================
# BANS
# ========================
def _load_bans():
    if not config.BAN_LIST_PATH:
        return
    try:
        with open(config.BAN_LIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return
        new = set()
        for x in data:
            n = _normalize_client_ip(str(x))
            if n:
                new.add(n)
        with state.lock:
            state.banned_ips.clear()
            state.banned_ips.update(new)
    except (OSError, json.JSONDecodeError, TypeError):
        pass


def _save_bans():
    if not config.BAN_LIST_PATH:
        return
    try:
        with state.lock:
            lst = sorted(state.banned_ips)
        d = os.path.dirname(config.BAN_LIST_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = config.BAN_LIST_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(lst, f)
        os.replace(tmp, config.BAN_LIST_PATH)
    except OSError:
        pass


# ========================
# AUDIT
# ========================
def _touch_audit_file(path):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8"):
        pass


def _ensure_state_dir():
    if not config.STATE_DIR:
        print(
            "[sentinel] WARNING: SENTINEL_STATE_DIR is not set -- all metrics (bytes_served, "
            "totals, history, behavior) will be lost on restart. "
            "Set SENTINEL_STATE_DIR=/var/lib/sentinel (or any writable path) to enable persistence.",
            file=sys.stderr, flush=True,
        )
        return
    try:
        os.makedirs(config.STATE_DIR, mode=0o700, exist_ok=True)
        if config.HISTORY_EVENTS_DIR:
            os.makedirs(config.HISTORY_EVENTS_DIR, mode=0o700, exist_ok=True)
        print(f"[sentinel] state dir ready: {config.STATE_DIR}", file=sys.stderr, flush=True)
    except OSError as err:
        print(f"[sentinel] state dir mkdir failed ({config.STATE_DIR}): {err}", file=sys.stderr, flush=True)


def _ensure_audit_file():
    """Create audit log path on startup so operators can confirm config and permissions."""
    if not config.AUDIT_LOG_PATH:
        print("[sentinel] audit log disabled (SENTINEL_AUDIT_DISABLE=1)", file=sys.stderr, flush=True)
        return
    try:
        _touch_audit_file(config.AUDIT_LOG_PATH)
        print(f"[sentinel] audit log ready: {config.AUDIT_LOG_PATH}", file=sys.stderr, flush=True)
        return
    except OSError as e:
        if (
            config.AUDIT_LOG_PATH != config._DEFAULT_AUDIT_LOG
            and getattr(e, "errno", None) == errno.EROFS
        ):
            bad = config.AUDIT_LOG_PATH
            config.AUDIT_LOG_PATH = config._DEFAULT_AUDIT_LOG
            print(
                f"[sentinel] audit log: {bad!r} is read-only in this unit ({e}); "
                f"using fallback {config.AUDIT_LOG_PATH!r} (remove SENTINEL_AUDIT_LOG or add ReadWritePaths)",
                file=sys.stderr,
                flush=True,
            )
            try:
                _touch_audit_file(config.AUDIT_LOG_PATH)
                print(f"[sentinel] audit log ready: {config.AUDIT_LOG_PATH}", file=sys.stderr, flush=True)
            except OSError as e2:
                print(f"[sentinel] audit log init failed ({config.AUDIT_LOG_PATH}): {e2}", file=sys.stderr, flush=True)
            return
        print(
            f"[sentinel] audit log init failed ({config.AUDIT_LOG_PATH}): {e} "
            "(under ProtectSystem=strict, add the directory to ReadWritePaths; "
            "or use SENTINEL_STATE_DIR under a writable path; "
            "or rely on the fallback file next to sentinel_soc.py)",
            file=sys.stderr,
            flush=True,
        )


# ========================
# HISTORY EVENTS
# ========================
def _history_events_path(ts):
    if not config.HISTORY_EVENTS_DIR:
        return ""
    d = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    return os.path.join(config.HISTORY_EVENTS_DIR, f"{d}.jsonl")


def _append_history_event(event_row):
    path = _history_events_path(event_row.get("ts_epoch", time.time()))
    if not path:
        return
    try:
        os.makedirs(config.HISTORY_EVENTS_DIR, exist_ok=True)
        payload = json.dumps(event_row, separators=(",", ":"), ensure_ascii=True) + "\n"
        with state.history_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(payload)
    except OSError:
        pass


def _prune_history_event_files(now=None):
    if not config.HISTORY_EVENTS_DIR or not os.path.isdir(config.HISTORY_EVENTS_DIR):
        return
    now = now or time.time()
    cutoff = now - config.HISTORY_RETENTION_S
    for name in os.listdir(config.HISTORY_EVENTS_DIR):
        if not name.endswith(".jsonl"):
            continue
        p = os.path.join(config.HISTORY_EVENTS_DIR, name)
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_mtime < cutoff:
            try:
                os.remove(p)
            except OSError:
                pass


# ========================
# PARSED STATE
# ========================
def _save_parsed_state():
    from sentinel.botnet import _campaign_for_api
    if not config.PARSED_STATE_PATH:
        return
    with state.lock:
        payload = {
            "saved_at": int(time.time()),
            "total": int(state.counters["total"]),
            "rps": int(state.counters["rps"]),
            "peak_rps": int(state.counters["peak_rps"]),
            "current_second": int(state.counters["current_second"]),
            "attack_counter": int(state.counters["attack_counter"]),
            "client_err": int(state.counters["client_err"]),
            "server_err": int(state.counters["server_err"]),
            "bytes_served": int(state.counters["bytes_served"]),
            "stream_started_at": float(state.counters["stream_started_at"] or 0.0),
            "ips": [[str(k), int(v)] for k, v in state.ips.items()],
            "domains": [[str(k), int(v)] for k, v in state.domains.items()],
            "referers": [[str(k), int(v)] for k, v in state.referers.items()],
            "paths": [[str(k), int(v)] for k, v in state.paths.items()],
            "status_codes": [[str(k), int(v)] for k, v in state.status_codes.items()],
            "asn_counts": [[str(k), int(v)] for k, v in state.asn_counts.items()],
            "countries": [[str(k), int(v)] for k, v in state.countries.items()],
            "ip_scores": [[str(k), int(v)] for k, v in state.ip_scores.items()],
            "ip_geo": {
                str(k): {
                    "country": str((v or {}).get("country", "??")),
                    "asn": str((v or {}).get("asn", "Unknown")),
                }
                for k, v in state.ip_geo.items()
                if isinstance(v, dict)
            },
            "ip_paths": {
                str(ip): [[str(p), int(c)] for p, c in cnt.items()]
                for ip, cnt in state.ip_paths.items()
            },
            "ip_tags": {str(ip): sorted(str(t) for t in tags) for ip, tags in state.ip_tags.items()},
            "asn_ips": {str(asn): sorted(str(ip) for ip in ipset) for asn, ipset in state.asn_ips.items()},
            "rps_timeline": [int(x) for x in state.rps_timeline[-600:]],
            "attack_timeline": [int(x) for x in state.attack_timeline[-600:]],
            "recent_alerts": list(state.recent_alerts),
            "pending_geo_hits": {str(k): int(v) for k, v in state.pending_geo_hits.items()},
            "geo_cache": {
                str(k): {
                    "country": str((v or {}).get("country", "??")),
                    "asn": str((v or {}).get("asn", "Unknown")),
                }
                for k, v in state.geo_cache.items()
                if isinstance(v, dict)
            },
            "suspicious_hit_buffer": list(state.suspicious_hit_buffer),
            "stream_parse_debug": dict(state.stream_parse_debug),
            "muted_hits": {str(k): int(v) for k, v in state.muted_hits.items()},
            "sources": [[str(k), int(v)] for k, v in state.sources.items()],
        }
    with state.botnet_lock:
        payload["botnet_campaigns"] = {
            str(uri): _campaign_for_api(c) for uri, c in state.botnet_campaigns.items()
        }
    try:
        d = os.path.dirname(config.PARSED_STATE_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = config.PARSED_STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, config.PARSED_STATE_PATH)
    except OSError:
        pass


def _load_parsed_state():
    from sentinel.botnet import _campaign_for_api
    if not config.PARSED_STATE_PATH:
        return
    try:
        with open(config.PARSED_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    with state.lock:
        state.counters["total"] = int(data.get("total", 0) or 0)
        state.counters["rps"] = int(data.get("rps", 0) or 0)
        state.counters["peak_rps"] = int(data.get("peak_rps", 0) or 0)
        state.counters["current_second"] = int(data.get("current_second", 0) or 0)
        state.counters["attack_counter"] = int(data.get("attack_counter", 0) or 0)
        state.counters["client_err"] = int(data.get("client_err", 0) or 0)
        state.counters["server_err"] = int(data.get("server_err", 0) or 0)
        state.counters["bytes_served"] = int(data.get("bytes_served", 0) or 0)
        ss = float(data.get("stream_started_at", 0) or 0.0)
        state.counters["stream_started_at"] = ss if ss > 0 else time.time()

        state.ips.clear()
        state.ips.update({str(k): int(v) for k, v in list(data.get("ips", []))})
        state.domains.clear()
        state.domains.update({str(k): int(v) for k, v in list(data.get("domains", []))})
        state.referers.clear()
        state.referers.update({str(k): int(v) for k, v in list(data.get("referers", []))})
        state.paths.clear()
        state.paths.update({str(k): int(v) for k, v in list(data.get("paths", []))})
        state.status_codes.clear()
        state.status_codes.update({str(k): int(v) for k, v in list(data.get("status_codes", []))})
        state.asn_counts.clear()
        state.asn_counts.update({str(k): int(v) for k, v in list(data.get("asn_counts", []))})
        state.countries.clear()
        state.countries.update({str(k): int(v) for k, v in list(data.get("countries", []))})
        state.ip_scores.clear()
        state.ip_scores.update({str(k): int(v) for k, v in list(data.get("ip_scores", []))})

        state.ip_geo.clear()
        for k, v in dict(data.get("ip_geo", {})).items():
            if isinstance(v, dict):
                state.ip_geo[str(k)] = {
                    "country": str(v.get("country", "??")),
                    "asn": str(v.get("asn", "Unknown")),
                }

        state.ip_paths.clear()
        for ip, rows in dict(data.get("ip_paths", {})).items():
            c = Counter()
            for p, cnt in list(rows):
                c[str(p)] += int(cnt)
            state.ip_paths[str(ip)] = c

        # Tags derived from runtime-only state (tls_fp_to_ips, ua_burst_window)
        # are not persisted alongside their source data, so strip them on load
        # to avoid stale badges that no longer match the live detection state.
        _RUNTIME_TAGS = {"shared_tls_fp", "ua_burst"}
        state.ip_tags.clear()
        for ip, tags in dict(data.get("ip_tags", {})).items():
            cleaned = set(str(t) for t in list(tags)) - _RUNTIME_TAGS
            if cleaned:
                state.ip_tags[str(ip)] = cleaned

        state.asn_ips.clear()
        for asn, ip_list in dict(data.get("asn_ips", {})).items():
            state.asn_ips[str(asn)] = set(str(ip) for ip in list(ip_list))

        state.rps_timeline.clear()
        state.rps_timeline.extend(int(x) for x in list(data.get("rps_timeline", []))[-600:])
        state.attack_timeline.clear()
        state.attack_timeline.extend(int(x) for x in list(data.get("attack_timeline", []))[-600:])

        state.recent_alerts.clear()
        for row in list(data.get("recent_alerts", []))[:config.ALERT_QUEUE_MAX]:
            if isinstance(row, dict):
                state.recent_alerts.append(row)

        state.pending_geo_hits.clear()
        state.pending_geo_hits.update({str(k): int(v) for k, v in dict(data.get("pending_geo_hits", {})).items()})

        state.geo_cache.clear()
        for k, v in dict(data.get("geo_cache", {})).items():
            if isinstance(v, dict):
                state.geo_cache[str(k)] = {
                    "country": str(v.get("country", "??")),
                    "asn": str(v.get("asn", "Unknown")),
                }

        state.suspicious_hit_buffer.clear()
        for row in list(data.get("suspicious_hit_buffer", []))[-10000:]:
            if isinstance(row, dict):
                state.suspicious_hit_buffer.append(row)

        for k in ("text_lines", "json_roots", "dicts_yielded", "buffer_overflows"):
            state.stream_parse_debug[k] = int(dict(data.get("stream_parse_debug", {})).get(k, 0) or 0)

        state.muted_hits.clear()
        state.muted_hits.update({str(k): int(v) for k, v in dict(data.get("muted_hits", {})).items()})

        state.sources.clear()
        state.sources.update({str(k): int(v) for k, v in list(data.get("sources", []))})

    with state.botnet_lock:
        state.botnet_campaigns.clear()
        for uri, campaign in dict(data.get("botnet_campaigns", {})).items():
            state.botnet_campaigns[str(uri)] = _campaign_for_api(campaign)


# ========================
# BEHAVIOR STATE
# ========================
def _save_behavior_state():
    if not config.BEHAVIOR_STATE_PATH:
        return
    with state.lock:
        _prune_runtime_state()
        payload = {
            "saved_at": int(time.time()),
            "fp_counts": [[k, int(v)] for k, v in state.fp_counts.most_common(25000)],
            "fp_last_seen": {k: float(v) for k, v in state.fp_last_seen.items()},
            "ip_to_uas": {ip: sorted(list(uas))[:30] for ip, uas in state.ip_to_uas.items()},
            "ip_behavior": {
                ip: {
                    "first_seen": float(b.get("first_seen", 0.0)),
                    "last_seen": float(b.get("last_seen", 0.0)),
                    "req_count": int(b.get("req_count", 0)),
                    "unique_paths": sorted(list(b.get("unique_paths", set())))[:150],
                    "status_4xx": int(b.get("status_4xx", 0)),
                    "status_5xx": int(b.get("status_5xx", 0)),
                    "login_hits": int(b.get("login_hits", 0)),
                    "wp_login_hits": int(b.get("wp_login_hits", 0)),
                    "admin_hits": int(b.get("admin_hits", 0)),
                    "ua_switches": int(b.get("ua_switches", 0)),
                    "last_ua": str(b.get("last_ua", ""))[:160],
                }
                for ip, b in state.ip_behavior.items()
            },
            "behavior_signal_counts": {k: int(v) for k, v in state.behavior_signal_counts.items()},
            "ip_days_seen": {ip: sorted(days) for ip, days in state.ip_days_seen.items() if days},
        }
    try:
        d = os.path.dirname(config.BEHAVIOR_STATE_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = config.BEHAVIOR_STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, config.BEHAVIOR_STATE_PATH)
    except OSError:
        pass


def _load_behavior_state():
    if not config.BEHAVIOR_STATE_PATH:
        return
    try:
        with open(config.BEHAVIOR_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    with state.lock:
        state.fp_counts.clear()
        for k, v in data.get("fp_counts", []):
            try:
                state.fp_counts[str(k)] += int(v)
            except (TypeError, ValueError):
                continue
        state.fp_last_seen.clear()
        for k, v in dict(data.get("fp_last_seen", {})).items():
            try:
                state.fp_last_seen[str(k)] = float(v)
            except (TypeError, ValueError):
                continue
        state.ip_to_uas.clear()
        for ip, uas in dict(data.get("ip_to_uas", {})).items():
            state.ip_to_uas[str(ip)].update(str(x) for x in list(uas)[:30])
        state.ua_to_ips.clear()
        for ip, uas in state.ip_to_uas.items():
            for u in uas:
                state.ua_to_ips[u].add(ip)
        state.ip_behavior.clear()
        for ip, raw in dict(data.get("ip_behavior", {})).items():
            if not isinstance(raw, dict):
                continue
            b = state.ip_behavior[str(ip)]
            b["first_seen"] = float(raw.get("first_seen", 0.0) or 0.0)
            b["last_seen"] = float(raw.get("last_seen", 0.0) or 0.0)
            b["req_count"] = int(raw.get("req_count", 0) or 0)
            b["unique_paths"] = set(str(x) for x in list(raw.get("unique_paths", []))[:150])
            b["status_4xx"] = int(raw.get("status_4xx", 0) or 0)
            b["status_5xx"] = int(raw.get("status_5xx", 0) or 0)
            b["login_hits"] = int(raw.get("login_hits", 0) or 0)
            b["wp_login_hits"] = int(raw.get("wp_login_hits", 0) or 0)
            b["admin_hits"] = int(raw.get("admin_hits", 0) or 0)
            b["ua_switches"] = int(raw.get("ua_switches", 0) or 0)
            b["last_ua"] = str(raw.get("last_ua", ""))[:160]
        state.behavior_signal_counts.clear()
        for k, v in dict(data.get("behavior_signal_counts", {})).items():
            try:
                state.behavior_signal_counts[str(k)] = int(v)
            except (TypeError, ValueError):
                continue
        state.ip_days_seen.clear()
        for ip, days in dict(data.get("ip_days_seen", {})).items():
            state.ip_days_seen[str(ip)] = set(str(d) for d in list(days) if isinstance(d, str) and len(d) == 10)
        _prune_runtime_state()


# ========================
# HISTORY BUCKETS
# ========================
def _save_history_buckets():
    if not config.HISTORY_BUCKETS_PATH:
        return
    with state.lock:
        _prune_runtime_state()
        payload = {
            "saved_at": int(time.time()),
            "buckets": [_history_bucket_to_json(v) for _, v in sorted(state.history_buckets.items())],
        }
    try:
        d = os.path.dirname(config.HISTORY_BUCKETS_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = config.HISTORY_BUCKETS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, config.HISTORY_BUCKETS_PATH)
    except OSError:
        pass


def _load_history_buckets():
    if not config.HISTORY_BUCKETS_PATH:
        return
    try:
        with open(config.HISTORY_BUCKETS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    with state.lock:
        state.history_buckets.clear()
        for raw in data.get("buckets", []):
            if not isinstance(raw, dict):
                continue
            try:
                ts = int(raw.get("ts", 0))
            except (TypeError, ValueError):
                continue
            b = _history_bucket()
            b["ts"] = ts
            b["total"] = int(raw.get("total", 0) or 0)
            b["attacks"] = int(raw.get("attacks", 0) or 0)
            b["client_errors"] = int(raw.get("client_errors", 0) or 0)
            b["server_errors"] = int(raw.get("server_errors", 0) or 0)
            b["status"] = Counter({str(k): int(v) for k, v in dict(raw.get("status", {})).items()})
            b["top_ips"] = Counter({str(k): int(v) for k, v in list(raw.get("top_ips", []))})
            b["top_paths"] = Counter({str(k): int(v) for k, v in list(raw.get("top_paths", []))})
            state.history_buckets[ts] = b
        _prune_runtime_state()


def get_storage_stats():
    """Return disk usage breakdown of all Sentinel state files (bytes)."""
    named_files = {
        "bans":            config.BAN_LIST_PATH,
        "audit":           config.AUDIT_LOG_PATH,
        "parsed_state":    config.PARSED_STATE_PATH,
        "behavior_state":  config.BEHAVIOR_STATE_PATH,
        "history_buckets": config.HISTORY_BUCKETS_PATH,
    }
    result = {}
    total = 0
    for label, path in named_files.items():
        sz = 0
        if path:
            try:
                sz = os.path.getsize(path)
            except OSError:
                sz = 0
        result[label] = sz
        total += sz

    events_dir = config.HISTORY_EVENTS_DIR
    events_sz = 0
    events_files = 0
    if events_dir and os.path.isdir(events_dir):
        for fname in os.listdir(events_dir):
            try:
                events_sz += os.path.getsize(os.path.join(events_dir, fname))
                events_files += 1
            except OSError:
                pass
    result["history_events"] = events_sz
    result["history_events_files"] = events_files
    total += events_sz
    result["total"] = total
    return result
